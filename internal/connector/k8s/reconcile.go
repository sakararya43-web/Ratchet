package k8s

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func (a *K8sAdapter) readObject(ctx context.Context, target kube.Object) (*kube.Object, error) {
	resources := map[string]string{"Role": "roles", "ClusterRole": "clusterroles", "RoleBinding": "rolebindings", "ClusterRoleBinding": "clusterrolebindings"}
	resource, ok := resources[target.Kind]
	if !ok {
		return nil, kube.ErrInvalid
	}
	args := []string{"get", resource + ".rbac.authorization.k8s.io", target.Name, "-o", "json", "--ignore-not-found=true"}
	if target.Namespace != "" {
		args = append(args, "--namespace", target.Namespace)
	}
	raw, err := a.kubectl(ctx, args...)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	object, _, err := NormalizeObject(value)
	return &object, err
}

func sameObject(want, got *kube.Object, metadata bool) bool {
	if want == nil || got == nil {
		return want == nil && got == nil
	}
	a, b := *want, *got
	if !metadata {
		a.UID, a.ResourceVersion, b.UID, b.ResourceVersion = "", "", "", ""
	}
	x, err := canon.New().Digest(a)
	if err != nil {
		return false
	}
	y, err := canon.New().Digest(b)
	return err == nil && x == y
}

// ReconcileOnce performs only an independent API read. A lost webhook response,
// target timeout or command redelivery can never repeat a write here.
func (h *AdmissionWebhookHandler) ReconcileOnce(ctx context.Context, commandID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.loadPending(commandID)
	if os.IsNotExist(err) {
		p, err = h.unchangedWithoutAdmission(ctx, commandID)
	}
	if err != nil {
		return err
	}
	if p.Status == "PUBLISHED" {
		return nil
	}
	if p.Status != "ALLOWED" && p.Status != "RESULT_READY" {
		return errors.New("native admission outcome is not an execution witness")
	}
	if h.config.Results == nil {
		return errors.New("native execution result transport unavailable")
	}
	if len(p.Result) == 0 {
		target := p.Admission.Mutation.After
		if target == nil {
			target = p.Admission.Mutation.Before
		}
		if target == nil {
			return kube.ErrInvalid
		}
		observed, err := h.config.Adapter.readObject(ctx, *target)
		if err != nil {
			return err
		}
		at := time.Now().UTC()
		observation := &workflow.NativeObservation{AdmissionUID: p.Admission.AdmissionUID, ContextDigest: p.Permit.ContextDigest, Object: observed}
		mutation := p.Admission.Mutation
		applied := false
		if mutation.Operation == "DELETE" {
			applied = observed == nil
			if applied {
				observation.DeletedUID = mutation.Before.UID
			}
		} else {
			applied = observed != nil && sameObject(mutation.After, observed, false) && observed.UID != "" && observed.ResourceVersion != ""
			if p.Admission.CreateUID != "" {
				applied = applied && observed.UID == p.Admission.CreateUID
			}
			if mutation.Before != nil {
				applied = applied && observed.UID == mutation.Before.UID && observed.ResourceVersion != mutation.Before.ResourceVersion
			}
		}
		unchanged := sameObject(mutation.Before, observed, true)
		if !applied && time.Now().Before(p.Permit.ExpiresAt) {
			return errors.New("native target application not yet independently observed")
		}
		if !applied && !unchanged {
			return errors.New("native target state differs from both exact approved and preimage states")
		}
		result := workflow.ExecutionResult{SchemaVersion: 1, Tenant: p.Command.Tenant, Connector: p.Command.Connector, CommandID: p.Command.CommandID, RequestID: p.Command.RequestID, CorrelationID: p.Command.CorrelationID, EnvelopeDigest: p.Command.EnvelopeDigest, Success: applied, ReadBackVerified: true, ObservedTenant: p.Command.Tenant, ObservedTarget: p.Command.Kubernetes.ObjectKey, ObservedRevision: p.Command.ExpectedRevision, ObservedAt: at, Kubernetes: observation}
		if applied {
			// This is the first independent confirmation time, an upper bound on
			// application. It must be inside the permit; no write time is invented.
			if at.After(p.Permit.ExpiresAt) {
				return errors.New("application before permit expiry cannot be proved; review required")
			}
			result.AppliedAt = at
		}
		result.ObservationDigest, err = workflow.NativeObservationDigest(result)
		if err != nil {
			return err
		}
		result.MessageID = uuid.NewSHA1(uuid.MustParse(result.CommandID), []byte("native-read-back:"+result.ObservationDigest.String())).String()
		digest, err := canon.New().Digest(struct {
			Domain string `json:"domain"`
			Body   any    `json:"body"`
		}{"RATCHET_EXEC_RESULT_V1", result})
		if err != nil {
			return err
		}
		result.Signature = ed25519.Sign(h.config.SigningKey, digest[:])
		p.Result, err = json.Marshal(result)
		if err != nil {
			return err
		}
		p.MessageID = result.MessageID
		p.Status = "RESULT_READY"
		if err := h.savePending(p); err != nil {
			return err
		}
	}
	if err := h.config.Results(ctx, p.MessageID, p.Result); err != nil {
		return err
	}
	p.Status = "PUBLISHED"
	return h.savePending(p)
}

// A command can be rejected by API validation before reaching this webhook.
// Once its deadline passes, a full independent inventory can prove an unchanged
// target; it can never prove successful execution without a consumed admission.
func (h *AdmissionWebhookHandler) unchangedWithoutAdmission(ctx context.Context, commandID string) (pendingAdmission, error) {
	var p pendingAdmission
	raw, err := os.ReadFile(filepath.Join(h.config.Adapter.config.StateDirectory, "commands", commandID+".json"))
	if err != nil {
		return p, err
	}
	var command workflow.PreparedCommand
	if json.Unmarshal(raw, &command) != nil || command.Kubernetes == nil {
		return p, kube.ErrInvalid
	}
	digest, err := commandDigest(command)
	if err != nil || !ed25519.Verify(h.config.CorePublicKey, digest[:], command.Signature) || command.CommandID != commandID {
		return p, kube.ErrInvalid
	}
	if time.Now().Before(command.Deadline) {
		return p, errors.New("unadmitted command is still live")
	}
	resources, err := h.config.Adapter.discovery(ctx)
	if err != nil {
		return p, err
	}
	state, err := h.config.Adapter.inventory(ctx, resources)
	if err != nil {
		return p, err
	}
	var observed *kube.Object
	for _, object := range state.Objects {
		if graph.KubernetesNodeID(state.Cluster, "object", kube.ObjectKey(object)) == command.Kubernetes.ObjectKey {
			copyObject := object
			observed = &copyObject
			break
		}
	}
	if command.Kubernetes.Operation == "CREATE" {
		if observed != nil {
			return p, errors.New("unadmitted create target exists; review required")
		}
	} else if observed == nil || observed.UID != command.Kubernetes.ExpectedUID || observed.ResourceVersion != command.Kubernetes.ExpectedResourceVersion {
		return p, errors.New("unadmitted target preimage changed; review required")
	}
	result := workflow.ExecutionResult{SchemaVersion: 1, Tenant: command.Tenant, Connector: command.Connector, CommandID: command.CommandID, RequestID: command.RequestID, CorrelationID: command.CorrelationID, EnvelopeDigest: command.EnvelopeDigest, ReadBackVerified: true, ObservedTenant: command.Tenant, ObservedTarget: command.Kubernetes.ObjectKey, ObservedRevision: command.ExpectedRevision, ObservedAt: time.Now().UTC(), Kubernetes: &workflow.NativeObservation{Object: observed}}
	result.ObservationDigest, err = workflow.NativeObservationDigest(result)
	if err != nil {
		return p, err
	}
	result.MessageID = uuid.NewSHA1(uuid.MustParse(commandID), []byte("native-read-back:"+result.ObservationDigest.String())).String()
	digest, err = canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{"RATCHET_EXEC_RESULT_V1", result})
	if err != nil {
		return p, err
	}
	result.Signature = ed25519.Sign(h.config.SigningKey, digest[:])
	p = pendingAdmission{Status: "RESULT_READY", Command: command, MessageID: result.MessageID}
	p.Result, err = json.Marshal(result)
	if err != nil {
		return p, err
	}
	return p, h.savePending(p)
}

func (h *AdmissionWebhookHandler) ReconcileAll(ctx context.Context) error {
	if h.config.Adapter == nil {
		return kube.ErrInvalid
	}
	files, err := os.ReadDir(h.config.Adapter.config.StateDirectory + string(os.PathSeparator) + "pending")
	if err != nil {
		return err
	}
	var failures []error
	pending := map[string]bool{}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(file.Name(), ".json")
		pending[id] = true
		if err := h.ReconcileOnce(ctx, id); err != nil {
			failures = append(failures, err)
		}
	}
	commands, err := os.ReadDir(filepath.Join(h.config.Adapter.config.StateDirectory, "commands"))
	if err != nil {
		return err
	}
	for _, file := range commands {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(file.Name(), ".json")
		if pending[id] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(h.config.Adapter.config.StateDirectory, "commands", file.Name()))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var command workflow.PreparedCommand
		if json.Unmarshal(raw, &command) != nil {
			failures = append(failures, kube.ErrInvalid)
			continue
		}
		if time.Now().Before(command.Deadline) {
			continue
		}
		if err := h.ReconcileOnce(ctx, id); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
