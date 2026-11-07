package k8s

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type AdmissionConfig struct {
	Adapter       *K8sAdapter
	CoreURL       string
	CorePublicKey ed25519.PublicKey
	SigningKey    ed25519.PrivateKey
	StorageKey    []byte
	HTTPClient    *http.Client
	Results       func(context.Context, string, []byte) error
	DecisionError func(error)
}
type AdmissionWebhookHandler struct {
	mu     sync.Mutex
	config AdmissionConfig
	client ratchetv1connect.DecisionServiceClient
}

func NewAdmissionWebhookHandler() *AdmissionWebhookHandler { return &AdmissionWebhookHandler{} }

func NewNativeAdmissionHandler(config AdmissionConfig) (*AdmissionWebhookHandler, error) {
	u, err := url.Parse(config.CoreURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(config.CorePublicKey) != 32 || len(config.SigningKey) != 64 || len(config.StorageKey) != 32 || config.Adapter == nil || config.HTTPClient == nil || config.Results == nil {
		return nil, kube.ErrInvalid
	}
	config.CorePublicKey = append(ed25519.PublicKey(nil), config.CorePublicKey...)
	config.SigningKey = append(ed25519.PrivateKey(nil), config.SigningKey...)
	config.StorageKey = append([]byte(nil), config.StorageKey...)
	for _, name := range []string{"commands", "pending"} {
		if err := os.MkdirAll(filepath.Join(config.Adapter.config.StateDirectory, name), 0700); err != nil {
			return nil, err
		}
	}
	return &AdmissionWebhookHandler{config: config, client: ratchetv1connect.NewDecisionServiceClient(config.HTTPClient, config.CoreURL)}, nil
}

// RegisterIntent rejects the former unauthenticated name-only grant path.
func (*AdmissionWebhookHandler) RegisterIntent(*ApprovedIntent) error {
	return errors.New("local intent registration is forbidden; a signed staged command is required")
}

func commandDigest(command workflow.PreparedCommand) (ports.Digest, error) {
	command.Signature = nil
	return canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{"RATCHET_EXEC_COMMAND_V1", command})
}

func (h *AdmissionWebhookHandler) Stage(ctx context.Context, command workflow.PreparedCommand) error {
	if h.config.Adapter == nil {
		return kube.ErrUnsupported
	}
	id, err := uuid.Parse(command.CommandID)
	if err != nil || id == uuid.Nil || id.String() != command.CommandID {
		return kube.ErrInvalid
	}
	digest, err := commandDigest(command)
	if err != nil || !ed25519.Verify(h.config.CorePublicKey, digest[:], command.Signature) {
		return bus.ErrAuthentication
	}
	cfg := h.config.Adapter.config
	if command.SchemaVersion != 1 || command.Tenant != cfg.Tenant || command.Connector != cfg.Connector || command.Kubernetes == nil || command.Purpose != "KUBERNETES_ADMISSION" || command.Envelope == nil || command.Envelope.Intent.Kubernetes == nil || command.Envelope.Intent.Kubernetes.PlanDigest != command.Kubernetes.PlanDigest {
		return kube.ErrInvalid
	}
	bound, err := canon.New().Digest(command.Envelope)
	if err != nil || bound != command.EnvelopeDigest {
		return kube.ErrInvalid
	}
	if command.VerifyOnly {
		return h.ReconcileOnce(ctx, command.CommandID)
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	path := filepath.Join(cfg.StateDirectory, "commands", command.CommandID+".json")
	prior, err := os.ReadFile(path)
	if err == nil {
		if !bytes.Equal(raw, prior) {
			return eventstore.ErrIdempotencyConflict
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return atomicFile(path, raw)
}

func (h *AdmissionWebhookHandler) matchingCommand(digest ports.Digest, source string) (*workflow.PreparedCommand, error) {
	files, err := os.ReadDir(filepath.Join(h.config.Adapter.config.StateDirectory, "commands"))
	if err != nil {
		return nil, err
	}
	var result *workflow.PreparedCommand
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(h.config.Adapter.config.StateDirectory, "commands", file.Name()))
		if err != nil {
			return nil, err
		}
		var command workflow.PreparedCommand
		if json.Unmarshal(raw, &command) != nil {
			return nil, errors.New("staged command integrity failure")
		}
		if command.Kubernetes != nil && command.Kubernetes.MutationDigest == digest && command.Kubernetes.SourceResourceVersion == source && time.Now().Before(command.Deadline) {
			if result != nil {
				return nil, errors.New("ambiguous staged native commands")
			}
			result = &command
		}
	}
	return result, nil
}

type pendingAdmission struct {
	Status    string                      `json:"status"`
	Command   workflow.PreparedCommand    `json:"command"`
	Admission kube.Admission              `json:"admission"`
	Before    kube.State                  `json:"before"`
	Permit    workflow.KubernetesDecision `json:"permit"`
	Result    []byte                      `json:"result,omitempty"`
	MessageID string                      `json:"message_id,omitempty"`
}

func (h *AdmissionWebhookHandler) pendingPath(command string) string {
	return filepath.Join(h.config.Adapter.config.StateDirectory, "pending", command+".json")
}
func (h *AdmissionWebhookHandler) savePending(p pendingAdmission) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(p.Command.Tenant+":native-pending:"+p.Command.CommandID))
	record, err := eventstore.SealPrivate(h.config.StorageKey, p.Command.Tenant, id, "connector-native-v1", raw)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicFile(h.pendingPath(p.Command.CommandID), raw)
}
func (h *AdmissionWebhookHandler) loadPending(command string) (pendingAdmission, error) {
	var p pendingAdmission
	id, err := uuid.Parse(command)
	if err != nil || id == uuid.Nil || id.String() != command {
		return p, kube.ErrInvalid
	}
	raw, err := os.ReadFile(h.pendingPath(command))
	if err != nil {
		return p, err
	}
	var record eventstore.PrivateRecord
	if json.Unmarshal(raw, &record) != nil {
		return p, errors.New("pending admission integrity failure")
	}
	raw, err = eventstore.OpenPrivate(h.config.StorageKey, h.config.Adapter.config.Tenant, record)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Command.CommandID != command {
		return p, errors.New("pending command mismatch")
	}
	return p, nil
}

func refusal(uid string, code int, reason string) *AdmissionResponse {
	return &AdmissionResponse{UID: uid, Allowed: false, Status: &AdmissionStatus{Code: int32(code), Reason: reason, Message: "RATCHET: " + reason}}
}
func (h *AdmissionWebhookHandler) HandleAdmission(request *AdmissionRequest) *AdmissionResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return h.Admit(ctx, request)
}

func (h *AdmissionWebhookHandler) Admit(ctx context.Context, request *AdmissionRequest) *AdmissionResponse {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if request == nil {
		return refusal("", 400, "MalformedAdmission")
	}
	if h.config.Adapter == nil || h.client == nil {
		return refusal(request.UID, 503, "CoreDependencyUnavailable")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.config.Adapter
	a.mu.Lock()
	state, err := a.state.Clone()
	a.mu.Unlock()
	if err != nil || state.ResourceVersion == "" {
		return refusal(request.UID, 503, "SourceContextUnavailable")
	}
	live, err := a.inventory(ctx, state.Resources)
	if err != nil {
		return refusal(request.UID, 503, "LiveSourceUnavailable")
	}
	if live.ResourceVersion != state.ResourceVersion {
		return refusal(request.UID, 409, "SourceResyncRequired")
	}
	admission, err := NormalizeAdmission(a.config.Tenant, a.config.Connector, a.config.Cluster, state.ResourceVersion, request)
	if err != nil {
		return refusal(request.UID, 400, "UnsupportedOrMalformedAdmission")
	}
	if _, err := admission.PrincipalIn(state); err != nil {
		return refusal(request.UID, 403, "ExactIdentityOrPreimageRequired")
	}
	digest, err := canon.New().Digest(admission.Mutation)
	if err != nil {
		return refusal(request.UID, 400, "MalformedMutation")
	}
	command, err := h.matchingCommand(digest, state.ResourceVersion)
	if err != nil {
		return refusal(request.UID, 503, "CommandContextUnavailable")
	}
	if command != nil {
		admission.ApprovedRequestID, admission.CommandID = command.RequestID, command.CommandID
	}
	contextDigest, err := canon.New().Digest(admission)
	if err != nil {
		return refusal(request.UID, 400, "MalformedContext")
	}
	var pending pendingAdmission
	if command != nil && !request.DryRun {
		if _, err := os.Stat(h.pendingPath(command.CommandID)); err == nil {
			return refusal(request.UID, 409, "CommandAlreadyConsumed")
		} else if !os.IsNotExist(err) {
			return refusal(request.UID, 503, "CommandStorageUnavailable")
		}
		pending = pendingAdmission{Status: "PREPARED", Command: *command, Admission: admission, Before: state}
		if err := h.savePending(pending); err != nil {
			return refusal(request.UID, 503, "CommandStorageUnavailable")
		}
	}
	message := kube.SignedKubernetesAdmission{SchemaVersion: 1, Admission: admission, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(3 * time.Second)}
	signatureDigest, err := kube.KubernetesAdmissionSigningDigest(canon.New(), message)
	if err != nil {
		return refusal(request.UID, 400, "MalformedContext")
	}
	message.Signature = ed25519.Sign(h.config.SigningKey, signatureDigest[:])
	raw, err := json.Marshal(message)
	if err != nil {
		return refusal(request.UID, 400, "MalformedContext")
	}
	response, err := h.client.DecideKubernetes(ctx, connect.NewRequest(&v1.KubernetesDecisionRequest{SignedAdmissionJson: raw}))
	if err != nil {
		if h.config.DecisionError != nil {
			h.config.DecisionError(err)
		}
		switch connect.CodeOf(err) {
		case connect.CodeInvalidArgument:
			return refusal(request.UID, 400, "CoreContextInvalid")
		case connect.CodeUnauthenticated, connect.CodePermissionDenied:
			return refusal(request.UID, 403, "CoreAuthenticationRefused")
		case connect.CodeFailedPrecondition, connect.CodeAborted:
			return refusal(request.UID, 409, "CoreContextChanged")
		}
		return refusal(request.UID, 503, "CoreDecisionUnavailable")
	}
	if command == nil || request.DryRun || !response.Msg.ExecutionAuthorized || response.Msg.Outcome != "ALLOW" {
		return refusal(request.UID, 403, "IndependentApprovalRequired")
	}
	var permit workflow.KubernetesDecision
	if json.Unmarshal(response.Msg.SignedNativeDecisionJson, &permit) != nil {
		return refusal(request.UID, 503, "InvalidCorePermit")
	}
	permitDigest, err := workflow.KubernetesDecisionSigningDigest(permit)
	if err != nil || !ed25519.Verify(h.config.CorePublicKey, permitDigest[:], permit.Signature) || !permit.ExecutionAuthorized || permit.Decision.Outcome != "ALLOW" || permit.Tenant != admission.Tenant || permit.Connector != a.config.Connector || permit.AdmissionUID != request.UID || permit.CommandID != command.CommandID || permit.RequestID != command.RequestID || permit.ContextDigest != contextDigest || permit.MutationDigest != digest || permit.ObjectDigest != admission.Mutation.ObjectDigest || !time.Now().Before(permit.ExpiresAt) {
		return refusal(request.UID, 503, "InvalidCorePermit")
	}
	pending.Status, pending.Permit = "ALLOWED", permit
	if err := h.savePending(pending); err != nil {
		return refusal(request.UID, 503, "PermitStorageUnavailable")
	}
	return &AdmissionResponse{UID: request.UID, Allowed: true, Status: &AdmissionStatus{Code: 200, Reason: "ExactApprovedCommand", Message: "RATCHET: exact signed core permit consumed"}}
}

// HTTPHandler accepts only mutually authenticated API-server callers. Direct
// JSON callers cannot assert Kubernetes userInfo or register their own intents.
func (h *AdmissionWebhookHandler) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "authenticated Kubernetes API server required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		var review AdmissionReview
		if decoder.Decode(&review) != nil || decoder.Decode(new(any)) != io.EOF || review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" || review.Request == nil {
			http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
			return
		}
		response := AdmissionReview{APIVersion: review.APIVersion, Kind: review.Kind, Response: h.Admit(r.Context(), review.Request)}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
	})
}
