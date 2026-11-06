//go:build integration

package workflow_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

func nativeWorkflow(t *testing.T, beneficiary string, configure ...func(system, ports.ApprovalVerifier) *workflow.Service) (system, *workflow.Service, kube.State, kube.Mutation, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	return nativeWorkflowOperation(t, beneficiary, "CREATE", configure...)
}

func nativeWorkflowOperation(t *testing.T, beneficiary, operation string, configure ...func(system, ports.ApprovalVerifier) *workflow.Service) (system, *workflow.Service, kube.State, kube.Mutation, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	state := kube.State{Cluster: "phase6-cluster", ResourceVersion: "opaque/source-cut", Complete: true, Namespaces: []string{"finance"}, Principals: []kube.Principal{{ID: "requester", UID: "native-requester-uid", Kind: "User", Name: "Native Private Requester"}, {ID: "owner", UID: "native-owner-uid", Kind: "User", Name: "Native Private Owner"}}, Resources: []kube.APIResource{{Resource: "pods", Namespaced: true}}, Objects: []kube.Object{{Kind: "ClusterRole", Name: "reader", UID: "role-uid", ResourceVersion: "opaque/role-rv", Rules: []kube.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}}}
	name := "Native Private Requester"
	if beneficiary == "owner" {
		name = "Native Private Owner"
	}
	after := kube.Object{Kind: "RoleBinding", Name: "grant", Namespace: "finance", RoleKind: "ClusterRole", RoleName: "reader", Subjects: []kube.Subject{{Kind: "User", Name: name}}}
	mutation := kube.Mutation{Cluster: state.Cluster, Connector: "native", Operation: operation, After: &after, ObjectDigest: ports.Digest{8}}
	if operation != "CREATE" {
		before := after
		before.UID, before.ResourceVersion = "existing-binding-uid", "opaque/existing-binding-rv"
		mutation.Before, mutation.OldObjectDigest = &before, ports.Digest{7}
		if operation == "UPDATE" {
			before.Subjects = []kube.Subject{}
			after.UID, after.ResourceVersion = before.UID, before.ResourceVersion
		} else {
			mutation.After = nil
		}
		state.Objects = append(state.Objects, before)
	}
	return nativeWorkflowState(t, state, mutation, 10, configure...)
}

func nativeWorkflowState(t *testing.T, state kube.State, mutation kube.Mutation, sourceRevision int64, configure ...func(system, ports.ApprovalVerifier) *workflow.Service) (system, *workflow.Service, kube.State, kube.Mutation, *ecdsa.PrivateKey, []byte) {
	return nativeWorkflowStateContext(t, nil, state, mutation, sourceRevision, configure...)
}

func nativeWorkflowStateContext(t *testing.T, ctx context.Context, state kube.State, mutation kube.Mutation, sourceRevision int64, configure ...func(system, ports.ApprovalVerifier) *workflow.Service) (system, *workflow.Service, kube.State, kube.Mutation, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	sys := setup(t)
	if ctx != nil {
		sys.ctx = ctx
	}
	projected, err := graph.KubernetesSource(0, state)
	if err != nil {
		t.Fatal("compile native baseline", err)
	}
	data := projected.Data()
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "native", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{3}).String(), ToRevision: sourceRevision, Complete: true, Snapshot: &data}, sys.key); err != nil {
		t.Fatal(err)
	}
	impact, err := graph.KubernetesImpact(1, state, mutation)
	if err != nil {
		t.Fatal("compare native proposal impact", err)
	}
	owners := map[string]any{"reports": []string{"user:owner"}}
	for _, a := range impact.Affected {
		for _, n := range a.NewResources {
			owners[n.ID] = []string{"user:owner", "user:sec1"}
		}
		for _, p := range a.RemovedPowers {
			owners[p.NodeID] = []string{"user:owner", "user:sec1"}
		}
	}
	modules := map[string]string{}
	for _, name := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile("../../policies/" + name)
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = string(raw)
	}
	bindings := map[string]any{}
	for _, principal := range state.Principals {
		if principal.Kind != "User" {
			continue
		}
		actor := ""
		if principal.ID == "requester" || principal.ID == "owner" {
			actor = "user:" + principal.ID
		}
		bindings[graph.KubernetesNodeID(state.Cluster, "identity", principal.ID)] = actor
	}
	bundle, err := sys.authority.ProposeBundle(sys.tenant, "1.1.0", "native identity associations and resource ownership", modules, map[string]any{"resource_owners": owners, "kubernetes_identity_bindings": bindings})
	if err != nil {
		t.Fatal(err)
	}
	digest := trust.ComputePolicySigningDigest(sys.tenant, 1, bundle.BundleDigest)
	signature, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.authority.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "authority-leader", Signature: signature}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	manager := policy.Manager{Store: sys.store, Engine: sys.engine, Authority: sys.authority, Root: sys.root, Tenant: sys.tenant}
	if err := manager.Activate(sys.ctx, raw); err != nil {
		t.Fatal(err)
	}
	credentials := approval.NewCredentialStore()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte(uuid.NewString())
	if err := credentials.SaveCredential(sys.tenant, "user:owner", "native review fixture", &webauthn.Credential{ID: credential, PublicKey: public}); err != nil {
		t.Fatal(err)
	}
	verifier, err := approval.NewApprovalVerifier(credentials, "console.test", []string{"https://console.test"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	if len(configure) > 0 {
		service = configure[0](sys, verifier)
	}
	return sys, service, state, mutation, key, credential
}

func readyNativeExecution(t *testing.T, operations ...string) (system, *workflow.Service, domain.Change, kube.Admission, ed25519.PrivateKey, ed25519.PublicKey, func() *workflow.Service) {
	t.Helper()
	public, connector, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	corePublic, core, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var open func() *workflow.Service
	operation := "CREATE"
	if len(operations) > 0 {
		operation = operations[0]
	}
	sys, service, state, mutation, key, credential := nativeWorkflowOperation(t, "requester", operation, func(sys system, verifier ports.ApprovalVerifier) *workflow.Service {
		capability := workflow.Capability{Tenant: sys.tenant, Connector: "native", Protocol: "RATCHET_EXEC_V1", Expires: time.Now().Add(time.Hour), BoundCommands: true, AtomicPreconditions: true, DurableDedup: true, IndependentReadBack: true, NativeRBAC: true}
		digest, err := canon.New().Digest(struct {
			Domain string `json:"domain"`
			Body   any    `json:"body"`
		}{"RATCHET_EXEC_CAPABILITY_V1", capability})
		if err != nil {
			t.Fatal(err)
		}
		capability.Signature = ed25519.Sign(connector, digest[:])
		execution, err := workflow.NewExecution(sys.tenant, "native", public, core, capability)
		if err != nil {
			t.Fatal(err)
		}
		open = func() *workflow.Service {
			s, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant}, workflow.Config{DriftResponders: map[string]string{sys.tenant: "user:sec1"}, KubernetesConnectors: []kube.KubernetesConnectorKey{{Tenant: sys.tenant, Connector: "native", Cluster: "phase6-cluster", PublicKey: public}}}, execution)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		return open()
	})
	c, err := service.SubmitKubernetes(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.KubernetesSubmit{Mutation: mutation, CommandID: uuid.New(), Justification: "Review native access before exact one-use admission"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c, err = service.Approve(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, "user:owner", c.Digest, key, credential))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Guard(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "guard"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || c.State != domain.Executing {
		t.Fatalf("native dispatch %s %+v %v", c.State, c.Decision, err)
	}
	target := mutation.After
	if target == nil {
		target = mutation.Before
	}
	a := kube.Admission{Tenant: sys.tenant, AdmissionUID: "actual-kubernetes-uid-" + uuid.NewString(), User: kube.UserInfo{Username: state.Principals[0].Name, UID: state.Principals[0].UID, Groups: kube.PrincipalGroups(state.Principals[0])}, APIGroup: kube.RBACGroup, APIVersion: "v1", Kind: "RoleBinding", Resource: "rolebindings", Namespace: target.Namespace, Name: target.Name, SourceResourceVersion: state.ResourceVersion, ApprovedRequestID: c.ID, CommandID: c.ExecutionID, Mutation: mutation}
	return sys, service, c, a, connector, corePublic, open
}

func signedNativeAdmission(t *testing.T, a kube.Admission, key ed25519.PrivateKey) kube.SignedKubernetesAdmission {
	t.Helper()
	message := kube.SignedKubernetesAdmission{SchemaVersion: 1, Admission: a, IssuedAt: time.Now().UTC().Add(-time.Second), ExpiresAt: time.Now().UTC().Add(20 * time.Second)}
	digest, err := kube.KubernetesAdmissionSigningDigest(canon.New(), message)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature = ed25519.Sign(key, digest[:])
	return message
}

func TestNativeAdmissionConsumesOneExactCommandAcrossConcurrencyAndRestart(t *testing.T) {
	sys, service, c, a, connector, core, open := readyNativeExecution(t)
	message := signedNativeAdmission(t, a, connector)
	var wg sync.WaitGroup
	results := make(chan workflow.KubernetesDecision, 2)
	errorsOut := make(chan error, 2)
	for range 2 {
		wg.Go(func() { result, err := service.DecideKubernetes(sys.ctx, message); results <- result; errorsOut <- err })
	}
	wg.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	allows := 0
	for result := range results {
		if result.ExecutionAuthorized {
			allows++
			digest, err := workflow.KubernetesDecisionSigningDigest(result)
			if err != nil || !ed25519.Verify(core, digest[:], result.Signature) || result.AdmissionUID != a.AdmissionUID || result.CommandID != c.ExecutionID || result.ExpiresAt.IsZero() {
				t.Fatal("incomplete signed native permit", err)
			}
		} else if result.Decision.Outcome != "HOLD" || len(result.Signature) != 0 {
			t.Fatal("retry returned a permit")
		}
	}
	if allows != 1 {
		t.Fatal("native concurrent permits", allows)
	}
	if retry, err := open().DecideKubernetes(sys.ctx, message); err != nil || retry.ExecutionAuthorized || len(retry.Signature) != 0 {
		t.Fatal("native restart reused permit", err)
	}
	a.AdmissionUID = "another-kubernetes-request"
	if retry, err := open().DecideKubernetes(sys.ctx, signedNativeAdmission(t, a, connector)); err != nil || retry.ExecutionAuthorized {
		t.Fatal("command reused by a different Kubernetes UID", err)
	}
	got, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || got.State != domain.Executing {
		t.Fatal("admission invented target verification", err)
	}
	var raw []byte
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, sys.tenant, c.ExecutionID).Scan(&raw)
	}); err != nil || bytes.Contains(raw, []byte("Native Private")) {
		t.Fatal("raw usernames leaked into command", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAdmissionRefusesChangedContextAndAuthenticatesConnector(t *testing.T) {
	for _, mismatch := range []string{"object", "user", "groups", "source", "command", "dry-run", "unapproved", "signature"} {
		t.Run(mismatch, func(t *testing.T) {
			sys, service, _, a, connector, _, _ := readyNativeExecution(t)
			switch mismatch {
			case "object":
				a.Mutation.ObjectDigest = ports.Digest{9}
			case "user":
				a.User.Username = "Native Private Owner"
				a.User.UID = "native-owner-uid"
			case "groups":
				a.User.Groups = append(a.User.Groups, "system:masters")
			case "source":
				a.SourceResourceVersion = "different-cut"
			case "command":
				a.CommandID = uuid.NewString()
			case "dry-run":
				a.DryRun = true
			case "unapproved":
				a.CommandID, a.ApprovedRequestID = "", ""
			}
			message := signedNativeAdmission(t, a, connector)
			if mismatch == "signature" {
				message.Signature[0] ^= 1
			}
			result, err := service.DecideKubernetes(sys.ctx, message)
			if mismatch == "signature" {
				if !errors.Is(err, kube.ErrAuthentication) {
					t.Fatal("unsigned evidence accepted", err)
				}
				return
			}
			if err != nil || result.ExecutionAuthorized || len(result.Signature) != 0 || result.Decision.Outcome == "ALLOW" {
				t.Fatal("mismatched context authorized", mismatch, result.Decision, err)
			}
			var count int
			if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
				return tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.native_admissions WHERE tenant_id=$1`, sys.tenant).Scan(&count)
			}); err != nil || count != 0 {
				t.Fatal("refusal consumed command", err)
			}
		})
	}
}

func TestNativeSourceAdvanceInvalidatesAnOtherwiseExactApprovedAdmission(t *testing.T) {
	sys, service, _, admission, connector, _, _ := readyNativeExecution(t)
	snapshot, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	state, err := snapshot.KubernetesState(admission.Mutation.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	state.ResourceVersion = "a-new-cut-with-the-same-powers"
	next, err := graph.KubernetesSource(0, state)
	if err != nil {
		t.Fatal(err)
	}
	data := next.Data()
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "native", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{31}).String(), ToRevision: 11, Complete: true, Snapshot: &data}, sys.key); err != nil {
		t.Fatal(err)
	}
	result, err := service.DecideKubernetes(sys.ctx, signedNativeAdmission(t, admission, connector))
	if err != nil || result.ExecutionAuthorized || result.Decision.Outcome != "HOLD" {
		t.Fatal("old source cut admitted after source advancement", err)
	}
}

func TestNativeExecutionRequiresConsumedAdmissionAndIndependentExactReadBack(t *testing.T) {
	sys, service, c, a, connector, _, _ := readyNativeExecution(t)
	observed := *a.Mutation.After
	observed.UID, observed.ResourceVersion = "apiserver-assigned-uid", "opaque/assigned-rv"
	a.CreateUID = observed.UID
	r := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "native", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: true, ReadBackVerified: true, ObservedTenant: sys.tenant, ObservedTarget: c.Intent.Target, ObservedRevision: 15, ObservedAt: time.Now().UTC(), AppliedAt: time.Now().UTC(), Kubernetes: &workflow.NativeObservation{AdmissionUID: a.AdmissionUID, Object: &observed}}
	setDigest := func() {
		t.Helper()
		var err error
		r.ObservationDigest, err = workflow.NativeObservationDigest(r)
		if err != nil {
			t.Fatal(err)
		}
	}
	setDigest()
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, r, connector)); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("unadmitted write verified", err)
	}
	permit, err := service.DecideKubernetes(sys.ctx, signedNativeAdmission(t, a, connector))
	if err != nil || !permit.ExecutionAuthorized {
		t.Fatal("native permit", err)
	}
	r.Kubernetes.ContextDigest = permit.ContextDigest
	r.AppliedAt = time.Now().UTC()
	r.ObservedAt = r.AppliedAt
	ack := r
	ack.MessageID, ack.ReadBackVerified = uuid.NewString(), false
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, ack, connector)); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || c.State != domain.Executing {
		t.Fatal("acknowledgement treated as execution", err)
	}
	if err := service.Reconcile(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "reconcile"}); err != nil {
		t.Fatal(err)
	}
	var probe []byte
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT payload FROM ratchet.outbox WHERE tenant_id=$1 AND subject=$2 AND convert_from(payload,'UTF8')::jsonb->>'verify_only'='true' ORDER BY sequence DESC LIMIT 1`, sys.tenant, "ratchet."+sys.tenant+".exec.native").Scan(&probe)
	}); err != nil {
		t.Fatal("native recovery probe missing", err)
	}
	var command workflow.PreparedCommand
	if json.Unmarshal(probe, &command) != nil || !command.VerifyOnly || command.Kubernetes == nil || command.CommandID != c.ExecutionID {
		t.Fatal("native recovery dispatched another write")
	}
	for _, mismatch := range []string{"context", "admission", "overgrant", "application-time", "assigned-uid"} {
		bad := r
		observation := *r.Kubernetes
		object := *r.Kubernetes.Object
		observation.Object = &object
		bad.Kubernetes = &observation
		bad.MessageID = uuid.NewString()
		switch mismatch {
		case "assigned-uid":
			bad.Kubernetes.Object.UID = "different-apiserver-object"
		case "context":
			observation.ContextDigest = ports.Digest{4}
		case "admission":
			observation.AdmissionUID = "unrelated-uid"
		case "overgrant":
			object.Subjects = []kube.Subject{{Kind: "Group", Name: "system:masters"}}
		case "application-time":
			bad.AppliedAt = permit.ExpiresAt.Add(time.Second)
			bad.ObservedAt = bad.AppliedAt
		}
		bad.ObservationDigest, err = workflow.NativeObservationDigest(bad)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, bad, connector)); !errors.Is(err, workflow.ErrPermission) {
			t.Fatal("mismatched native result accepted", mismatch, err)
		}
	}
	r.MessageID = uuid.NewString()
	setDigest()
	raw := signedResult(t, r, connector)
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, raw); err != nil {
		t.Fatal("exact independent native observation rejected", err)
	}
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, raw); err != nil {
		t.Fatal("read-back duplicate not idempotent", err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || c.State != domain.Executed {
		t.Fatal("native execution not verified", c.State, err)
	}
	events, err := sys.store.LoadStream(sys.ctx, sys.tenant, "change:"+c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if bytes.Contains(e.Entry.Canonical, []byte("Native Private")) {
			t.Fatal("native read-back leaked private subjects")
		}
	}
}

func TestNativeUpdateAndDeleteRequireExactPreimageAndOpaqueObservedVersions(t *testing.T) {
	for _, operation := range []string{"UPDATE", "DELETE"} {
		t.Run(operation, func(t *testing.T) {
			sys, service, c, a, connector, _, _ := readyNativeExecution(t, operation)
			permit, err := service.DecideKubernetes(sys.ctx, signedNativeAdmission(t, a, connector))
			if err != nil || !permit.ExecutionAuthorized {
				t.Fatal("exact native preimage not admitted", operation, err)
			}
			observation := &workflow.NativeObservation{AdmissionUID: a.AdmissionUID, ContextDigest: permit.ContextDigest}
			if operation == "UPDATE" {
				object := *a.Mutation.After
				object.ResourceVersion = "opaque/new-version-without-numeric-increment"
				observation.Object = &object
			} else {
				observation.DeletedUID = a.Mutation.Before.UID
			}
			stamp := time.Now().UTC()
			r := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "native", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: true, ReadBackVerified: true, ObservedTenant: sys.tenant, ObservedTarget: c.Intent.Target, ObservedRevision: 12, ObservedAt: stamp, AppliedAt: stamp, Kubernetes: observation}
			wrong := *observation
			if operation == "UPDATE" {
				object := *observation.Object
				object.UID = "same-name-recreated-object"
				wrong.Object = &object
			} else {
				wrong.DeletedUID = "different-object-uid"
			}
			bad := r
			bad.MessageID, bad.Kubernetes = uuid.NewString(), &wrong
			bad.ObservationDigest, err = workflow.NativeObservationDigest(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, bad, connector)); !errors.Is(err, workflow.ErrPermission) {
				t.Fatal("same-name different UID accepted", err)
			}
			r.ObservationDigest, err = workflow.NativeObservationDigest(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, r, connector)); err != nil {
				t.Fatal("exact native observation rejected", operation, err)
			}
			c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
			if err != nil || c.State != domain.Executed {
				t.Fatal("native lifecycle incomplete", operation, c.State, err)
			}
		})
	}
}

func TestNativeDecisionRPCUsesTLSAndConnectorSignatureWithoutBrowserSession(t *testing.T) {
	sys, service, _, a, connector, _, _ := readyNativeExecution(t)
	handler, err := api.NewKubernetesDecisionHandler(service)
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewRecorder()
	handler.ServeHTTP(plain, httptest.NewRequest(http.MethodPost, ratchetv1connect.DecisionServiceDecideKubernetesProcedure, nil))
	if plain.Code != http.StatusUpgradeRequired {
		t.Fatal("native admission accepted plaintext")
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := ratchetv1connect.NewDecisionServiceClient(server.Client(), server.URL)
	raw, err := json.Marshal(signedNativeAdmission(t, a, connector))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.DecideKubernetes(sys.ctx, connect.NewRequest(&v1.KubernetesDecisionRequest{SignedAdmissionJson: raw}))
	if err != nil || !response.Msg.ExecutionAuthorized || len(response.Msg.SignedNativeDecisionJson) == 0 || response.Msg.AdmissionContextDigest == "" {
		t.Fatal("signed native RPC failed", err)
	}
	response, err = client.DecideKubernetes(sys.ctx, connect.NewRequest(&v1.KubernetesDecisionRequest{SignedAdmissionJson: raw}))
	if err != nil || response.Msg.ExecutionAuthorized || len(response.Msg.SignedNativeDecisionJson) != 0 {
		t.Fatal("RPC replay reused permit", err)
	}
	invalid := signedNativeAdmission(t, a, connector)
	invalid.Signature[0] ^= 1
	raw, err = json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DecideKubernetes(sys.ctx, connect.NewRequest(&v1.KubernetesDecisionRequest{SignedAdmissionJson: raw})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatal("authentication failure not distinguished", err)
	}
	if _, err := client.DecideKubernetes(sys.ctx, connect.NewRequest(&v1.KubernetesDecisionRequest{SignedAdmissionJson: []byte(`{"unexpected":true}`)})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("request error not distinguished", err)
	}
}

func TestNativeSubmissionAssessmentApprovalReplayAndPrivacy(t *testing.T) {
	sys, service, state, mutation, key, credential := nativeWorkflow(t, "requester")
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	input := workflow.KubernetesSubmit{Mutation: mutation, CommandID: uuid.New(), Justification: "Approve ordinary native report access"}
	c, err := service.SubmitKubernetes(sys.ctx, actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if c.Intent.Kubernetes == nil || c.Intent.Kubernetes.PlanID != c.ID {
		t.Fatal("native intent lacks exact commitments")
	}
	retry, err := service.SubmitKubernetes(sys.ctx, actor, input)
	if err != nil || retry.ID != c.ID || retry.Revision != c.Revision {
		t.Fatal("native duplicate submission changed workflow", err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || c.State != domain.AwaitingApproval || c.Decision.Quorum != 1 {
		t.Fatalf("native owner review: %s %+v %v", c.State, c.Decision, err)
	}
	owner := workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}
	detail, err := service.ResponseDetail(sys.ctx, owner, c)
	if err != nil || !detail {
		t.Fatal("independent owner cannot inspect native request", err)
	}
	context, err := service.KubernetesContext(sys.ctx, owner, c)
	if err != nil || context.After.Subjects[0].Name != "Native Private Requester" {
		t.Fatal("authorized exact native context unavailable", err)
	}
	c, err = service.Approve(sys.ctx, owner, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, owner.ID, c.Digest, key, credential))
	if err != nil || c.State != domain.Approved {
		t.Fatal("native independent approval failed", c.State, err)
	}
	evidence, err := service.DecisionEvidence(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}, c.ID, 0)
	if err != nil {
		t.Fatal("native decision replay", err)
	}
	if evidence.Kubernetes == nil {
		t.Fatal("non-personal replay projection omitted")
	}
	events, err := sys.store.LoadStream(sys.ctx, sys.tenant, "change:"+c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if bytes.Contains(e.Entry.Canonical, []byte("Native Private")) {
			t.Fatal("native names leaked into retained lifecycle")
		}
	}
	raw, err := json.Marshal(evidence)
	if err != nil || bytes.Contains(raw, []byte("Native Private")) {
		t.Fatal("native replay evidence leaked actor names", err)
	}
	if err := sys.store.DeletePrivateRecord(sys.ctx, sys.tenant, uuid.MustParse(c.Intent.Kubernetes.PrivateReference)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DecisionEvidence(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}, c.ID, 0); err != nil {
		t.Fatal("private deletion broke anonymous policy replay", err)
	}
	if _, err := service.KubernetesContext(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}, c); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("deleted raw intent was reconstructed", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal("native chain verification after deletion", err)
	}
	// Original idempotency survives target/source advancement and does not build
	// a second plan from later state for an old command ID.
	state.ResourceVersion = "opaque/later-source-cut"
	updated, err := graph.KubernetesSource(0, state)
	if err != nil {
		t.Fatal(err)
	}
	data := updated.Data()
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "native", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{4}).String(), ToRevision: 11, Complete: true, Snapshot: &data}, sys.key); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := service.SubmitKubernetes(sys.ctx, actor, input); err != nil || duplicate.Revision != 1 {
		t.Fatal("native retry used newer source context", err)
	}
}

func TestNativeBeneficiaryCannotApproveAndUnapprovedChangesCannotDispatch(t *testing.T) {
	sys, service, _, mutation, key, credential := nativeWorkflow(t, "owner")
	c, err := service.SubmitKubernetes(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.KubernetesSubmit{Mutation: mutation, CommandID: uuid.New(), Justification: "Review grant benefiting the resource owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, "user:owner", c.Digest, key, credential)); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("mapped native beneficiary approved their own increase", err)
	}
	if err := service.Guard(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "guard"}); err != nil && !errors.Is(err, domain.ErrTransition) {
		t.Fatal(err)
	}
	var commands int
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.execution_attempts WHERE tenant_id=$1`, sys.tenant).Scan(&commands)
	}); err != nil || commands != 0 {
		t.Fatal("unapproved native write staged", err)
	}
}
