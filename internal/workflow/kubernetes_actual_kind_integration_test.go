//go:build integration && kindintegration

package workflow_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector/k8s"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/testutil/kindadmission"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestNativeActualKindComparisonCodec(t *testing.T) {
	cluster := &kindadmission.Cluster{Kubeconfig: os.Getenv("RATCHET_KIND_KUBECONFIG")}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a, err := k8s.NewConfiguredAdapter(k8s.AdapterConfig{Tenant: "codec", Connector: "native", Cluster: "phase6-actual-admission", Kubeconfig: cluster.Kubeconfig, StateDirectory: t.TempDir(), DirectoryComplete: true, Directory: cluster.Principals(t, ctx)})
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := a.NativeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	object := kube.Object{Kind: "RoleBinding", Name: "codec-proposal", Namespace: "default", RoleKind: "ClusterRole", RoleName: "view", Subjects: []kube.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "default"}}}
	next, err := state.After(kube.Mutation{Cluster: state.Cluster, Connector: "native", Operation: "CREATE", After: &object, ObjectDigest: ports.Digest{1}})
	if err != nil {
		t.Fatal(err)
	}
	base, err := graph.CompileKubernetes(1, state)
	if err != nil {
		t.Fatal(err)
	}
	before, err := graph.CompileKubernetes(1, state, next)
	if err != nil {
		t.Fatal(err)
	}
	after, err := graph.CompileKubernetes(1, next, state)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := base.Difference(before)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := base.Difference(after)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual comparison: base nodes=%d edges=%d; before +%d/-%d nodes +%d/-%d edges; after +%d/-%d nodes +%d/-%d edges", len(base.Data().Nodes), len(base.Data().Edges), len(d1.NodesAdded), len(d1.NodesRemoved), len(d1.EdgesAdded), len(d1.EdgesRemoved), len(d2.NodesAdded), len(d2.NodesRemoved), len(d2.EdgesAdded), len(d2.EdgesRemoved))
	raw, err := json.Marshal(workflow.KubernetesPlan{Version: 1, Current: base.Data(), Before: before.Data(), After: after.Data()})
	if err != nil {
		t.Fatal(err)
	}
	var plan workflow.KubernetesPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual comparison replay document bytes=%d", len(raw))
}

func TestNativeActualKindAdmissionApprovalReadBackAndOutage(t *testing.T) {
	cluster := kindadmission.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	cluster.Apply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]string{"name": "ratchet-native"}})
	cluster.Apply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]string{"name": "beneficiary", "namespace": "ratchet-native"}})
	cluster.Apply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]string{"name": "drift-beneficiary", "namespace": "ratchet-native"}})
	cluster.Apply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]string{"name": "ratchet-native-reader"}, "rules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get"}}}})
	directory := cluster.Principals(t, ctx)
	probe, err := k8s.NewConfiguredAdapter(k8s.AdapterConfig{Tenant: "probe", Connector: "native", Cluster: "phase6-actual-admission", Kubeconfig: cluster.Kubeconfig, StateDirectory: t.TempDir(), DirectoryComplete: true, Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	state, revision, err := probe.NativeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rawObject := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": map[string]any{"name": "exact-approved", "namespace": "ratchet-native"}, "roleRef": map[string]string{"apiGroup": kube.RBACGroup, "kind": "ClusterRole", "name": "ratchet-native-reader"}, "subjects": []any{map[string]string{"kind": "ServiceAccount", "name": "beneficiary", "namespace": "ratchet-native"}}}
	object, objectDigest, err := k8s.NormalizeObject(rawObject)
	if err != nil {
		t.Fatal(err)
	}
	mutation := kube.Mutation{Cluster: state.Cluster, Connector: "native", Operation: "CREATE", After: &object, ObjectDigest: objectDigest}
	public, connector, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	corePublic, coreKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sys, service, _, _, approvalKey, credential := nativeWorkflowStateContext(t, ctx, state, mutation, revision, func(sys system, verifier ports.ApprovalVerifier) *workflow.Service {
		capability := workflow.Capability{Tenant: sys.tenant, Connector: "native", Protocol: "RATCHET_EXEC_V1", Expires: time.Now().Add(time.Hour), BoundCommands: true, AtomicPreconditions: true, DurableDedup: true, IndependentReadBack: true, NativeRBAC: true}
		digest, err := canon.New().Digest(struct {
			Domain string `json:"domain"`
			Body   any    `json:"body"`
		}{"RATCHET_EXEC_CAPABILITY_V1", capability})
		if err != nil {
			t.Fatal(err)
		}
		capability.Signature = ed25519.Sign(connector, digest[:])
		execution, err := workflow.NewExecution(sys.tenant, "native", public, coreKey, capability)
		if err != nil {
			t.Fatal(err)
		}
		service, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant}, workflow.Config{DriftResponders: map[string]string{sys.tenant: "user:sec1"}, KubernetesConnectors: []kube.KubernetesConnectorKey{{Tenant: sys.tenant, Connector: "native", Cluster: state.Cluster, PublicKey: public}}}, execution)
		if err != nil {
			t.Fatal(err)
		}
		return service
	})
	adapter, err := k8s.NewConfiguredAdapter(k8s.AdapterConfig{Tenant: sys.tenant, Connector: "native", Cluster: state.Cluster, Kubeconfig: cluster.Kubeconfig, StateDirectory: t.TempDir(), DirectoryComplete: true, Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.NativeSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	coreHandler, err := api.NewKubernetesDecisionHandler(service)
	if err != nil {
		t.Fatal(err)
	}
	core := httptest.NewTLSServer(coreHandler)
	defer core.Close()
	broker, err := bus.Connect(os.Getenv("RATCHET_NATS_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if err := broker.EnsureTenant(ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
	if err := broker.EnsureExecution(ctx, sys.tenant, "native"); err != nil {
		t.Fatal(err)
	}
	results := make(chan workflow.ExecutionResult, 8)
	h, err := k8s.NewNativeAdmissionHandler(k8s.AdmissionConfig{Adapter: adapter, CoreURL: core.URL, CorePublicKey: corePublic, SigningKey: connector, StorageKey: sys.key, HTTPClient: core.Client(), DecisionError: func(err error) { t.Logf("actual core decision RPC error: %v", err) }, Results: func(ctx context.Context, id string, raw []byte) error {
		var result workflow.ExecutionResult
		if err := json.Unmarshal(raw, &result); err != nil {
			return err
		}
		select {
		case results <- result:
		default:
		}
		return broker.Publish(ctx, "ratchet."+sys.tenant+".exec.results", id, raw)
	}})
	if err != nil {
		t.Fatal(err)
	}
	var approvedCalls, refusedCalls, outageCalls atomic.Int64
	var approvedNS atomic.Int64
	webhook := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		response := httptest.NewRecorder()
		h.HTTPHandler().ServeHTTP(response, r)
		var review k8s.AdmissionReview
		if json.Unmarshal(response.Body.Bytes(), &review) == nil && review.Response != nil {
			if review.Response.Allowed {
				approvedCalls.Add(1)
				approvedNS.Store(time.Since(start).Nanoseconds())
			} else if review.Response.Status != nil && review.Response.Status.Code == 503 {
				outageCalls.Add(1)
			} else {
				refusedCalls.Add(1)
			}
		}
		for key, values := range response.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	})}
	webhookDone := make(chan error, 1)
	go func() { webhookDone <- webhook.Serve(tls.NewListener(cluster.Listener, cluster.TLS)) }()
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := webhook.Shutdown(stop); err != nil {
			t.Error(err)
		}
		if err := <-webhookDone; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	consume, stopConsume := context.WithCancel(ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resultDone := make(chan error, 1)
	go func() {
		resultDone <- broker.ConsumeResults(consume, sys.tenant, func(ctx context.Context, raw []byte) error {
			return service.RecordExecutionResult(ctx, sys.tenant, raw)
		}, logger)
	}()
	stageDone := make(chan error, 1)
	staged := make(chan string, 8)
	go func() {
		stageDone <- broker.ConsumeExecution(consume, sys.tenant, "native", func(ctx context.Context, raw []byte) error {
			var command workflow.PreparedCommand
			if err := json.Unmarshal(raw, &command); err != nil {
				return err
			}
			if err := h.Stage(ctx, command); err != nil {
				return err
			}
			staged <- command.CommandID
			return nil
		}, logger)
	}()
	defer func() {
		stopConsume()
		for _, done := range []chan error{resultDone, stageDone} {
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("native durable consumer did not stop")
			}
		}
	}()
	cluster.Apply(t, ctx, cluster.WebhookConfiguration("ratchet-native"))
	t.Log("actual API-server webhook installed; checking refusal and approved lifecycle")
	// Propagation is proven by an actual dry-run request, never a fixed sleep.
	probeObject := map[string]any{}
	for key, value := range rawObject {
		probeObject[key] = value
	}
	probeObject["metadata"] = map[string]string{"name": "unapproved-probe", "namespace": "ratchet-native"}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := cluster.Command(ctx, probeObject, "create", "-f", "-", "--dry-run=server")
		if err != nil && refusedCalls.Load() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual API server never reached authenticated refusing webhook")
		}
		time.Sleep(100 * time.Millisecond)
	}
	c, err := service.SubmitKubernetes(ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.KubernetesSubmit{Mutation: mutation, CommandID: uuid.New(), Justification: "Actual kind one-use RBAC admission"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("actual native proposal submitted")
	if err := service.Assess(ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(ctx, sys.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c, err = service.Approve(ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, "user:owner", c.Digest, approvalKey, credential))
	if err != nil {
		t.Fatalf("independent actual cryptographic approval: %v (%+v)", err, c.Decision)
	}
	if err := service.Guard(ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "guard"}); err != nil {
		t.Fatal(err)
	}
	t.Log("independent approval accepted and exact native command guarded")
	c, err = sys.store.ReadChange(ctx, sys.tenant, c.ID)
	if err != nil || c.State != domain.Executing {
		t.Fatalf("actual native dispatch state %s: %v %+v", c.State, err, c.Decision)
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		select {
		case id := <-staged:
			if id != c.ExecutionID {
				t.Fatal("different command staged")
			}
			goto delivered
		default:
		}
		select {
		case err := <-stageDone:
			t.Fatalf("actual signed command consumer stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("durable signed command was not staged")
		}
		worked, err := sys.store.DeliverOne(ctx, sys.tenant, broker.Publish)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			time.Sleep(10 * time.Millisecond)
		}
	}
delivered:
	reconcileDone := make(chan struct{})
	readCtx, stopRead := context.WithCancel(ctx)
	go func() {
		defer close(reconcileDone)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-readCtx.Done():
				return
			case <-tick.C:
				_ = h.ReconcileAll(readCtx)
			}
		}
	}()
	defer func() { stopRead(); <-reconcileDone }()
	started := time.Now()
	if output, err := cluster.Command(ctx, rawObject, "create", "-f", "-"); err != nil {
		t.Fatalf("actual approved API write: %v %s", err, output)
	}
	writeElapsed := time.Since(started)
	deadline = time.Now().Add(10 * time.Second)
	for {
		c, err = sys.store.ReadChange(ctx, sys.tenant, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if c.State == domain.Executed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("actual target not independently verified: %s", c.State)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if approvedCalls.Load() != 1 {
		t.Fatal("approved API calls", approvedCalls.Load())
	}
	var admissionCount int
	if err := sys.store.WithTenantTx(ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM ratchet.native_admissions WHERE tenant_id=$1 AND command_id=$2::uuid`, sys.tenant, c.ExecutionID).Scan(&admissionCount)
	}); err != nil || admissionCount != 1 {
		t.Fatal("actual admission not one-use correlated", admissionCount, err)
	}
	// Refresh from actual storage, then close the real core HTTPS server.
	if _, _, err := adapter.NativeSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	core.Close()
	probeObject["metadata"] = map[string]string{"name": "outage-probe", "namespace": "ratchet-native"}
	output, err := cluster.Command(ctx, probeObject, "create", "-f", "-")
	if err == nil || outageCalls.Load() == 0 {
		t.Fatalf("core outage did not block actual sensitive write: %v %s", err, output)
	}
	output, err = cluster.Command(ctx, nil, "get", "rolebinding", "outage-probe", "-n", "ratchet-native", "--ignore-not-found=true", "-o", "json")
	if err != nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("outage grant exists: %v %s", err, output)
	}
	// Feed actual source cuts and connector-authenticated observations through
	// the production ingest/drift boundaries, independently of admission allow.
	t.Log("actual approved write/read-back and outage gates passed; checking real drift evidence")
	var readback workflow.ExecutionResult
	select {
	case readback = <-results:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	registry, err := graph.NewRegistry(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ingestor, err := bus.NewIngestor(sys.store, registry, canon.New(), sys.key, []bus.ConnectorKey{{TenantID: sys.tenant, ConnectorID: "native", PublicKey: public}})
	if err != nil {
		t.Fatal(err)
	}
	syncCut := func() (kube.State, int64, int64) {
		message, err := adapter.SignedSnapshot(ctx, connector)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := protojson.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if err := ingestor.Handle(ctx, sys.tenant, raw); err != nil {
			t.Fatal(err)
		}
		var cut kube.State
		if err := json.Unmarshal(message.GetKubernetes().NormalizedStateJson, &cut); err != nil {
			t.Fatal(err)
		}
		snapshot, err := sys.store.CurrentGraph(ctx, sys.tenant, sys.key)
		if err != nil {
			t.Fatal(err)
		}
		return cut, message.Envelope.SourceRevision, snapshot.Version()
	}
	post, postRevision, postVersion := syncCut()
	baseVersion := c.Envelope.GraphVersion
	report := workflow.SignedKubernetesDrift{SchemaVersion: 1, Tenant: sys.tenant, Connector: "native", Cluster: state.Cluster, DriftID: uuid.NewString(), OperationID: uuid.NewString(), CorrelationID: c.CorrelationID, BaselineGraphVersion: baseVersion, SourceRevision: postRevision, Before: state, Mutation: mutation, Observation: *readback.Kubernetes, CommandID: c.ExecutionID, AppliedAt: readback.AppliedAt, ObservedAt: readback.ObservedAt}
	var receipts []workflow.KubernetesDriftReceipt
	acceptDrift := func(ctx context.Context, _ string, _ string, raw []byte) error {
		receipt, err := service.RecordDrift(ctx, sys.tenant, raw)
		if err != nil {
			return err
		}
		var evidence workflow.KubernetesDriftReceipt
		if err := sys.store.WithTenantTx(ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
			var document []byte
			if err := tx.QueryRow(ctx, `SELECT document FROM ratchet.native_drift_receipts WHERE tenant_id=$1 AND drift_id=$2::uuid`, sys.tenant, report.DriftID).Scan(&document); err != nil {
				return err
			}
			return json.Unmarshal(document, &evidence)
		}); err != nil {
			return err
		}
		if receipt.Outcome != evidence.Outcome {
			return eventstore.ErrIntegrity
		}
		receipts = append(receipts, evidence)
		return nil
	}
	if err := adapter.PublishDrift(ctx, report, connector, acceptDrift); err != nil {
		t.Fatal(err)
	}
	if receipts[0].Outcome != "CORRELATED_APPROVED_COMMAND" || receipts[0].Impact == nil {
		t.Fatalf("actual approved drift not correlated: %+v", receipts[0])
	}
	t.Log("actual approved drift correlated against committed real source cut")
	// Remove only this test's webhook, representing an out-of-band control-plane
	// bypass. No production grant path or rollback exception is introduced.
	if output, err := cluster.Command(ctx, nil, "delete", "validatingwebhookconfiguration", "ratchet-native"); err != nil {
		t.Fatalf("owned fault injection: %v %s", err, output)
	}
	unapproved := map[string]any{}
	for key, value := range rawObject {
		unapproved[key] = value
	}
	unapproved["metadata"] = map[string]string{"name": "actual-unapproved-drift", "namespace": "ratchet-native"}
	unapproved["subjects"] = []any{map[string]string{"kind": "ServiceAccount", "name": "drift-beneficiary", "namespace": "ratchet-native"}}
	cluster.Apply(t, ctx, unapproved)
	current, currentRevision, _ := syncCut()
	var observed *kube.Object
	for _, object := range current.Objects {
		if object.Kind == "RoleBinding" && object.Name == "actual-unapproved-drift" {
			copyObject := object
			observed = &copyObject
		}
	}
	if observed == nil {
		t.Fatal("real out-of-band write not observed")
	}
	proposal := *observed
	proposal.UID, proposal.ResourceVersion = "", ""
	watchDigest, err := canon.New().Digest(*observed)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	report = workflow.SignedKubernetesDrift{SchemaVersion: 1, Tenant: sys.tenant, Connector: "native", Cluster: state.Cluster, DriftID: uuid.NewString(), OperationID: uuid.NewString(), CorrelationID: uuid.NewString(), BaselineGraphVersion: postVersion, SourceRevision: currentRevision, Before: post, Mutation: kube.Mutation{Cluster: state.Cluster, Connector: "native", Operation: "CREATE", After: &proposal, ObjectDigest: watchDigest}, Observation: workflow.NativeObservation{Object: observed}, AppliedAt: now, ObservedAt: now}
	if err := adapter.PublishDrift(ctx, report, connector, acceptDrift); err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 || receipts[1].Outcome != "HELD_FOR_REVIEW" || receipts[1].IncidentID == "" || receipts[1].Impact == nil {
		t.Fatal("actual drift incident missing complete evidence")
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	incident, err := service.GetIncident(ctx, actor, receipts[1].IncidentID)
	if err != nil || incident.Incident.Kubernetes == nil {
		t.Fatal("actual drift get evidence", err)
	}
	page, err := service.ListIncidents(ctx, actor, "OPEN", 0, 0, 10)
	if err != nil || len(page.Incidents) != 1 {
		t.Fatal("actual drift list evidence", err)
	}
	// The real full-cluster ingest has more than one ledger page. Hidden graph
	// records still consume cursor positions; follow the complete contiguous feed.
	var cursor int64
	updates := 0
	for {
		stream, err := service.StreamPage(ctx, actor, "incidents", cursor)
		if err != nil {
			t.Fatal("actual drift watch evidence", err)
		}
		for _, update := range stream.Incidents {
			if update.Incident.Incident.ID != receipts[1].IncidentID || update.Incident.Incident.Kubernetes == nil {
				t.Fatal("stream returned unrelated or incomplete native evidence")
			}
			updates++
		}
		if stream.After >= stream.End {
			break
		}
		if stream.After <= cursor {
			t.Fatal("incident stream cursor did not advance")
		}
		cursor = stream.After
	}
	if updates != 1 {
		t.Fatalf("actual drift incident stream updates: got %d, want 1", updates)
	}
	t.Logf("actual kind acceptance: approved=%d policy_refusals=%d dependency_refusals=%d webhook_ms=%.2f api_write_ms=%.2f", approvedCalls.Load(), refusedCalls.Load(), outageCalls.Load(), float64(approvedNS.Load())/1e6, float64(writeElapsed)/float64(time.Millisecond))
	if dir := os.Getenv("RATCHET_EVALUATION_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			t.Fatal("absolute evidence output directory required")
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		evidence, err := json.Marshal(map[string]any{"actual_api_server": true, "mutual_tls": true, "one_use_admissions": admissionCount, "executed": c.State, "approved": approvedCalls.Load(), "policy_refusals": refusedCalls.Load(), "dependency_refusals": outageCalls.Load(), "webhook_ms": float64(approvedNS.Load()) / 1e6, "api_write_ms": float64(writeElapsed) / float64(time.Millisecond), "approved_drift": receipts[0].Outcome, "unapproved_drift": receipts[1].Outcome, "incident_get_list_stream": updates == 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "phase6-actual-kind.json"), evidence, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
