//go:build integration

package workflow_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func nativeDriftFixture(t *testing.T, approved bool) (system, *workflow.Service, workflow.SignedKubernetesDrift, ed25519.PrivateKey, string) {
	t.Helper()
	sys, service, c, admission, connector, _, _ := readyNativeExecution(t)
	baseline, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	before, err := baseline.KubernetesState(admission.Mutation.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	observation := workflow.NativeObservation{}
	command := ""
	if approved {
		permit, err := service.DecideKubernetes(sys.ctx, signedNativeAdmission(t, admission, connector))
		if err != nil || !permit.ExecutionAuthorized {
			t.Fatal("drift setup native permit", err)
		}
		observation.AdmissionUID, observation.ContextDigest, command = admission.AdmissionUID, permit.ContextDigest, c.ExecutionID
	}
	observed := *admission.Mutation.After
	observed.UID, observed.ResourceVersion = "assigned-binding-uid", "opaque/watch-rv"
	observation.Object = &observed
	current, err := before.Clone()
	if err != nil {
		t.Fatal(err)
	}
	current.ResourceVersion = "opaque/post-write-cut"
	current.Objects = append(current.Objects, observed)
	projected, err := graph.KubernetesSource(0, current)
	if err != nil {
		t.Fatal(err)
	}
	data := projected.Data()
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "native", MessageID: uuid.New(), CorrelationID: c.CorrelationID, WireDigest: (ports.Digest{21}).String(), ToRevision: 11, Complete: true, Snapshot: &data}, sys.key); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	message := workflow.SignedKubernetesDrift{SchemaVersion: 1, Tenant: sys.tenant, Connector: "native", Cluster: before.Cluster, DriftID: uuid.NewString(), OperationID: uuid.NewString(), CorrelationID: c.CorrelationID, BaselineGraphVersion: c.Envelope.GraphVersion, SourceRevision: 11, Before: before, Mutation: admission.Mutation, Observation: observation, CommandID: command, AppliedAt: now, ObservedAt: now}
	return sys, service, message, connector, c.ID
}

func signedNativeDrift(t *testing.T, message workflow.SignedKubernetesDrift, key ed25519.PrivateKey) []byte {
	t.Helper()
	message.Signature = nil
	digest, err := workflow.KubernetesDriftSigningDigest(message)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature = ed25519.Sign(key, digest[:])
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeDriftRetainsRealImpactAndIncidentEvidenceWithDurableDedup(t *testing.T) {
	sys, service, message, connector, _ := nativeDriftFixture(t, false)
	raw := signedNativeDrift(t, message, connector)
	receipt, err := service.RecordKubernetesDrift(sys.ctx, sys.tenant, raw)
	if err != nil || receipt.Outcome != "HELD_FOR_REVIEW" || receipt.IncidentID == "" || receipt.Impact == nil || receipt.Impact.MonotonicReduction || receipt.Replay == nil || receipt.Decision.Outcome != "REQUIRE_APPROVAL" {
		t.Fatalf("native drift evidence %+v %v", receipt, err)
	}
	duplicate, err := service.RecordKubernetesDrift(sys.ctx, sys.tenant, raw)
	if err != nil || duplicate.IncidentID != receipt.IncidentID || !duplicate.At.Equal(receipt.At) {
		t.Fatal("native drift retry duplicated incident", err)
	}
	message.DriftID = uuid.NewString()
	if duplicate, err := service.RecordKubernetesDrift(sys.ctx, sys.tenant, signedNativeDrift(t, message, connector)); err != nil || duplicate.IncidentID != receipt.IncidentID {
		t.Fatal("new transport drift ID bypassed semantic dedup", err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	view, err := service.GetIncident(sys.ctx, actor, receipt.IncidentID)
	if err != nil || view.Incident.Kubernetes == nil || view.Incident.Status != "OPEN" || view.VerifiedCorrection != nil {
		t.Fatal("native incident read model", err)
	}
	page, err := service.ListIncidents(sys.ctx, actor, "OPEN", 0, 0, 20)
	if err != nil || len(page.Incidents) != 1 {
		t.Fatal("native incident list", err)
	}
	updates, err := service.StreamPage(sys.ctx, actor, "incidents", 0)
	if err != nil || len(updates.Incidents) != 1 || updates.Incidents[0].Incident.Incident.Kubernetes == nil {
		t.Fatal("native incident stream omitted evidence", err)
	}
	document, err := json.Marshal(view)
	if err != nil || bytes.Contains(document, []byte("Native Private")) {
		t.Fatal("native drift read model retained raw usernames", err)
	}
	privateID := uuid.NewSHA1(uuid.MustParse(message.OperationID), []byte(sys.tenant+":native:native-drift"))
	if err := sys.store.DeletePrivateRecord(sys.ctx, sys.tenant, privateID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetIncident(sys.ctx, actor, receipt.IncidentID); err != nil {
		t.Fatal("private erasure broke native incident evidence", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDriftCorrelatesOnlyAnExactConsumedAdmissionAndDoesNotVerifyExecution(t *testing.T) {
	sys, service, message, connector, request := nativeDriftFixture(t, true)
	raw := signedNativeDrift(t, message, connector)
	wrapper, err := protojson.Marshal(&v1.SignedKubernetesDriftReport{SignedKubernetesDriftJson: raw})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := service.RecordDrift(sys.ctx, sys.tenant, wrapper)
	if err != nil || receipt.Outcome != "CORRELATED_APPROVED_COMMAND" || receipt.IncidentID != "" {
		t.Fatal("approved native observation not correlated", receipt.Outcome, err)
	}
	c, err := sys.store.ReadChange(sys.ctx, sys.tenant, request)
	if err != nil || c.State != domain.Executing {
		t.Fatal("watch evidence replaced independent read-back", err)
	}
	message.OperationID, message.DriftID = uuid.NewString(), uuid.NewString()
	message.Observation.ContextDigest = ports.Digest{14}
	wrong, err := service.RecordKubernetesDrift(sys.ctx, sys.tenant, signedNativeDrift(t, message, connector))
	if err != nil || wrong.Outcome != "HELD_FOR_REVIEW" || wrong.IncidentID == "" {
		t.Fatal("claiming an approved command hid an unrelated native change", err)
	}
}

func TestNativeDriftRejectsForgedBaselineAndWaitsForTheObservedSourceCut(t *testing.T) {
	sys, service, message, connector, _ := nativeDriftFixture(t, false)
	message.Before.ResourceVersion = "invented-baseline"
	if _, err := service.RecordKubernetesDrift(sys.ctx, sys.tenant, signedNativeDrift(t, message, connector)); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("uncommitted drift baseline trusted", err)
	}
	var effects int
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT (SELECT count(*) FROM ratchet.native_drift_receipts WHERE tenant_id=$1)+(SELECT count(*) FROM ratchet.events WHERE tenant_id=$1 AND stream_id LIKE 'incident:%')`, sys.tenant).Scan(&effects)
	}); err != nil || effects != 0 {
		t.Fatal("forged baseline committed evidence", err)
	}
	message.SourceRevision++
	if _, err := service.RecordKubernetesDrift(sys.ctx, sys.tenant, signedNativeDrift(t, message, connector)); !errors.Is(err, workflow.ErrDependency) {
		t.Fatal("source lag accepted as observed state", err)
	}
}
