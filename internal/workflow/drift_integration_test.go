//go:build integration

package workflow_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func signedDrift(t *testing.T, message *v1.SignedDriftReport, key ed25519.PrivateKey) []byte {
	t.Helper()
	digest, err := workflow.DriftSigningDigest(message)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature = ed25519.Sign(key, digest[:])
	raw, err := protojson.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func report(t *testing.T, tenant, action, role string, revision int64) *v1.SignedDriftReport {
	t.Helper()
	corr := uuid.NewString()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	return &v1.SignedDriftReport{Report: &v1.DriftReport{DriftId: uuid.NewString(), TenantId: tenant, ConnectorId: "source", ObservedRevision: revision, DetectedAt: at, Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: tenant, ConnectorId: "source", MessageId: uuid.NewString(), CorrelationId: corr, SourceRevision: revision}, UnapprovedOperation: &v1.AuditEvent{EventId: uuid.NewString(), TenantId: tenant, ActorId: "opaque:external", Action: action, Target: "user:requester", Timestamp: at, CorrelationId: corr, Details: map[string]string{"resource_or_role": role, "private_note": "PRIVATE observation person@example.com"}}}}
}
func driftSystem(t *testing.T, protected bool) (system, *workflow.Service, ed25519.PrivateKey, graph.Data) {
	t.Helper()
	sys := setup(t)
	base, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := base.Data()
	props := map[string]string{}
	if protected {
		props["protected"] = "true"
	}
	data.Edges = append(data.Edges, graph.Edge{ID: "unauthorized-admin", Source: "user:requester", Target: "role:admin", Kind: "ASSIGNED", Properties: props}, graph.Edge{ID: "legitimate-finance", Source: "user:requester", Target: "role:finance", Kind: "ASSIGNED"})
	replaceGraph(t, sys, data)
	execution, key := signCapability(t, sys.tenant, false, true)
	s, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant}, workflow.Config{DriftResponders: map[string]string{sys.tenant: "user:sec1"}}, execution)
	if err != nil {
		t.Fatal(err)
	}
	return sys, s, key, data
}

func TestAuthenticatedDriftDeduplicatesStagesOnlyReductionAndVerifiesAfterGraphRecovery(t *testing.T) {
	sys, s, signer, data := driftSystem(t, false)
	start(t, s, sys.ctx)
	message := report(t, sys.tenant, "ASSIGN_ROLE", "role:admin", 11)
	raw := signedDrift(t, message, signer)
	// Concurrent delivery through the actual durable transaction boundary.
	var wg sync.WaitGroup
	receipts := make(chan workflow.DriftReceipt, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() { r, err := s.RecordDrift(sys.ctx, sys.tenant, raw); receipts <- r; failures <- err })
	}
	wg.Wait()
	close(receipts)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var receipt workflow.DriftReceipt
	for r := range receipts {
		if r.Outcome != "CORRECTIVE_COMMAND_STAGED" || r.ReductionDigest.IsZero() {
			t.Fatal("safe drift correction missing", r)
		}
		if receipt.IncidentID != "" && receipt.IncidentID != r.IncidentID {
			t.Fatal("duplicate incident")
		}
		receipt = r
	}
	changedID := message.Report.DriftId
	message.Report.DriftId = uuid.NewString()
	message.Report.Envelope.MessageId = uuid.NewString()
	duplicate, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, signer))
	if err != nil || duplicate.IncidentID != receipt.IncidentID {
		t.Fatal("redelivered audit operation duplicated incident", err)
	}
	message.Report.DriftId = changedID
	message.Report.UnapprovedOperation.Details["resource_or_role"] = "role:finance"
	if _, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, signer)); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("observation ID reused with another operation", err)
	}
	c := waitState(t, sys, receipt.RequestID, domain.Executing)
	var command workflow.PreparedCommand
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		var raw []byte
		if err := tx.QueryRow(sys.ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, sys.tenant, c.ExecutionID).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &command)
	}); err != nil {
		t.Fatal(err)
	}
	if command.Purpose != "DRIFT_REDUCTION" || command.ReductionDigest != receipt.ReductionDigest || command.ExpectedRevision != 11 || len(command.ExpectedRoles) != 1 || command.ExpectedRoles[0] != "role:finance" || len(command.Approvals) != 0 {
		t.Fatal("corrector exceeded proved reduction", command)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	before, err := s.GetIncident(sys.ctx, actor, receipt.IncidentID)
	if err != nil || before.VerifiedCorrection != nil || before.Incident.Status != "CONTAINING" {
		t.Fatal("staged correction invented success", err)
	}
	r := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "source", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: true, ReadBackVerified: true, ObservedTenant: sys.tenant, ObservedTarget: c.Intent.Target, ObservedRoles: []string{"role:finance"}, ObservedRevision: 12, AppliedAt: c.UpdatedAt.Add(time.Microsecond), ObservedAt: time.Now().UTC()}
	observationDigest(t, &r)
	if err := s.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, r, signer)); err != nil {
		t.Fatal(err)
	}
	verified, err := s.GetIncident(sys.ctx, actor, receipt.IncidentID)
	if err != nil || verified.VerifiedCorrection == nil || verified.Incident.Status != "CONTAINING" || verified.Incident.CorrectiveVerifiedAt.IsZero() {
		t.Fatal("read-back evidence missing or stale graph claimed contained", err)
	}
	data.Edges = append([]graph.Edge(nil), data.Edges...)
	kept := []graph.Edge{}
	for _, edge := range data.Edges {
		if edge.ID != "unauthorized-admin" {
			kept = append(kept, edge)
		}
	}
	data.Edges = kept
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{8}).String(), FromRevision: 11, ToRevision: 12, Snapshot: &data, Complete: true}, sys.key); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileDriftIncident(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 5, Operation: "incident"}); err != nil {
		t.Fatal(err)
	}
	contained, err := s.GetIncident(sys.ctx, actor, receipt.IncidentID)
	if err != nil || contained.Incident.Status != "CONTAINED" || len(contained.Observed.Routes) != 0 || contained.Incident.ContainedAt.IsZero() {
		t.Fatal("actual graph proof did not finish incident", err)
	}
	diagnostics, err := s.InvestigatorDiagnostics(sys.ctx, actor)
	if err != nil || diagnostics.VerifiedContainmentSamples != 1 || diagnostics.VerifiedContainmentTotalSeconds <= 0 {
		t.Fatal("verified containment duration absent", diagnostics, err)
	}
	// The connector's own corrective audit observation must not start a loop.
	corrected := report(t, sys.tenant, "REVOKE_ROLE", "role:admin", 12)
	corrected.Report.Envelope.CommandId = c.ExecutionID
	corrected.Report.Envelope.CorrelationId = c.CorrelationID
	corrected.Report.UnapprovedOperation.CorrelationId = c.CorrelationID
	correlated, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, corrected, signer))
	if err != nil || correlated.Outcome != "CORRELATED_APPROVED_COMMAND" || correlated.IncidentID != "" {
		t.Fatal("corrective observation caused reversal loop", err)
	}
	page, err := s.ListIncidents(sys.ctx, actor, "", 0, 0, 20)
	if err != nil || len(page.Incidents) != 1 {
		t.Fatal("drift duplicated incidents", err)
	}
	restore, err := s.Submit(sys.ctx, actor, workflow.Submit{CommandID: uuid.New(), Justification: "Restore only after independent incident review and fresh passkeys", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:admin", IncidentID: receipt.IncidentID}})
	if err != nil {
		t.Fatal(err)
	}
	assessed := waitState(t, sys, restore.ID, domain.AwaitingApproval)
	if assessed.Decision.Quorum != 2 || len(assessed.Approvals) != 0 || assessed.SourceDrift != "" {
		t.Fatal("drift restoration bypassed independent review")
	}
}

func TestDriftUnsafeAndProtectedReversalsStayInReview(t *testing.T) {
	for _, protected := range []bool{false, true} {
		sys, s, key, _ := driftSystem(t, protected)
		action := "REVOKE_ROLE"
		if protected {
			action = "ASSIGN_ROLE"
		}
		message := report(t, sys.tenant, action, "role:admin", 11)
		r, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, key))
		if err != nil || r.Outcome != "HELD_FOR_REVIEW" || r.RequestID != "" || r.IncidentID == "" {
			t.Fatal("unsafe/protected change auto-reverted", r, err)
		}
		message.Signature[0] ^= 1
		raw, err := protojson.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RecordDrift(sys.ctx, sys.tenant, raw); !errors.Is(err, workflow.ErrPermission) {
			t.Fatal("forged observation accepted", err)
		}
	}
}

func TestRealJetStreamDriftConsumerCommitsBeforeAcknowledging(t *testing.T) {
	sys, s, key, _ := driftSystem(t, false)
	url := os.Getenv("RATCHET_NATS_URL")
	if url == "" {
		url = "nats://127.0.0.1:54222"
	}
	b, err := bus.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(sys.ctx)
	defer cancel()
	done := make(chan error, 1)
	committed := make(chan workflow.DriftReceipt, 2)
	go func() {
		done <- b.ConsumeDrift(ctx, sys.tenant, func(ctx context.Context, raw []byte) error {
			r, err := s.RecordDrift(ctx, sys.tenant, raw)
			if err == nil {
				committed <- r
			}
			return err
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	message := report(t, sys.tenant, "ASSIGN_ROLE", "role:admin", 11)
	if err := b.Publish(sys.ctx, "ratchet."+sys.tenant+".drift.reports", message.Report.Envelope.MessageId, signedDrift(t, message, key)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-committed:
		if r.RequestID == "" {
			t.Fatal("consumer acknowledged without effect")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real drift delivery lost")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("consumer did not stop")
	}
}

func TestApprovedCommandReadbackDelayDoesNotCreateDriftAndCorrelationCannotHideAnotherWrite(t *testing.T) {
	sys, s, c, key, _ := readyExecution(t)
	base, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := base.Data()
	data.Edges = append(data.Edges, graph.Edge{ID: "approved-finance", Source: c.Intent.Target, Target: c.Intent.Access, Kind: "ASSIGNED"})
	replaceGraph(t, sys, data)
	message := report(t, sys.tenant, "ASSIGN_ROLE", c.Intent.Access, 11)
	message.Report.Envelope.CommandId = c.ExecutionID
	message.Report.Envelope.CorrelationId = c.CorrelationID
	message.Report.UnapprovedOperation.CorrelationId = c.CorrelationID
	r, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, key))
	if err != nil || r.Outcome != "CORRELATED_APPROVED_COMMAND" || r.IncidentID != "" {
		t.Fatal("normal read-back delay became an incident", r, err)
	}
	if got, _ := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID); got.State != domain.Executing {
		t.Fatal("audit correlation invented independent verification")
	}
	message = report(t, sys.tenant, "ASSIGN_ROLE", "role:admin", 12)
	message.Report.Envelope.CommandId = c.ExecutionID
	message.Report.Envelope.CorrelationId = c.CorrelationID
	message.Report.UnapprovedOperation.CorrelationId = c.CorrelationID
	if _, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, key)); !errors.Is(err, workflow.ErrDependency) {
		t.Fatal("drift processed before observed graph caught up", err)
	}
	data.Edges = append(data.Edges, graph.Edge{ID: "unapproved-admin", Source: c.Intent.Target, Target: "role:admin", Kind: "ASSIGNED"})
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{8}).String(), FromRevision: 11, ToRevision: 12, Snapshot: &data, Complete: true}, sys.key); err != nil {
		t.Fatal(err)
	}
	r, err = s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, key))
	if err != nil || r.Outcome != "HELD_FOR_REVIEW" || r.IncidentID == "" || r.RequestID != "" {
		t.Fatal("old capability or copied correlation authorized a correction", r, err)
	}
}

func TestDriftTransactionRollsBackCorrectorIncidentAndJobIfEvidenceWriteFails(t *testing.T) {
	sys, s, key, _ := driftSystem(t, false)
	message := report(t, sys.tenant, "ASSIGN_ROLE", "role:admin", 11)
	privateID := uuid.NewSHA1(uuid.MustParse(message.Report.UnapprovedOperation.EventId), []byte("drift-private"))
	private, err := eventstore.SealPrivate(sys.key, sys.tenant, privateID, "workflow-v1", []byte("existing independently retained private record"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sys.store.Append(sys.ctx, eventstore.Command{TenantID: sys.tenant, ID: uuid.New(), ActorReference: uuid.New(), StreamID: "test:evidence-collision", Events: []eventstore.Event{{Type: "TestEvidenceCollision", Facts: json.RawMessage(`{}`), Private: &private}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, message, key)); err == nil {
		t.Fatal("injected evidence uniqueness failure did not occur")
	}
	var effects, jobs int
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT (SELECT count(*) FROM ratchet.execution_attempts WHERE tenant_id=$1)+(SELECT count(*) FROM ratchet.drift_receipts WHERE tenant_id=$1)+(SELECT count(*) FROM ratchet.change_projection WHERE tenant_id=$1)+(SELECT count(*) FROM ratchet.events WHERE tenant_id=$1 AND stream_id LIKE 'incident:%')`, sys.tenant).Scan(&effects)
	}); err != nil {
		t.Fatal(err)
	}
	if err := sys.pool.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet_jobs.river_job WHERE args->>'tenant_id'=$1`, sys.tenant).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if effects != 0 || jobs != 0 {
		t.Fatal("failed drift evidence left partial authority", effects, jobs)
	}
}

func TestDriftCannotAutomateAfterSourceSecurityEvidenceIsErased(t *testing.T) {
	sys, s, key, _ := driftSystem(t, true)
	var id uuid.UUID
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT private_record_id FROM ratchet.graph_sources WHERE tenant_id=$1 AND connector_id='source'`, sys.tenant).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	if err := sys.store.DeletePrivateRecord(sys.ctx, sys.tenant, id); err != nil {
		t.Fatal(err)
	}
	r, err := s.RecordDrift(sys.ctx, sys.tenant, signedDrift(t, report(t, sys.tenant, "ASSIGN_ROLE", "role:admin", 11), key))
	if err != nil || r.Outcome != "HELD_FOR_REVIEW" || r.RequestID != "" {
		t.Fatal("erasure converted protected access into an automatic reduction", r, err)
	}
}
