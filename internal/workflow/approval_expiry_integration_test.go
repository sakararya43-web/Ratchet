//go:build integration

package workflow_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestApprovalExpirySurvivesWorkerReplacementAndIgnoresObsoleteTimers(t *testing.T) {
	sys := setup(t)
	newService := func() *workflow.Service {
		t.Helper()
		s, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant}, workflow.Config{ApprovalLifetime: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := newService()
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	c, err := s.Submit(sys.ctx, actor, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: actor.ID, Access: "role:finance"}, Justification: "An independently approved time limited assessment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c = waitState(t, sys, c.ID, domain.AwaitingApproval)
	old := workflow.ApprovalExpiryArgs{Tenant: sys.tenant, Request: c.ID, Digest: c.Digest, Expires: c.Envelope.ExpiresAt}
	if !c.Envelope.ExpiresAt.Equal(c.UpdatedAt.Add(time.Second)) {
		t.Fatal("expiry did not use configured duration and transaction time")
	}
	if err := s.ExpireApproval(sys.ctx, old); err == nil {
		t.Fatal("early job did not request rescheduling")
	}
	if got, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID); err != nil || got.State != domain.AwaitingApproval {
		t.Fatal("early job changed request", err)
	}
	// Replace the approval envelope while its old scheduled timer remains durable.
	if err := s.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c = waitState(t, sys, c.ID, domain.AwaitingApproval)
	if c.Digest == old.Digest {
		t.Fatal("reassessment did not replace envelope")
	}
	if err := s.ExpireApproval(sys.ctx, old); err != nil {
		t.Fatal("obsolete timer should be harmless", err)
	}
	var timers int
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet_jobs.river_job WHERE kind='ratchet_approval_expiry_v1' AND args->>'tenant_id'=$1`, sys.tenant).Scan(&timers)
	}); err != nil || timers != 2 {
		t.Fatal("assessment and timer were not committed together", timers, err)
	}
	// No worker was running. Start a completely new service after the deadline.
	for time.Now().Before(c.Envelope.ExpiresAt.Add(100 * time.Millisecond)) {
		time.Sleep(20 * time.Millisecond)
	}
	replacement := newService()
	start(t, replacement, sys.ctx)
	expired := waitState(t, sys, c.ID, domain.Expired)
	if expired.UpdatedAt.Before(c.Envelope.ExpiresAt) || len(expired.Approvals) != 0 {
		t.Fatal("invalid expiry evidence")
	}
	if err := replacement.ExpireApproval(sys.ctx, workflow.ApprovalExpiryArgs{Tenant: sys.tenant, Request: c.ID, Digest: c.Digest, Expires: c.Envelope.ExpiresAt}); err != nil {
		t.Fatal("expiry retry", err)
	}
}
