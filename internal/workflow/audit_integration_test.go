//go:build integration

package workflow_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestAuditProjectionRebuildTamperDetectionAndPrivateErasure(t *testing.T) {
	sys := setup(t)
	incident := uuid.NewString()
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", IncidentID: incident}, Justification: "Private audit retention regression explanation"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	start, endTime := c.CreatedAt.Add(-time.Second), c.CreatedAt.Add(time.Minute)
	actorRef := uuid.NewSHA1(uuid.NameSpaceOID, []byte(sys.tenant+":user:requester")).String()
	byActor, _, err := service.QueryAudit(sys.ctx, actor, eventstore.AuditFilter{Actor: actorRef, Request: c.ID, Start: &start, End: &endTime}, 0, 0, 100)
	if err != nil || len(byActor) != 1 || byActor[0].Event.Type != "ChangeSubmitted" {
		t.Fatal("actor/time filters", err)
	}
	byIncident, _, err := service.QueryAudit(sys.ctx, actor, eventstore.AuditFilter{Incident: incident}, 0, 0, 100)
	if err != nil || len(byIncident) != 3 {
		t.Fatal("incident filter", err)
	}
	filter := eventstore.AuditFilter{Request: c.ID, Resource: "reports"}
	before, end, err := service.QueryAudit(sys.ctx, actor, filter, 0, 0, 100)
	if err != nil || len(before) != 2 {
		t.Fatal("request/resource audit projection", len(before), err)
	}
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		_, err := tx.Exec(sys.ctx, `UPDATE ratchet.audit_projection SET display=jsonb_set(display,'{state}','"FORGED"') WHERE tenant_id=$1 AND sequence=$2`, sys.tenant, before[0].Event.Sequence)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.QueryAudit(sys.ctx, actor, filter, 0, 0, 100); !errors.Is(err, eventstore.ErrIntegrity) {
		t.Fatal("forged display accepted", err)
	}
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		_, err := tx.Exec(sys.ctx, `DELETE FROM ratchet.audit_projection WHERE tenant_id=$1`, sys.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := sys.store.DeletePrivateRecord(sys.ctx, sys.tenant, uuid.MustParse(c.PrivateReference)); err != nil {
		t.Fatal(err)
	}
	after, rebuiltEnd, err := service.QueryAudit(sys.ctx, actor, filter, 0, 0, 100)
	if err != nil || rebuiltEnd != end || len(after) != len(before) {
		t.Fatal("projection rebuild failed after erasure", err)
	}
	for i := range before {
		if string(before[i].Display) != string(after[i].Display) || before[i].Event.Entry.Hash != after[i].Event.Entry.Hash {
			t.Fatal("rebuild changed verified display/history")
		}
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal("private erasure changed chain", err)
	}
}
