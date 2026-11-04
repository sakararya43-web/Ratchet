//go:build integration

package workflow_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestDurableContainmentPlanningIsAuthorizedIdempotentAndNeverExecutes(t *testing.T) {
	sys := setup(t)
	snapshot, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := snapshot.Data()
	data.Edges = append(data.Edges, graph.Edge{Source: "user:requester", Target: "role:finance", Kind: "ASSIGNED"}, graph.Edge{Source: "user:requester", Target: "role:admin", Kind: "ASSIGNED"})
	replaceGraph(t, sys, data)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	input := workflow.PlanInput{CommandID: uuid.New(), CorrelationID: uuid.NewString(), Identity: "user:requester", Costs: map[string]int64{"ROLE_REVOKE": 1, "RESTRICT_ACCOUNT": 100}}
	if _, err := service.PlanContainment(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, input); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("unauthorized plan access", err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	var wg sync.WaitGroup
	plans := make(chan workflow.ContainmentProposal, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plan, err := service.PlanContainment(sys.ctx, actor, input)
			if err != nil {
				t.Error(err)
				return
			}
			plans <- plan
		}()
	}
	wg.Wait()
	close(plans)
	var plan workflow.ContainmentProposal
	for proposal := range plans {
		if plan.Body.ID != "" && (plan.Body.ID != proposal.Body.ID || plan.Digest != proposal.Digest) {
			t.Fatal("parallel planning forked its receipt")
		}
		plan = proposal
	}
	if plan.Body.ID == "" || plan.Body.Plan.Cost != 1 || !plan.Body.Plan.MinimumProved || len(plan.Body.Plan.Actions) != 1 || plan.Body.Plan.Actions[0].Access != "role:admin" {
		t.Fatal("incorrect containment", plan)
	}
	digest, err := canon.New().Digest(plan.Body)
	if err != nil || digest != plan.Digest {
		t.Fatal("plan evidence not bound", err)
	}
	changed := input
	changed.Identity = "user:owner"
	if _, err := service.PlanContainment(sys.ctx, actor, changed); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("plan command changed its meaning", err)
	}
	events, err := sys.store.LoadStream(sys.ctx, sys.tenant, "containment:"+plan.Body.ID)
	if err != nil || len(events) != 1 || events[0].Type != "ContainmentPlanned" {
		t.Fatal("planning evidence duplicated", err)
	}
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		var count int
		if err := tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.execution_attempts WHERE tenant_id=$1`, sys.tenant).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("planning staged execution")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	reach, err := current.Reach("user:requester")
	if err != nil || reach.ByTier[0] != 1 || reach.ByTier[2] != 1 {
		t.Fatal("planning changed live graph", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
}
