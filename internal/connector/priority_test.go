package connector_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

func TestPriorityContainmentEngineExecutionAndVerification(t *testing.T) {
	ctx := context.Background()

	// 1. Setup simulator with active Rahul session
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	brokerToken := "sim-broker-secret"
	srv := server.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	tenantID := "tenant-exchange-demo"
	adapter := sim.NewAdapter(ts.URL, brokerToken, tenantID, "connector-sim-01")

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "containment_state.json")

	engine, err := connector.NewPriorityContainmentEngine(adapter, statePath)
	if err != nil {
		t.Fatalf("failed to create priority containment engine: %v", err)
	}

	// 2. Setup cut plan for compromised Rahul: terminate session + revoke role
	plan := &connector.ContainmentPlan{
		PlanID:         "plan-contain-rahul-001",
		TenantID:       tenantID,
		IncidentID:     "inc-2026-11-001",
		TargetIdentity: "user:rahul",
		Actions: []connector.ContainmentAction{
			{
				ActionID:                "act-term-sess-001",
				ActionType:              connector.ActionTerminateSession,
				TargetIdentity:          "user:rahul",
				TargetResourceOrSession: "session:rahul-workstation-1",
				CorrelationID:           "corr-001",
			},
			{
				ActionID:                "act-rev-role-002",
				ActionType:              connector.ActionRevokeRole,
				TargetIdentity:          "user:rahul",
				TargetResourceOrSession: "role:finance-analyst",
				CorrelationID:           "corr-002",
			},
		},
		ConfirmedBy: "user:sec-lead-1",
		CreatedAt:   time.Now().UTC(),
	}

	// 3. Execute plan
	result, err := engine.ExecutePlan(ctx, plan)
	if err != nil {
		t.Fatalf("ExecutePlan failed: %v", err)
	}

	if result.TotalActions != 2 {
		t.Errorf("expected 2 total actions, got %d", result.TotalActions)
	}
	if result.SucceededActions != 2 {
		t.Errorf("expected 2 succeeded actions, got %d (failed: %d)", result.SucceededActions, result.FailedActions)
	}

	// 4. Test reload from persistence
	reloadedEngine, err := connector.NewPriorityContainmentEngine(adapter, statePath)
	if err != nil {
		t.Fatalf("failed to reload engine: %v", err)
	}

	reloadedRes, err := reloadedEngine.GetPlanResult(plan.PlanID)
	if err != nil {
		t.Fatalf("failed to fetch reloaded plan: %v", err)
	}
	if reloadedRes.PlanID != plan.PlanID {
		t.Errorf("expected plan ID %s, got %s", plan.PlanID, reloadedRes.PlanID)
	}

	// 5. Test rejection of non-reduction commands
	nonReductionPlan := &connector.ContainmentPlan{
		PlanID:         "plan-rogue-increase",
		TenantID:       tenantID,
		IncidentID:     "inc-fake",
		TargetIdentity: "user:rahul",
		Actions: []connector.ContainmentAction{
			{
				ActionID:                "act-rogue-assign",
				ActionType:              "ASSIGN_ROLE", // Forbidden increase!
				TargetIdentity:          "user:rahul",
				TargetResourceOrSession: "role:exchange-admin",
			},
		},
	}

	badRes, err := engine.ExecutePlan(ctx, nonReductionPlan)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}
	if badRes.FailedActions != 1 || badRes.SucceededActions != 0 {
		t.Errorf("expected non-reduction command to fail, got %d succeeded", badRes.SucceededActions)
	}
}
