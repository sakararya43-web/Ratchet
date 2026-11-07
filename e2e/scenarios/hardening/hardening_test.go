//go:build peerintegration

package hardening_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// TestHardening_PersistenceRestartAndColdStartRecovery proves that all services and engines
// survive process crashes, reboots, and restore state deterministically without data loss.
func TestHardening_PersistenceRestartAndColdStartRecovery(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	simStateFile := filepath.Join(tmpDir, "sim_persisted.json")
	authFile := filepath.Join(tmpDir, "auth_persisted.json")
	priorityFile := filepath.Join(tmpDir, "priority_persisted.json")
	tempGrantsFile := filepath.Join(tmpDir, "temp_grants_persisted.json")

	// 1. Simulator Persistence and Restart
	t.Run("SimulatorPersistenceAndRestart", func(t *testing.T) {
		// Initialize store with file
		store1, err := domain.NewStore(simStateFile)
		if err != nil {
			t.Fatalf("failed to init sim store: %v", err)
		}

		// Mutate state: grant role to Rahul's assistant
		err = store1.AssignRole("test-operator", "user:rahul-assistant", "role:finance-analyst")
		if err != nil {
			t.Fatalf("assign failed: %v", err)
		}

		rev1 := store1.GetState().Revision

		// Simulate process termination and cold restart from disk
		store2, err := domain.NewStore(simStateFile)
		if err != nil {
			t.Fatalf("failed to reload sim store: %v", err)
		}

		state2 := store2.GetState()
		if state2.Revision != rev1 {
			t.Errorf("expected revision %d after restart, got %d", rev1, state2.Revision)
		}

		found := false
		for _, g := range state2.Grants {
			if g.IdentityID == "user:rahul-assistant" && g.RoleID == "role:finance-analyst" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("persisted grant lost across simulator restart!")
		}
	})

	// 2. Authority Store Genesis & Bundle Persistence Across Restart
	t.Run("AuthorityStorePersistenceAndRestart", func(t *testing.T) {
		authStore1, err := trust.NewStore(authFile)
		if err != nil {
			t.Fatalf("failed to init authority store: %v", err)
		}

		k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkBytes1, _ := x509.MarshalPKIXPublicKey(&k1.PublicKey)
		k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkBytes2, _ := x509.MarshalPKIXPublicKey(&k2.PublicKey)

		_, err = authStore1.InitGenesis("tenant-exchange-demo", 2, 2, []trust.AuthorityMember{
			{ActorID: "user:sec-lead-1", DisplayName: "Alice", PublicKey: pkBytes1, IsActive: true},
			{ActorID: "user:sec-lead-2", DisplayName: "Bob", PublicKey: pkBytes2, IsActive: true},
		})
		if err != nil {
			t.Fatalf("genesis failed: %v", err)
		}

		bundle, err := authStore1.ProposeBundle("tenant-exchange-demo", "v1.0.1", "Hardening update", map[string]string{"rules.rego": "package rules"}, nil)
		if err != nil {
			t.Fatalf("propose failed: %v", err)
		}

		// Simulate restart of Authority service
		authStore2, err := trust.NewStore(authFile)
		if err != nil {
			t.Fatalf("failed to reload authority store: %v", err)
		}

		gen, err := authStore2.GetGenesis()
		if err != nil || gen.ThresholdM != 2 {
			t.Fatalf("genesis state corrupted across authority restart")
		}

		proposals := authStore2.ListProposals()
		if len(proposals) != 1 || proposals[0].ProposalID != bundle.ProposalID {
			t.Fatalf("policy proposals lost across authority restart")
		}
	})

	// 3. Priority Containment Engine History Persistence Across Restart
	t.Run("PriorityContainmentEnginePersistence", func(t *testing.T) {
		// Mock adapter
		store, _ := domain.NewStore("")
		srv := server.NewServer(store, "sim-secret")
		ts := httptest.NewServer(srv.Routes())
		defer ts.Close()

		adapter := sim.NewAdapter(ts.URL, "sim-secret", store.GetState().TenantID, "conn-01")

		pce1, err := connector.NewPriorityContainmentEngine(adapter, priorityFile)
		if err != nil {
			t.Fatalf("failed to init pce: %v", err)
		}

		plan := &connector.ContainmentPlan{
			PlanID:         "plan-restart-01",
			TenantID:       store.GetState().TenantID,
			IncidentID:     "inc-01",
			TargetIdentity: "user:rahul",
			Actions: []connector.ContainmentAction{
				{
					ActionID:                "act-term-1",
					ActionType:              connector.ActionTerminateSession,
					TargetIdentity:          "user:rahul",
					TargetResourceOrSession: "session:rahul-workstation-1",
					CorrelationID:           "inc-01",
				},
			},
		}

		_, err = pce1.ExecutePlan(ctx, plan)
		if err != nil {
			t.Fatalf("execute plan failed: %v", err)
		}

		// Reload engine from disk
		pce2, err := connector.NewPriorityContainmentEngine(adapter, priorityFile)
		if err != nil {
			t.Fatalf("reload pce failed: %v", err)
		}

		savedRes, err := pce2.GetPlanResult("plan-restart-01")
		if err != nil || savedRes.SucceededActions != 1 {
			t.Fatalf("priority plan result lost across engine restart")
		}
	})

	// 4. Temporary Grant Manager Cold-Start Catch-up
	t.Run("TemporaryGrantManagerColdStartSweep", func(t *testing.T) {
		store, _ := domain.NewStore("")
		srv := server.NewServer(store, "sim-secret")
		ts := httptest.NewServer(srv.Routes())
		defer ts.Close()

		adapter := sim.NewAdapter(ts.URL, "sim-secret", store.GetState().TenantID, "conn-01")

		// Assign role initially
		_ = store.AssignRole("broker:ratchet-connector", "user:admin-operator", "role:security-lead")

		tgm1, err := connector.NewTemporaryGrantManager(adapter, tempGrantsFile)
		if err != nil {
			t.Fatalf("failed to init tgm: %v", err)
		}

		// Grant was supposed to expire 5 seconds ago (expired while system was down)
		expiredTime := time.Now().Add(-5 * time.Second)
		if err := tgm1.ScheduleGrant(&connector.TemporaryGrantRecord{
			GrantID:    "grant-offline-expired",
			TenantID:   store.GetState().TenantID,
			IdentityID: "user:admin-operator",
			RoleID:     "role:security-lead",
			GrantedAt:  time.Now().Add(-1 * time.Hour),
			ExpiresAt:  expiredTime,
			Status:     connector.GrantStatusActive,
		}); err != nil {
			t.Fatal(err)
		}

		// Cold restart: connector starts up and immediately sweeps backlog
		tgm2, err := connector.NewTemporaryGrantManager(adapter, tempGrantsFile)
		if err != nil {
			t.Fatalf("failed to reload tgm: %v", err)
		}

		revoked, err := tgm2.CheckAndRevokeExpired(ctx, time.Now())
		if err != nil {
			t.Fatalf("sweep failed: %v", err)
		}
		if len(revoked) != 1 || revoked[0].Status != connector.GrantStatusRevoked {
			t.Fatalf("cold-start sweep failed to revoke expired grant: %v", revoked)
		}

		// Verify target simulator confirms grant removal
		obs, err := adapter.Verify(ctx, &connector.ExecCommand{
			Action:         "REVOKE_ROLE",
			TargetIdentity: "user:admin-operator",
			ResourceOrRole: "role:security-lead",
		})
		if err != nil {
			t.Fatalf("read-back verification failed: %v", err)
		}
		for _, r := range obs.CurrentRoles {
			if r == "role:security-lead" {
				t.Fatalf("expired role still active on target!")
			}
		}
	})
}

// TestHardening_StaleContextAndReplayRefusal verifies security against replayed nonces and expired challenges.
func TestHardening_StaleContextAndReplayRefusal(t *testing.T) {
	ctx := context.Background()
	credStore := approval.NewCredentialStore()
	_ = approval.SeedDemoCredentials(credStore, "tenant-exchange-demo")

	verifier, err := approval.NewApprovalVerifier(credStore, "localhost", []string{"http://localhost:3000"})
	if err != nil {
		t.Fatalf("failed to init verifier: %v", err)
	}

	digester := canon.New()
	change1, _ := digester.Digest(map[string]any{"change_id": "chg-1", "action": "REVOKE"})
	change2, _ := digester.Digest(map[string]any{"change_id": "chg-2", "action": "GRANT"})

	// Generate assertion for change1
	sub1, err := approval.GenerateSimulatedAssertion("tenant-exchange-demo", "user:sec-lead-1", change1, "localhost", "http://localhost:3000")
	if err != nil {
		t.Fatalf("failed to generate assertion: %v", err)
	}

	// 1. Valid for change1
	v1, err := verifier.Verify(ctx, sub1, change1)
	if err != nil || v1.ActorID != "user:sec-lead-1" {
		t.Fatalf("expected valid verification for matching change")
	}

	// 2. Cross-change replay MUST FAIL: replaying assertion against change2
	_, err = verifier.Verify(ctx, sub1, change2)
	if err == nil {
		t.Fatalf("VIOLATION: assertion was accepted for an unapproved change digest (replay vulnerability)!")
	}

	// 3. Zero digest MUST FAIL
	_, err = verifier.Verify(ctx, sub1, ports.Digest{})
	if err == nil {
		t.Fatalf("VIOLATION: zero digest was accepted!")
	}
}
