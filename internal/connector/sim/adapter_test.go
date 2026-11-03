package sim_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

func TestSimulatorAdapterExecuteAndVerify(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	store, err := domain.NewStore(filepath.Join(tmpDir, "sim.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	brokerToken := "valid-broker-secret"
	srv := simserver.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	adapter := sim.NewAdapter(ts.URL, brokerToken, "tenant-exchange-demo", "connector-01")

	// 1. Execute an authorized role assignment: grant Rahul exchange-admin
	assignCmd := &connector.ExecCommand{
		CommandID:      "cmd-exec-001",
		TenantID:       "tenant-exchange-demo",
		RequestID:      "req-001",
		Action:         "ASSIGN_ROLE",
		TargetIdentity: "user:rahul",
		ResourceOrRole: "role:exchange-admin",
		IsReduction:    false,
	}

	execRes, err := adapter.Execute(ctx, assignCmd)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if !execRes.Success {
		t.Fatalf("execute was not successful: %s", execRes.ErrorMessage)
	}
	if execRes.TargetRevisionAfter != 1001 {
		t.Errorf("expected target revision 1001, got %d", execRes.TargetRevisionAfter)
	}

	// 2. Independently verify the grant via read-back
	observed, err := adapter.Verify(ctx, assignCmd)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	hasRole := false
	for _, r := range observed.CurrentRoles {
		if r == "role:exchange-admin" {
			hasRole = true
			break
		}
	}
	if !hasRole {
		t.Errorf("expected role:exchange-admin to be observed in read-back")
	}

	// 3. Test verification failure: verify a role that was NOT granted
	fakeCmd := &connector.ExecCommand{
		CommandID:      "cmd-fake",
		Action:         "ASSIGN_ROLE",
		TargetIdentity: "user:rahul",
		ResourceOrRole: "role:non-existent-role",
	}
	_, err = adapter.Verify(ctx, fakeCmd)
	if err == nil {
		t.Errorf("expected verification mismatch error for non-existent role, got nil")
	}

	// 4. Execute revocation: remove role:exchange-admin
	revokeCmd := &connector.ExecCommand{
		CommandID:      "cmd-exec-002",
		TenantID:       "tenant-exchange-demo",
		Action:         "REVOKE_ROLE",
		TargetIdentity: "user:rahul",
		ResourceOrRole: "role:exchange-admin",
		IsReduction:    true,
	}

	revokeRes, err := adapter.Execute(ctx, revokeCmd)
	if err != nil {
		t.Fatalf("revoke execute failed: %v", err)
	}
	if !revokeRes.Success {
		t.Fatalf("revoke was not successful: %s", revokeRes.ErrorMessage)
	}

	// 5. Verify revocation
	observedAfterRevoke, err := adapter.Verify(ctx, revokeCmd)
	if err != nil {
		t.Fatalf("verify after revoke failed: %v", err)
	}
	for _, r := range observedAfterRevoke.CurrentRoles {
		if r == "role:exchange-admin" {
			t.Errorf("expected role:exchange-admin to be absent after revocation")
		}
	}
}

