package sim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/conformance"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
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
		ExpectedTargetRevision: 1000,
		CommandID:              "cmd-exec-001",
		TenantID:               "tenant-exchange-demo",
		RequestID:              "req-001",
		Action:                 "ASSIGN_ROLE",
		TargetIdentity:         "user:rahul",
		ResourceOrRole:         "role:exchange-admin",
		IsReduction:            false,
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
		ExpectedTargetRevision: 1001,
		CommandID:              "cmd-exec-002",
		TenantID:               "tenant-exchange-demo",
		Action:                 "REVOKE_ROLE",
		TargetIdentity:         "user:rahul",
		ResourceOrRole:         "role:exchange-admin",
		IsReduction:            true,
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

func TestCompleteSnapshotStableAndRetainsActualRestriction(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "target.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(simserver.NewServer(store, "snapshot-test-token").Routes())
	defer server.Close()
	adapter := sim.NewAdapter(server.URL, "snapshot-test-token", "tenant-exchange-demo", "snapshot-source")
	first, err := adapter.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("same target revision changed durable message bytes")
	}
	command := &connector.ExecCommand{CommandID: "restrict", TenantID: "tenant-exchange-demo", Action: "RESTRICT_ACCOUNT", TargetIdentity: "user:rahul", ExpectedTargetRevision: first.SourceRevision}
	result, err := adapter.Execute(context.Background(), command)
	if err != nil || !result.Success {
		t.Fatal(result, err)
	}
	observed, err := adapter.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(observed)
	wire := new(v1.GraphSnapshot)
	if err = protojson.Unmarshal(raw, wire); err != nil {
		t.Fatal(err)
	}
	snapshot, err := conformance.Snapshot(wire)
	if err != nil {
		t.Fatal(err)
	}
	reach, err := snapshot.Reach("user:rahul")
	if err != nil || len(reach.Powers) != 0 {
		t.Fatal("restricted target retained access", reach, err)
	}
	found := false
	for _, node := range observed.Nodes {
		if node.ID == "session:rahul-workstation-1" {
			found = true
			if node.Properties["disabled"] != "true" {
				t.Fatal("actual session revocation lost")
			}
		}
	}
	if !found {
		t.Fatal("retained session omitted")
	}
}
