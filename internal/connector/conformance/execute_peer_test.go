//go:build peerintegration

package conformance_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

func TestPeerExecuteVerifyAndRecoveryConformance(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "target.json")
	store, err := domain.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(simserver.NewServer(store, "conformance-token").Routes())
	defer server.Close()
	adapter := sim.NewAdapter(server.URL, "conformance-token", "tenant-exchange-demo", "source")
	base := store.GetState().Revision
	cmd := &connector.ExecCommand{CommandID: uuid.NewString(), TenantID: "tenant-exchange-demo", RequestID: uuid.NewString(), Action: "ASSIGN_ROLE", TargetIdentity: "user:rahul-assistant", ResourceOrRole: "role:finance-analyst", ExpectedTargetRevision: base}
	result, err := adapter.Execute(ctx, cmd)
	if err != nil || !result.Success {
		t.Fatalf("actual assign: %+v %v", result, err)
	}
	observed, err := adapter.Verify(ctx, cmd)
	if err != nil || !slices.Contains(observed.CurrentRoles, cmd.ResourceOrRole) {
		t.Fatal("actual independent readback", err)
	}
	t.Run("duplicate-command", func(t *testing.T) {
		before := store.GetState().Revision
		duplicate, err := adapter.Execute(ctx, cmd)
		if err != nil || !duplicate.Success || duplicate.TargetRevisionAfter != result.TargetRevisionAfter || store.GetState().Revision != before {
			t.Fatalf("duplicate did not reproduce original evidence: %+v %v", duplicate, err)
		}
	})
	t.Run("failed-precondition", func(t *testing.T) {
		// Isolate this adversarial write from the read-back and restart cases.
		isolated, err := domain.NewStore(filepath.Join(t.TempDir(), "stale-target.json"))
		if err != nil {
			t.Fatal(err)
		}
		target := httptest.NewServer(simserver.NewServer(isolated, "conformance-token").Routes())
		defer target.Close()
		writer := sim.NewAdapter(target.URL, "conformance-token", "tenant-exchange-demo", "source")
		before := isolated.GetState().Revision
		stale := *cmd
		stale.CommandID = uuid.NewString()
		stale.TargetIdentity = "user:rahul-assistant"
		stale.ResourceOrRole = "role:exchange-admin"
		stale.ExpectedTargetRevision = before - 1
		result, err := writer.Execute(ctx, &stale)
		if err == nil && result.Success {
			t.Error("stale target revision was applied")
		}
		if isolated.GetState().Revision != before {
			t.Error("failed precondition changed actual IAM")
		}
	})
	t.Run("mismatched-readback", func(t *testing.T) {
		wrong := *cmd
		wrong.ResourceOrRole = "role:exchange-admin"
		if _, err := adapter.Verify(ctx, &wrong); err == nil {
			t.Fatal("missing role accepted as verified")
		}
	})
	t.Run("restart-after-lost-ack", func(t *testing.T) {
		server.Close()
		restarted, err := domain.NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		next := httptest.NewServer(simserver.NewServer(restarted, "conformance-token").Routes())
		defer next.Close()
		reader := sim.NewAdapter(next.URL, "conformance-token", "tenant-exchange-demo", "source")
		state, err := reader.Verify(ctx, cmd)
		if err != nil || !slices.Contains(state.CurrentRoles, cmd.ResourceOrRole) {
			t.Fatal("recovery could not reconcile committed target state", err)
		}
	})
}
