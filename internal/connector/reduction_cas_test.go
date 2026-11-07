package connector_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

func TestReductionCallersRefuseChangedTargetContext(t *testing.T) {
	for _, kind := range []string{"drift", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			store, err := domain.NewStore("")
			if err != nil {
				t.Fatal(err)
			}
			target := httptest.NewServer(server.NewServer(store, "cas-token").Routes())
			defer target.Close()
			adapter := sim.NewAdapter(target.URL, "cas-token", "tenant-exchange-demo", "cas-source")
			watch, err := connector.NewWatchEngine(target.URL, adapter, "")
			if err != nil {
				t.Fatal(err)
			}
			timer, err := connector.NewTemporaryGrantManager(adapter, "")
			if err != nil {
				t.Fatal(err)
			}
			var alert string
			if kind == "drift" {
				if err = store.AssignRole("rogue", "user:rahul", "role:wallet-operator"); err != nil {
					t.Fatal(err)
				}
				alerts, err := watch.PollOnce(ctx)
				if err != nil || len(alerts) != 1 {
					t.Fatal(alerts, err)
				}
				alert = alerts[0].AlertID
			} else {
				if err = timer.ScheduleGrant(&connector.TemporaryGrantRecord{GrantID: "expire", TenantID: "tenant-exchange-demo", IdentityID: "user:rahul", RoleID: "role:finance-analyst", GrantedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
					t.Fatal(err)
				}
			}
			if err = store.AssignRole("unrelated writer", "user:rahul-assistant", "role:finance-analyst"); err != nil {
				t.Fatal(err)
			}
			before := store.GetState().Revision
			if kind == "drift" {
				if _, err = watch.RevertDrift(ctx, alert); err == nil {
					t.Fatal("stale drift correction executed")
				}
			} else {
				processed, err := timer.CheckAndRevokeExpired(ctx, time.Now())
				if err != nil || len(processed) != 1 || processed[0].Status != connector.GrantStatusFailed {
					t.Fatal("stale expiry was reported verified", processed, err)
				}
			}
			if store.GetState().Revision != before {
				t.Fatal("stale reduction changed target IAM")
			}
		})
	}
}
