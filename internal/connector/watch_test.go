package connector_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

func TestWatchEngine_DriftDetectionAndRevert(t *testing.T) {
	ctx := context.Background()

	// 1. Setup simulator server
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}

	brokerToken := "sim-broker-secret"
	srv := server.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	adapter := sim.NewAdapter(ts.URL, brokerToken, "tenant-exchange-demo", "connector-watch-01")
	tmpDir := t.TempDir()
	cursorFile := filepath.Join(tmpDir, "watch_cursor.json")

	we, err := connector.NewWatchEngine(ts.URL, adapter, cursorFile)
	if err != nil {
		t.Fatalf("failed to create watch engine: %v", err)
	}

	// Initial poll: baseline state has no drift
	initialAlerts, err := we.PollOnce(ctx)
	if err != nil {
		t.Fatalf("initial poll failed: %v", err)
	}
	if len(initialAlerts) != 0 {
		t.Fatalf("expected 0 initial drift alerts, got %d", len(initialAlerts))
	}

	// 2. Inject Out-of-band Rogue Admin Drift into simulator directly
	injectReq, _ := json.Marshal(map[string]string{
		"actor_id":        "rogue-attacker:out-of-band",
		"target_identity": "user:rahul",
		"role_id":         "role:wallet-operator",
	})
	resp, err := http.Post(ts.URL+"/api/v1/test/inject-drift", "application/json", bytes.NewReader(injectReq))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("drift injection failed: %v (code %d)", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. Poll once via WatchEngine: Drift MUST be detected
	driftAlerts, err := we.PollOnce(ctx)
	if err != nil {
		t.Fatalf("poll failed: %v", err)
	}
	if len(driftAlerts) != 1 {
		t.Fatalf("expected 1 drift alert, got %d", len(driftAlerts))
	}

	alert := driftAlerts[0]
	if alert.ActorID != "rogue-attacker:out-of-band" {
		t.Errorf("expected rogue actor in alert, got %s", alert.ActorID)
	}
	if alert.TargetIdentity != "user:rahul" || alert.ResourceOrRole != "role:wallet-operator" {
		t.Errorf("unexpected drift target: %s / %s", alert.TargetIdentity, alert.ResourceOrRole)
	}
	if alert.Status != connector.DriftDetected {
		t.Errorf("expected status %s, got %s", connector.DriftDetected, alert.Status)
	}

	// 4. Authorized Revert & Independent Verification
	execRes, err := we.RevertDrift(ctx, alert.AlertID)
	if err != nil {
		t.Fatalf("revert drift failed: %v", err)
	}
	if !execRes.Success {
		t.Fatalf("revert execution was not successful: %v", execRes.ErrorMessage)
	}

	// 5. Verify Target IAM has been reverted (role:wallet-operator no longer present for Rahul)
	orgReq, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/org", nil)
	orgResp, err := http.DefaultClient.Do(orgReq)
	if err != nil {
		t.Fatalf("failed to fetch org: %v", err)
	}
	defer func() {
		if err := orgResp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if orgResp.StatusCode != http.StatusOK {
		t.Fatalf("org read-back status: %d", orgResp.StatusCode)
	}

	var org domain.OrgState
	if err := json.NewDecoder(orgResp.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}

	for _, g := range org.Grants {
		if g.IdentityID == "user:rahul" && g.RoleID == "role:wallet-operator" {
			t.Fatalf("VIOLATION: rogue grant still present after corrective revert!")
		}
	}

	// Verify alert status updated
	alerts := we.GetAlerts()
	if len(alerts) != 1 || alerts[0].Status != connector.DriftReverted {
		t.Fatalf("expected alert status to be REVERTED, got %v", alerts)
	}
}

func TestTemporaryGrantManager_ScheduleAndRevoke(t *testing.T) {
	ctx := context.Background()

	// Setup simulator
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}

	brokerToken := "sim-broker-secret"
	srv := server.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	adapter := sim.NewAdapter(ts.URL, brokerToken, "tenant-exchange-demo", "connector-temp-01")

	// Initially grant temporary role to Rahul's assistant
	grantCmd := &connector.ExecCommand{
		ExpectedTargetRevision: store.GetState().Revision,
		CommandID:              "grant-intern-temp-01",
		TenantID:               "tenant-exchange-demo",
		Action:                 "ASSIGN_ROLE",
		TargetIdentity:         "user:rahul-assistant",
		ResourceOrRole:         "role:finance-analyst",
		IsReduction:            false,
	}
	_, err = adapter.Execute(ctx, grantCmd)
	if err != nil {
		t.Fatalf("initial temporary grant failed: %v", err)
	}

	tmpDir := t.TempDir()
	grantsFile := filepath.Join(tmpDir, "temp_grants.json")

	tgm, err := connector.NewTemporaryGrantManager(adapter, grantsFile)
	if err != nil {
		t.Fatalf("failed to init temporary grant manager: %v", err)
	}

	// Schedule grant with 100ms TTL
	expiry := time.Now().Add(100 * time.Millisecond)
	tempRecord := &connector.TemporaryGrantRecord{
		GrantID:    "tgrant-intern-100",
		TenantID:   "tenant-exchange-demo",
		IdentityID: "user:rahul-assistant",
		RoleID:     "role:finance-analyst",
		GrantedAt:  time.Now().UTC(),
		ExpiresAt:  expiry,
		Status:     connector.GrantStatusActive,
	}

	if err := tgm.ScheduleGrant(tempRecord); err != nil {
		t.Fatalf("failed to schedule grant: %v", err)
	}

	// Check immediately before expiry: no revocation
	revoked, err := tgm.CheckAndRevokeExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked grants before expiry, got %d", len(revoked))
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Check after expiry: MUST execute revocation and read-back verify
	revokedAfter, err := tgm.CheckAndRevokeExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("check after expiry failed: %v", err)
	}
	if len(revokedAfter) != 1 {
		t.Fatalf("expected 1 revoked grant after expiry, got %d", len(revokedAfter))
	}

	if revokedAfter[0].Status != connector.GrantStatusRevoked {
		t.Errorf("expected status %s, got %s", connector.GrantStatusRevoked, revokedAfter[0].Status)
	}

	// Verify target simulator has actually removed the grant
	orgReq, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/org", nil)
	orgResp, err := http.DefaultClient.Do(orgReq)
	if err != nil {
		t.Fatalf("failed to fetch org: %v", err)
	}
	defer func() {
		if err := orgResp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if orgResp.StatusCode != http.StatusOK {
		t.Fatalf("org read-back status: %d", orgResp.StatusCode)
	}

	var org domain.OrgState
	if err := json.NewDecoder(orgResp.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}

	for _, g := range org.Grants {
		if g.IdentityID == "user:rahul-assistant" && g.RoleID == "role:finance-analyst" {
			t.Fatalf("VIOLATION: expired temporary grant still active in target after revocation!")
		}
	}
}
