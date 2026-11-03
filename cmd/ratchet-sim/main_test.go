package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
)

func TestSimulatorHTTPServer(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := domain.NewStore(filepath.Join(tmpDir, "test_sim.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	brokerSecret := "test-secret-token"
	server := NewServer(store, brokerSecret)
	handler := server.Routes()

	// 1. Test /healthz
	reqHealth := httptest.NewRequest("GET", "/healthz", nil)
	recHealth := httptest.NewRecorder()
	handler.ServeHTTP(recHealth, reqHealth)

	if recHealth.Code != http.StatusOK {
		t.Errorf("healthz status %d, expected 200", recHealth.Code)
	}

	// 2. Test /api/v1/org
	reqOrg := httptest.NewRequest("GET", "/api/v1/org", nil)
	recOrg := httptest.NewRecorder()
	handler.ServeHTTP(recOrg, reqOrg)

	if recOrg.Code != http.StatusOK {
		t.Errorf("org status %d, expected 200", recOrg.Code)
	}

	var org domain.OrgState
	if err := json.Unmarshal(recOrg.Body.Bytes(), &org); err != nil {
		t.Fatalf("failed to parse org response: %v", err)
	}
	if org.TenantID != "tenant-exchange-demo" {
		t.Errorf("unexpected tenant: %s", org.TenantID)
	}

	// 3. Test Broker Mode: unauthorized execute
	execBody := []byte(`{"command_id":"cmd-1","action":"ASSIGN_ROLE","target_identity":"user:rahul","resource_or_role":"role:exchange-admin"}`)
	reqExecNoAuth := httptest.NewRequest("POST", "/api/v1/execute", bytes.NewReader(execBody))
	recExecNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(recExecNoAuth, reqExecNoAuth)

	if recExecNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without bearer token, got %d", recExecNoAuth.Code)
	}

	// 4. Test Broker Mode: authorized execute
	reqExecAuth := httptest.NewRequest("POST", "/api/v1/execute", bytes.NewReader(execBody))
	reqExecAuth.Header.Set("Authorization", "Bearer "+brokerSecret)
	recExecAuth := httptest.NewRecorder()
	handler.ServeHTTP(recExecAuth, reqExecAuth)

	if recExecAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK with broker token, got %d (body: %s)", recExecAuth.Code, recExecAuth.Body.String())
	}

	var execResult map[string]any
	if err := json.Unmarshal(recExecAuth.Body.Bytes(), &execResult); err != nil {
		t.Fatalf("failed to parse execute response: %v", err)
	}
	if execResult["success"] != true {
		t.Errorf("expected success true in execute response")
	}

	// 5. Test Audit Log has recorded the broker execution
	reqAudit := httptest.NewRequest("GET", "/api/v1/audit", nil)
	recAudit := httptest.NewRecorder()
	handler.ServeHTTP(recAudit, reqAudit)

	var auditEntries []domain.TargetAuditEntry
	if err := json.Unmarshal(recAudit.Body.Bytes(), &auditEntries); err != nil {
		t.Fatalf("failed to parse audit log: %v", err)
	}
	if len(auditEntries) < 2 {
		t.Errorf("expected at least 2 audit entries, got %d", len(auditEntries))
	}

	// 6. Test Reset to Seed
	reqReset := httptest.NewRequest("POST", "/api/v1/reset", nil)
	recReset := httptest.NewRecorder()
	handler.ServeHTTP(recReset, reqReset)

	if recReset.Code != http.StatusOK {
		t.Errorf("expected 200 for reset, got %d", recReset.Code)
	}

	stateAfterReset := store.GetState()
	if stateAfterReset.Revision != 1000 {
		t.Errorf("expected revision 1000 after reset, got %d", stateAfterReset.Revision)
	}
}
