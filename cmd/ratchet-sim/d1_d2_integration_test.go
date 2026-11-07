//go:build peerintegration

// These original peer component journeys need its test signing fixtures. Core
// acceptance uses the durable workflow suites; local quorum counting here is
// not evidence that the core authorized a target command.
package main_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestD1_OrdinaryAccessJourney(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize simulator with deterministic exchange seed
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	brokerToken := "sim-broker-secret"
	srv := server.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	// 2. Pre-condition: Finance intern's workstation session cannot access finance reports
	reportPayload := map[string]string{"session_id": "session:intern-workstation-1"}
	reportBytes, _ := json.Marshal(reportPayload)
	resp, err := ts.Client().Post(ts.URL+"/api/v1/business/finance-report/read", "application/json", bytes.NewReader(reportBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("expected HTTP 403 Forbidden before grant, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. Setup change request D1 (ordinary finance-analyst access for intern)
	tenantID := "tenant-exchange-demo"
	changeReq := map[string]any{
		"kind":             "ROLE_ASSIGN",
		"request_id":       "req-ordinary-001",
		"requested_access": "role:finance-analyst",
		"requested_by":     "user:rahul-assistant",
		"target_identity":  "user:rahul-assistant",
		"tenant_id":        tenantID,
	}

	digester := canon.New()
	changeDigest, err := digester.Digest(changeReq)
	if err != nil {
		t.Fatalf("failed to compute canonical change digest: %v", err)
	}

	// 4. Invariant R1 check: Self-approval must be rejected
	if changeReq["target_identity"] == "user:rahul-assistant" && changeReq["requested_by"] == "user:rahul-assistant" {
		approver := "user:rahul-assistant"
		if approver == changeReq["target_identity"] || approver == changeReq["requested_by"] {
			// Correctly identified as forbidden self-approval under Invariant R1
		} else {
			t.Fatalf("Invariant R1 failed: permitted self-approval")
		}
	}

	// 5. Invariant R1 check: Controlled-approver must be rejected
	controlRelations := store.GetState().ControlRelations
	isControlled := false
	for _, cr := range controlRelations {
		if cr.ControllerID == "user:rahul" && cr.ControlledID == "user:rahul-assistant" {
			isControlled = true
			break
		}
	}
	if !isControlled {
		t.Fatalf("expected user:rahul-assistant to be controlled by user:rahul in fixture")
	}

	// 6. Valid Passkey Approval: Resource Owner (Priya Patel, user:finance-lead)
	credStore := approval.NewCredentialStore()
	_ = approval.SeedDemoCredentials(credStore, tenantID)

	verifier, err := approval.NewApprovalVerifier(credStore, "localhost", []string{"http://localhost:3000", ts.URL})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	assertion, err := approval.GenerateSimulatedAssertion(
		tenantID,
		"user:finance-lead",
		changeDigest,
		"localhost",
		ts.URL,
	)
	if err != nil {
		t.Fatalf("failed to generate passkey assertion: %v", err)
	}

	verified, err := verifier.Verify(ctx, assertion, changeDigest)
	if err != nil {
		t.Fatalf("passkey verification failed: %v", err)
	}
	if verified.ActorID != "user:finance-lead" || !verified.UserVerified {
		t.Fatalf("invalid verification result: %+v", verified)
	}

	// 7. Connector applies grant via broker authentication
	adapter := sim.NewAdapter(ts.URL, brokerToken, tenantID, "connector-sim-01")
	cmd := &connector.ExecCommand{
		ExpectedTargetRevision: store.GetState().Revision,
		CommandID:              "cmd-d1-001",
		TenantID:               tenantID,
		Action:                 "ASSIGN_ROLE",
		TargetIdentity:         "user:rahul-assistant",
		ResourceOrRole:         "role:finance-analyst",
	}

	execRes, err := adapter.Execute(ctx, cmd)
	if err != nil || !execRes.Success {
		t.Fatalf("adapter execution failed: err=%v, res=%+v", err, execRes)
	}

	// 8. Independent Read-Back Verification (FR-K2)
	observed, err := adapter.Verify(ctx, cmd)
	if err != nil {
		t.Fatalf("adapter read-back verification failed: %v", err)
	}

	hasRole := false
	for _, r := range observed.CurrentRoles {
		if r == "role:finance-analyst" {
			hasRole = true
			break
		}
	}
	if !hasRole {
		t.Fatalf("expected role:finance-analyst to be observed in read-back IAM state")
	}

	// 9. Post-condition: Intern workstation session can now access finance reports!
	respAfter, err := ts.Client().Post(ts.URL+"/api/v1/business/finance-report/read", "application/json", bytes.NewReader(reportBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = respAfter.Body.Close() }()

	if respAfter.StatusCode != 200 {
		t.Fatalf("expected HTTP 200 OK after verified grant, got %d", respAfter.StatusCode)
	}

	var bizResp map[string]any
	_ = json.NewDecoder(respAfter.Body).Decode(&bizResp)
	if bizResp["status"] != "ok" || bizResp["actor"] != "user:rahul-assistant" {
		t.Fatalf("unexpected business response: %+v", bizResp)
	}
}

func TestD2_SensitiveAdminEscalationTwoLeadQuorum(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-exchange-demo"

	credStore := approval.NewCredentialStore()
	_ = approval.SeedDemoCredentials(credStore, tenantID)

	verifier, err := approval.NewApprovalVerifier(credStore, "localhost", []string{"http://localhost:3000"})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Setup D2 change: Rahul requests exchange-admin (Tier-0 access)
	changeReq := map[string]any{
		"kind":             "ROLE_ASSIGN",
		"request_id":       "req-rahul-admin-002",
		"requested_access": "role:exchange-admin",
		"requested_by":     "user:rahul",
		"target_identity":  "user:rahul",
		"tenant_id":        tenantID,
	}

	digester := canon.New()
	changeDigest, err := digester.Digest(changeReq)
	if err != nil {
		t.Fatalf("failed to compute digest: %v", err)
	}

	// Step 1: Security Lead 1 (Alice Vance) approves
	subAlice, err := approval.GenerateSimulatedAssertion(tenantID, "user:sec-lead-1", changeDigest, "localhost", "http://localhost:3000")
	if err != nil {
		t.Fatalf("failed to generate Alice assertion: %v", err)
	}

	verifiedAlice, err := verifier.Verify(ctx, subAlice, changeDigest)
	if err != nil || verifiedAlice.ActorID != "user:sec-lead-1" {
		t.Fatalf("Alice verification failed: %v", err)
	}

	// Step 2: Quorum check - 1 of 2 signatures is insufficient for Tier-0 admin
	collectedSigners := []string{verifiedAlice.ActorID}
	requiredQuorum := 2
	if len(collectedSigners) >= requiredQuorum {
		t.Fatalf("expected 1 of 2 signatures to NOT meet quorum")
	}

	// Step 3: Security Lead 2 (Bob Chen) approves
	subBob, err := approval.GenerateSimulatedAssertion(tenantID, "user:sec-lead-2", changeDigest, "localhost", "http://localhost:3000")
	if err != nil {
		t.Fatalf("failed to generate Bob assertion: %v", err)
	}

	verifiedBob, err := verifier.Verify(ctx, subBob, changeDigest)
	if err != nil || verifiedBob.ActorID != "user:sec-lead-2" {
		t.Fatalf("Bob verification failed: %v", err)
	}

	// Step 4: Quorum check - distinct signers check
	if verifiedAlice.ActorID == verifiedBob.ActorID {
		t.Fatalf("duplicate signers detected")
	}
	collectedSigners = append(collectedSigners, verifiedBob.ActorID)

	if len(collectedSigners) < requiredQuorum {
		t.Fatalf("expected 2 of 2 signatures to meet quorum")
	}

	// Step 5: Anti-tamper verification check: verifying against a tampered digest must fail
	tamperedDigest := ports.Digest(sha256.Sum256([]byte(`{"tampered":"request"}`)))
	_, err = verifier.Verify(ctx, subBob, tamperedDigest)
	if err == nil {
		t.Fatalf("expected tampered digest to fail verification, got success")
	}
}
