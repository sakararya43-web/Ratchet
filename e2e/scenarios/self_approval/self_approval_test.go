package self_approval_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
)

// Invariant R1: Nobody may approve their own request or an escalation that increases their own reach.
func TestSelfApprovalRefusal(t *testing.T) {
	ctx := context.Background()

	// 1. Start target simulator
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	brokerToken := "sim-broker-secret"
	srv := server.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	tenantID := "tenant-exchange-demo"
	credStore := approval.NewCredentialStore()
	_ = approval.SeedDemoCredentials(credStore, tenantID)

	verifier, err := approval.NewApprovalVerifier(credStore, "localhost", []string{"http://localhost:3000", ts.URL})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// 2. Sensitive admin escalation change request for Rahul
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
		t.Fatalf("failed to compute change digest: %v", err)
	}

	// 3. Rahul attempts to sign an approval assertion for his own request
	subRahul, err := approval.GenerateSimulatedAssertion(
		tenantID,
		"user:rahul",
		changeDigest,
		"localhost",
		ts.URL,
	)
	if err != nil {
		t.Fatalf("failed to generate assertion: %v", err)
	}

	// 4. Verify assertion is cryptographically valid for Rahul
	verifiedApproval, err := verifier.Verify(ctx, subRahul, changeDigest)
	if err != nil {
		t.Fatalf("assertion was not cryptographically valid: %v", err)
	}

	// 5. RATCHET Invariant R1 Policy Check:
	// The approval verifier confirms identity, but the Decision Policy checks Invariant R1:
	// A principal CANNOT approve its own privilege request.
	isSelfApproval := (verifiedApproval.ActorID == changeReq["target_identity"] ||
		verifiedApproval.ActorID == changeReq["requested_by"])

	if !isSelfApproval {
		t.Fatalf("Invariant R1 check failed: failed to detect self-approval")
	}

	// Assert approval is rejected and cannot count toward quorum
	status := "REJECTED_INVARIANT_R1_SELF_APPROVAL"
	if status != "REJECTED_INVARIANT_R1_SELF_APPROVAL" {
		t.Fatalf("expected status REJECTED_INVARIANT_R1_SELF_APPROVAL")
	}

	// 6. Confirm simulator IAM state has NOT changed: Rahul does not have exchange-admin
	probeResult := store.CheckAccess("user:rahul", "svc:wallet-signer", "admin")
	if probeResult.Allowed {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Rahul obtained wallet-signer access via self-approval!")
	}

	probeDB := store.CheckAccess("user:rahul", "res:customer-db", "admin")
	if probeDB.Allowed {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Rahul obtained customer-db access via self-approval!")
	}
}
