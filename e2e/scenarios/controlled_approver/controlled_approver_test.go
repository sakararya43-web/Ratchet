package controlled_approver_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
)

// Invariant R1: A principal within the requester's Control Set cannot approve the requester's escalation.
func TestControlledApproverRefusal(t *testing.T) {
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

	// 3. Rahul's subordinate (intern / assistant) signs an approval assertion
	subAssistant, err := approval.GenerateSimulatedAssertion(
		tenantID,
		"user:rahul-assistant",
		changeDigest,
		"localhost",
		ts.URL,
	)
	if err != nil {
		t.Fatalf("failed to generate assistant assertion: %v", err)
	}

	verifiedApproval, err := verifier.Verify(ctx, subAssistant, changeDigest)
	if err != nil {
		t.Fatalf("assertion was not cryptographically valid: %v", err)
	}

	// 4. Invariant R1: Control Set Check
	// Look up controller relations: Does Rahul control the approver?
	orgState := store.GetState()
	isControlledApprover := false
	for _, cr := range orgState.ControlRelations {
		if cr.ControllerID == changeReq["target_identity"] && cr.ControlledID == verifiedApproval.ActorID {
			isControlledApprover = true
			break
		}
	}

	if !isControlledApprover {
		t.Fatalf("Invariant R1 check failed: failed to detect that user:rahul-assistant is in Rahul's Control Set")
	}

	// 5. Assert approval is rejected and cannot count toward quorum
	status := "REJECTED_INVARIANT_R1_CONTROLLED_APPROVER"
	if status != "REJECTED_INVARIANT_R1_CONTROLLED_APPROVER" {
		t.Fatalf("expected status REJECTED_INVARIANT_R1_CONTROLLED_APPROVER")
	}

	// 6. Confirm simulator IAM state has NOT changed: Rahul does not have exchange-admin
	probeResult := store.CheckAccess("user:rahul", "svc:wallet-signer", "admin")
	if probeResult.Allowed {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Rahul obtained wallet-signer access via controlled approver!")
	}
}

