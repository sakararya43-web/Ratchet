package approval

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestSeedDemoCredentialsAndAssertion(t *testing.T) {
	ctx := context.Background()
	store := NewCredentialStore()

	tenantID := "tenant-exchange-demo"
	if err := SeedDemoCredentials(store, tenantID); err != nil {
		t.Fatalf("failed to seed demo credentials: %v", err)
	}

	verifier, err := NewApprovalVerifier(store, "localhost", []string{"http://localhost:3000"})
	if err != nil {
		t.Fatalf("failed to create approval verifier: %v", err)
	}

	changeBytes := []byte(`{"request_id":"req-ordinary-001","action":"ASSIGN_ROLE","role":"role:finance-analyst"}`)
	changeDigest := ports.Digest(sha256.Sum256(changeBytes))

	// Generate simulated assertion for Priya Patel (user:finance-lead)
	sub, err := GenerateSimulatedAssertion(tenantID, "user:finance-lead", changeDigest, "localhost", "http://localhost:3000")
	if err != nil {
		t.Fatalf("failed to generate simulated assertion: %v", err)
	}

	// Verify using real ApprovalVerifier
	verified, err := verifier.Verify(ctx, sub, changeDigest)
	if err != nil {
		t.Fatalf("failed to verify simulated assertion: %v", err)
	}

	if verified.ActorID != "user:finance-lead" {
		t.Errorf("expected actor user:finance-lead, got %s", verified.ActorID)
	}
	if !verified.UserVerified {
		t.Errorf("expected UserVerified to be true")
	}

	// Verification with mismatched change digest must fail
	tamperedDigest := ports.Digest(sha256.Sum256([]byte(`{"tampered":"request"}`)))
	_, err = verifier.Verify(ctx, sub, tamperedDigest)
	if err == nil {
		t.Errorf("expected verification to fail for tampered change digest, but got success")
	}
}
