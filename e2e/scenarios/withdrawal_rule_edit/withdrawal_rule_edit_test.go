package withdrawal_rule_edit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func TestWithdrawalRuleSafeguardGovernance(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-exchange-demo"

	// 1. Initialize Simulator
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to create simulator store: %v", err)
	}

	initialSafeguard := store.GetState().Safeguards[0]
	if initialSafeguard.ID != "safeguard:withdrawal-rule" {
		t.Fatalf("expected first safeguard to be safeguard:withdrawal-rule, got %s", initialSafeguard.ID)
	}
	if initialSafeguard.Parameters["threshold_usd"] != "10000" {
		t.Fatalf("expected initial threshold 10000, got %s", initialSafeguard.Parameters["threshold_usd"])
	}

	// -------------------------------------------------------------
	// NEGATIVE CASE: Ordinary/Rogue IAM Request to Weaken Safeguard
	// -------------------------------------------------------------
	// Attempting to modify safeguard:withdrawal-rule through an ordinary IAM grant
	rogueActor := "user:admin-operator"
	accessCheck := store.CheckAccess(rogueActor, "safeguard:withdrawal-rule", "modify")
	if accessCheck.Allowed {
		t.Fatalf("VULNERABILITY: Ordinary admin operator allowed to directly modify Tier-0 safeguard!")
	}

	// Direct mutation outside of broker or authority must be rejected
	initialRevision := store.GetState().Revision
	initialGrantsCount := len(store.GetState().Grants)

	// -------------------------------------------------------------
	// POSITIVE CASE: Governed Independent Authority Amendment
	// -------------------------------------------------------------
	tmpDir := t.TempDir()
	authStore, err := trust.NewStore(filepath.Join(tmpDir, "authority_safeguard.json"))
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	keyAlice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubAlice, _ := x509.MarshalPKIXPublicKey(&keyAlice.PublicKey)

	keyBob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBob, _ := x509.MarshalPKIXPublicKey(&keyBob.PublicKey)

	members := []trust.AuthorityMember{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance", PublicKey: pubAlice, IsActive: true},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen", PublicKey: pubBob, IsActive: true},
	}

	// Initialize genesis with M=2, N=2
	_, err = authStore.InitGenesis(tenantID, 2, 2, members)
	if err != nil {
		t.Fatalf("genesis failed: %v", err)
	}

	// Propose updated security policy bundle governing dual-control withdrawal rule
	newModules := map[string]string{
		"change.rego": `package ratchet.change
import rego.v1
default allow := false
allow if input.impact.monotonic_reduction == true`,
		"safeguards.rego": `package ratchet.safeguards
import rego.v1
default protected := true
threshold_usd := 25000`,
	}
	newData := map[string]any{
		"critical_tier": 0,
		"withdrawal_rule": map[string]any{
			"threshold_usd":   25000,
			"required_checks": 2,
		},
	}

	proposal, err := authStore.ProposeBundle(tenantID, "v1.1.0", "Governed update to dual-control threshold", newModules, newData)
	if err != nil {
		t.Fatalf("proposal failed: %v", err)
	}

	// Security Lead 1 (Alice) signs
	sigAlice := trust.ComputePolicySigningDigest(tenantID, 1, proposal.BundleDigest)
	rA, sA, _ := ecdsa.Sign(rand.Reader, keyAlice, sigAlice[:])
	asnSigA, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rA, S: sA})
	_ = authStore.SignProposal(proposal.ProposalID, trust.MemberSignature{
		ActorID:   "user:sec-lead-1",
		Signature: asnSigA,
	})

	// Security Lead 2 (Bob) signs
	sigBob := trust.ComputePolicySigningDigest(tenantID, 1, proposal.BundleDigest)
	rB, sB, _ := ecdsa.Sign(rand.Reader, keyBob, sigBob[:])
	asnSigB, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rB, S: sB})
	_ = authStore.SignProposal(proposal.ProposalID, trust.MemberSignature{
		ActorID:   "user:sec-lead-2",
		Signature: asnSigB,
	})

	// Activate bundle in Authority
	activeBundle, err := authStore.ActivateBundle(proposal.ProposalID)
	if err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	if activeBundle.Status != "ACTIVE" {
		t.Fatalf("expected bundle status ACTIVE, got %s", activeBundle.Status)
	}

	// Verify using peer-consumable BundleVerifier
	verifier := trust.NewBundleVerifier(authStore)
	bundleBytes, _ := json.Marshal(activeBundle)
	verifiedBundle, err := verifier.Verify(ctx, bundleBytes)
	if err != nil {
		t.Fatalf("BundleVerifier rejected valid bundle: %v", err)
	}

	if verifiedBundle.BundleVersion != "v1.1.0" {
		t.Errorf("expected version v1.1.0, got %s", verifiedBundle.BundleVersion)
	}

	// -------------------------------------------------------------
	// SEPARATION OF CONCERNS VERIFICATION:
	// The signed policy bundle updates the Authority's active rules,
	// but DOES NOT directly mutate simulator IAM!
	// -------------------------------------------------------------
	currentOrgState := store.GetState()
	if currentOrgState.Revision != initialRevision {
		t.Fatalf("VIOLATION: Authority bundle activation directly mutated simulator IAM revision!")
	}
	if len(currentOrgState.Grants) != initialGrantsCount {
		t.Fatalf("VIOLATION: Authority bundle activation altered simulator grants!")
	}
}
