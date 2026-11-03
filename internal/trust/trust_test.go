package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"path/filepath"
	"testing"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func TestAuthorityGenesisAndBundleQuorum(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "authority_test.json")

	store, err := NewStore(filePath)
	if err != nil {
		t.Fatalf("failed to create authority store: %v", err)
	}

	// 1. Generate 3 keypairs for 3 Authority security leads (Alice, Bob, Carol)
	keyAlice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubAlice, _ := x509.MarshalPKIXPublicKey(&keyAlice.PublicKey)

	keyBob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBob, _ := x509.MarshalPKIXPublicKey(&keyBob.PublicKey)

	keyCarol, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubCarol, _ := x509.MarshalPKIXPublicKey(&keyCarol.PublicKey)

	members := []AuthorityMember{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance", PublicKey: pubAlice, IsActive: true},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen", PublicKey: pubBob, IsActive: true},
		{ActorID: "user:sec-lead-3", DisplayName: "Carol Danvers", PublicKey: pubCarol, IsActive: true},
	}

	// 2. Initialize Genesis: 2-of-3 quorum
	tenantID := "tenant-exchange-demo"
	genesis, err := store.InitGenesis(tenantID, 2, 3, members)
	if err != nil {
		t.Fatalf("genesis failed: %v", err)
	}

	if genesis.ThresholdM != 2 || genesis.TotalN != 3 {
		t.Errorf("expected 2-of-3 threshold, got %d-of-%d", genesis.ThresholdM, genesis.TotalN)
	}

	// 3. Test Genesis Immutability: attempt to re-initialize genesis (must fail)
	_, err = store.InitGenesis(tenantID, 1, 3, members)
	if err == nil {
		t.Errorf("expected error attempting to re-initialize genesis, got nil")
	}

	// 4. Propose a Policy Bundle (demo policies)
	modules := map[string]string{
		"change.rego": `package ratchet.change
import rego.v1
decision := allow if input.impact.monotonic_reduction`,
	}
	data := map[string]any{
		"critical_tier": 0,
	}

	proposal, err := store.ProposeBundle(tenantID, "v1.0.0", "Initial production security policy bundle", modules, data)
	if err != nil {
		t.Fatalf("propose bundle failed: %v", err)
	}

	if proposal.BundleDigest.IsZero() {
		t.Fatalf("expected non-zero bundle digest")
	}

	// 5. Member 1 (Alice) signs the proposal
	sigHash := sha256.Sum256(proposal.BundleDigest[:])
	rAlice, sAlice, _ := ecdsa.Sign(rand.Reader, keyAlice, sigHash[:])
	asn1SigAlice, _ := asn1.Marshal(ecdsaSignature{R: rAlice, S: sAlice})

	err = store.SignProposal(proposal.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-1",
		Signature: asn1SigAlice,
	})
	if err != nil {
		t.Fatalf("Alice sign failed: %v", err)
	}

	// 6. Test duplicate signature prevention: Alice signs again (must fail)
	err = store.SignProposal(proposal.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-1",
		Signature: asn1SigAlice,
	})
	if err == nil {
		t.Errorf("expected error on duplicate signature from same member, got nil")
	}

	// 7. Attempt activation before meeting quorum (only 1 of 2 signatures collected)
	_, err = store.ActivateBundle(proposal.ProposalID)
	if err == nil {
		t.Errorf("expected error activating bundle before meeting threshold M=2, got nil")
	}

	// 8. Member 2 (Bob) signs the proposal -> Quorum 2-of-3 is met!
	rBob, sBob, _ := ecdsa.Sign(rand.Reader, keyBob, sigHash[:])
	asn1SigBob, _ := asn1.Marshal(ecdsaSignature{R: rBob, S: sBob})

	err = store.SignProposal(proposal.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-2",
		Signature: asn1SigBob,
	})
	if err != nil {
		t.Fatalf("Bob sign failed: %v", err)
	}

	// 9. Activate bundle
	activeBundle, err := store.ActivateBundle(proposal.ProposalID)
	if err != nil {
		t.Fatalf("bundle activation failed: %v", err)
	}
	if activeBundle.Status != "ACTIVE" {
		t.Errorf("expected status ACTIVE, got %s", activeBundle.Status)
	}

	// 10. Test BundleVerifier (consumed by Half A policy engine)
	verifier := NewBundleVerifier(store)
	bundleRawBytes, err := json.Marshal(activeBundle)
	if err != nil {
		t.Fatalf("marshal active bundle failed: %v", err)
	}

	verifiedBundle, err := verifier.Verify(ctx, bundleRawBytes)
	if err != nil {
		t.Fatalf("bundle verification failed: %v", err)
	}
	if verifiedBundle.BundleVersion != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", verifiedBundle.BundleVersion)
	}
	if len(verifiedBundle.SignerIDs) != 2 {
		t.Errorf("expected 2 verified signers, got %d", len(verifiedBundle.SignerIDs))
	}

	// 11. Test Tamper Rejection: tamper with module content in bundle
	var tamperedBundle PolicyBundle
	_ = json.Unmarshal(bundleRawBytes, &tamperedBundle)
	tamperedBundle.Modules["change.rego"] = `package ratchet.change; decision := allow` // modified
	tamperedBytes, _ := json.Marshal(tamperedBundle)

	_, err = verifier.Verify(ctx, tamperedBytes)
	if err == nil {
		t.Errorf("expected error verifying tampered bundle, but verification succeeded!")
	}
}
