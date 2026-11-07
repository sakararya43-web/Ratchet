package trust

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func deriveAuthKey(seed string) *ecdsa.PrivateKey {
	h := sha256.Sum256([]byte(seed))
	ecdhKey, err := ecdh.P256().NewPrivateKey(h[:])
	for i := 1; err != nil; i++ {
		h = sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, i)))
		ecdhKey, err = ecdh.P256().NewPrivateKey(h[:])
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecdhKey)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal pkcs8: %v", err))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		panic(fmt.Sprintf("failed to parse pkcs8: %v", err))
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("unexpected parsed key type: %T", parsed))
	}
	return priv
}

func TestGenerateAndVerifyAuthorityFixtures(t *testing.T) {
	ctx := context.Background()

	keyAlice := deriveAuthKey("ratchet-authority-alice-vance-seed")
	pubAlice, _ := x509.MarshalPKIXPublicKey(&keyAlice.PublicKey)

	keyBob := deriveAuthKey("ratchet-authority-bob-chen-seed")
	pubBob, _ := x509.MarshalPKIXPublicKey(&keyBob.PublicKey)

	keyCarol := deriveAuthKey("ratchet-authority-carol-danvers-seed")
	pubCarol, _ := x509.MarshalPKIXPublicKey(&keyCarol.PublicKey)

	type memberJSON struct {
		ActorID     string `json:"actor_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
	}

	membersExport := []memberJSON{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance (Security Lead 1)", PublicKey: hex.EncodeToString(pubAlice)},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen (Security Lead 2)", PublicKey: hex.EncodeToString(pubBob)},
		{ActorID: "user:sec-lead-3", DisplayName: "Carol Danvers (Security Lead 3)", PublicKey: hex.EncodeToString(pubCarol)},
	}

	membersDir := filepath.Join(t.TempDir(), "authority")
	if os.Getenv("UPDATE_FIXTURES") == "1" {
		membersDir = filepath.Join("..", "..", "testdata", "authority")
	}
	if err := os.MkdirAll(membersDir, 0755); err != nil {
		t.Fatalf("failed to create authority testdata dir: %v", err)
	}

	membersData, err := json.MarshalIndent(membersExport, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal members: %v", err)
	}
	if err := os.WriteFile(filepath.Join(membersDir, "members.json"), membersData, 0644); err != nil {
		t.Fatalf("failed to write members.json: %v", err)
	}

	// Create temporary store to produce signed bundle
	tmpFile := filepath.Join(t.TempDir(), "temp_authority.json")
	store, err := NewStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create temp store: %v", err)
	}

	authorityMembers := []AuthorityMember{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance", PublicKey: pubAlice, IsActive: true},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen", PublicKey: pubBob, IsActive: true},
		{ActorID: "user:sec-lead-3", DisplayName: "Carol Danvers", PublicKey: pubCarol, IsActive: true},
	}

	tenantID := "tenant-exchange-demo"
	_, err = store.InitGenesis(tenantID, 2, 3, authorityMembers)
	if err != nil {
		t.Fatalf("genesis failed: %v", err)
	}

	modules := map[string]string{
		"change.rego": `package ratchet.change
import rego.v1
default allow := false
allow if input.impact.monotonic_reduction == true
allow if input.approvals.count >= 2`,
		"safeguards.rego": `package ratchet.safeguards
import rego.v1
default protected := true`,
	}
	policyData := map[string]any{
		"critical_tier": 0,
		"quorums": map[string]any{
			"tier0":    2,
			"ordinary": 1,
		},
	}

	proposal, err := store.ProposeBundle(tenantID, "v1.0.0", "RATCHET Production Security Policy Bundle v1.0.0", modules, policyData)
	if err != nil {
		t.Fatalf("propose bundle failed: %v", err)
	}

	// Alice signs
	sigHash := sha256.Sum256(proposal.BundleDigest[:])
	rAlice, sAlice, _ := ecdsa.Sign(rand.Reader, keyAlice, sigHash[:])
	asn1SigAlice, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rAlice, S: sAlice})
	_ = store.SignProposal(proposal.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-1",
		Signature: asn1SigAlice,
	})

	// Bob signs
	rBob, sBob, _ := ecdsa.Sign(rand.Reader, keyBob, sigHash[:])
	asn1SigBob, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rBob, S: sBob})
	_ = store.SignProposal(proposal.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-2",
		Signature: asn1SigBob,
	})

	// Activate bundle
	activeBundle, err := store.ActivateBundle(proposal.ProposalID)
	if err != nil {
		t.Fatalf("activate bundle failed: %v", err)
	}

	bundleJSON, err := json.MarshalIndent(activeBundle, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal active bundle: %v", err)
	}

	if err := os.WriteFile(filepath.Join(membersDir, "initial_bundle.json"), bundleJSON, 0644); err != nil {
		t.Fatalf("failed to write initial_bundle.json: %v", err)
	}

	// Verify using BundleVerifier
	verifier := NewBundleVerifier(store)
	verified, err := verifier.Verify(ctx, bundleJSON)
	if err != nil {
		t.Fatalf("BundleVerifier rejected generated fixture: %v", err)
	}

	if verified.BundleVersion != "v1.0.0" {
		t.Errorf("expected v1.0.0, got %s", verified.BundleVersion)
	}
	if len(verified.SignerIDs) != 2 {
		t.Errorf("expected 2 signers, got %d", len(verified.SignerIDs))
	}
}

