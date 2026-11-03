package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"path/filepath"
	"testing"
)

func TestRegistryRotationQuorum(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(filepath.Join(tmpDir, "authority_gov_test.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// 1. Initial Genesis: Alice, Bob, Carol (M=2, N=3, Epoch 1)
	keyAlice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubAlice, _ := x509.MarshalPKIXPublicKey(&keyAlice.PublicKey)

	keyBob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBob, _ := x509.MarshalPKIXPublicKey(&keyBob.PublicKey)

	keyCarol, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubCarol, _ := x509.MarshalPKIXPublicKey(&keyCarol.PublicKey)

	membersEpoch1 := []AuthorityMember{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance", PublicKey: pubAlice, IsActive: true},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen", PublicKey: pubBob, IsActive: true},
		{ActorID: "user:sec-lead-3", DisplayName: "Carol Danvers", PublicKey: pubCarol, IsActive: true},
	}

	tenantID := "tenant-exchange-demo"
	_, err = store.InitGenesis(tenantID, 2, 3, membersEpoch1)
	if err != nil {
		t.Fatalf("genesis failed: %v", err)
	}

	// 2. Propose Registry Rotation: Add Dave, rotate Carol, increase M to 3, N to 4 for Epoch 2
	keyDave, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDave, _ := x509.MarshalPKIXPublicKey(&keyDave.PublicKey)

	membersEpoch2 := []AuthorityMember{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance", PublicKey: pubAlice, IsActive: true},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen", PublicKey: pubBob, IsActive: true},
		{ActorID: "user:sec-lead-3", DisplayName: "Carol Danvers", PublicKey: pubCarol, IsActive: false}, // rotated out
		{ActorID: "user:sec-lead-4", DisplayName: "Dave Miller", PublicKey: pubDave, IsActive: true},      // new lead
	}

	regProp, err := store.ProposeRegistryChange(tenantID, 2, 4, membersEpoch2)
	if err != nil {
		t.Fatalf("propose registry change failed: %v", err)
	}

	if regProp.TargetEpoch != 2 {
		t.Errorf("expected target epoch 2, got %d", regProp.TargetEpoch)
	}

	// 3. Test that Dave (proposed member, but NOT yet active in Epoch 1) CANNOT sign the proposal
	sigDigestDave := ComputeRegistrySigningDigest(tenantID, 1, 2, regProp.ProposalDigest)
	rDave, sDave, _ := ecdsa.Sign(rand.Reader, keyDave, sigDigestDave[:])
	asn1SigDave, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rDave, S: sDave})

	err = store.SignRegistryProposal(regProp.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-4",
		Signature: asn1SigDave,
	})
	if err == nil {
		t.Fatalf("expected signature from unactivated member Dave to fail, got success")
	}

	// 4. Current member Alice signs
	sigDigestAlice := ComputeRegistrySigningDigest(tenantID, 1, 2, regProp.ProposalDigest)
	rAlice, sAlice, _ := ecdsa.Sign(rand.Reader, keyAlice, sigDigestAlice[:])
	asn1SigAlice, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rAlice, S: sAlice})

	err = store.SignRegistryProposal(regProp.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-1",
		Signature: asn1SigAlice,
	})
	if err != nil {
		t.Fatalf("Alice sign failed: %v", err)
	}

	// 5. Activation attempt before quorum (only 1 signature collected, M=2 required)
	_, err = store.ActivateRegistryProposal(regProp.ProposalID)
	if err == nil {
		t.Fatalf("expected activation to fail before quorum met, got success")
	}

	// 6. Current member Bob signs -> Quorum met under Epoch 1 (2 of 3)
	sigDigestBob := ComputeRegistrySigningDigest(tenantID, 1, 2, regProp.ProposalDigest)
	rBob, sBob, _ := ecdsa.Sign(rand.Reader, keyBob, sigDigestBob[:])
	asn1SigBob, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rBob, S: sBob})

	err = store.SignRegistryProposal(regProp.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-2",
		Signature: asn1SigBob,
	})
	if err != nil {
		t.Fatalf("Bob sign failed: %v", err)
	}

	// 7. Activate registry change -> Advances to Epoch 2
	updatedGenesis, err := store.ActivateRegistryProposal(regProp.ProposalID)
	if err != nil {
		t.Fatalf("activate registry failed: %v", err)
	}

	if updatedGenesis.Epoch != 2 {
		t.Errorf("expected epoch 2 after activation, got %d", updatedGenesis.Epoch)
	}
	if len(updatedGenesis.Members) != 4 {
		t.Errorf("expected 4 members in epoch 2, got %d", len(updatedGenesis.Members))
	}

	// 8. Verify registry history recorded
	history := store.GetRegistryHistory()
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries (genesis + epoch 2), got %d", len(history))
	}
	if history[1].Epoch != 2 {
		t.Errorf("expected epoch 2 in history, got %d", history[1].Epoch)
	}
}

func TestStaleProposalRejectionAcrossEpochs(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(filepath.Join(tmpDir, "authority_stale_test.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	keyAlice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubAlice, _ := x509.MarshalPKIXPublicKey(&keyAlice.PublicKey)

	keyBob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBob, _ := x509.MarshalPKIXPublicKey(&keyBob.PublicKey)

	members := []AuthorityMember{
		{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance", PublicKey: pubAlice, IsActive: true},
		{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen", PublicKey: pubBob, IsActive: true},
	}

	tenantID := "tenant-exchange-demo"
	_, _ = store.InitGenesis(tenantID, 2, 2, members)

	// Propose bundle in Epoch 1
	bundleEpoch1, err := store.ProposeBundle(tenantID, "v1.0.0", "Epoch 1 bundle", map[string]string{"p.rego": "package p"}, nil)
	if err != nil {
		t.Fatalf("propose bundle failed: %v", err)
	}

	// Rotate registry to Epoch 2
	regProp, _ := store.ProposeRegistryChange(tenantID, 2, 2, members)
	sigAlice := ComputeRegistrySigningDigest(tenantID, 1, 2, regProp.ProposalDigest)
	rA, sA, _ := ecdsa.Sign(rand.Reader, keyAlice, sigAlice[:])
	asnSigA, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rA, S: sA})
	_ = store.SignRegistryProposal(regProp.ProposalID, MemberSignature{ActorID: "user:sec-lead-1", Signature: asnSigA})

	sigBob := ComputeRegistrySigningDigest(tenantID, 1, 2, regProp.ProposalDigest)
	rB, sB, _ := ecdsa.Sign(rand.Reader, keyBob, sigBob[:])
	asnSigB, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rB, S: sB})
	_ = store.SignRegistryProposal(regProp.ProposalID, MemberSignature{ActorID: "user:sec-lead-2", Signature: asnSigB})

	_, err = store.ActivateRegistryProposal(regProp.ProposalID)
	if err != nil {
		t.Fatalf("registry rotation failed: %v", err)
	}

	// Attempting to sign the Epoch 1 bundle under active Epoch 2 must be rejected!
	bundleSigAlice := ComputePolicySigningDigest(tenantID, 1, bundleEpoch1.BundleDigest)
	rBA, sBA, _ := ecdsa.Sign(rand.Reader, keyAlice, bundleSigAlice[:])
	asnSigBA, _ := asn1.Marshal(struct{ R, S *big.Int }{R: rBA, S: sBA})

	err = store.SignProposal(bundleEpoch1.ProposalID, MemberSignature{
		ActorID:   "user:sec-lead-1",
		Signature: asnSigBA,
	})
	if err == nil {
		t.Fatalf("expected signing stale proposal to fail, but succeeded")
	}

	// Attempting to activate stale proposal must be rejected!
	_, err = store.ActivateBundle(bundleEpoch1.ProposalID)
	if err == nil {
		t.Fatalf("expected activating stale proposal to fail, but succeeded")
	}
}

func TestCrossActionReplayPrevention(t *testing.T) {
	keyAlice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tenantID := "tenant-exchange-demo"

	bundleDigest := [32]byte{1, 2, 3, 4, 5}

	// 1. Policy bundle digest
	policyDigest := ComputePolicySigningDigest(tenantID, 1, bundleDigest)

	// 2. Registry digest
	registryDigest := ComputeRegistrySigningDigest(tenantID, 1, 2, bundleDigest)

	if policyDigest == registryDigest {
		t.Fatalf("cross-action replay vulnerability: policy and registry hashes are identical!")
	}

	// Sign policyDigest
	r, s, _ := ecdsa.Sign(rand.Reader, keyAlice, policyDigest[:])
	asn1Sig, _ := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})

	// Verifying against registryDigest must fail
	if ecdsa.VerifyASN1(&keyAlice.PublicKey, registryDigest[:], asn1Sig) {
		t.Fatalf("cross-action replay vulnerability: policy signature verified as valid registry signature!")
	}
}
