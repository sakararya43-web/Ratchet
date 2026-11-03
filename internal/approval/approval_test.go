package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func TestCredentialStoreManagement(t *testing.T) {
	cs := NewCredentialStore()

	credID := []byte("cred-12345")
	cred := &webauthn.Credential{
		ID:        credID,
		PublicKey: []byte("pubkey-bytes"),
	}

	// 1. Save
	if err := cs.SaveCredential("tenant-1", "user-alice", "My Macbook Passkey", cred); err != nil {
		t.Fatalf("failed to save credential: %v", err)
	}

	// 2. List
	list := cs.ListCredentials("tenant-1", "user-alice")
	if len(list) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list))
	}
	if list[0].Label != "My Macbook Passkey" {
		t.Errorf("expected label 'My Macbook Passkey', got %s", list[0].Label)
	}

	// 3. User with active credentials
	user := cs.GetUser("tenant-1", "user-alice", "Alice")
	if len(user.Credentials) != 1 {
		t.Errorf("expected 1 active credential on user, got %d", len(user.Credentials))
	}

	// 4. Revoke
	if err := cs.RevokeCredential("tenant-1", "user-alice", credID); err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}

	userAfterRevoke := cs.GetUser("tenant-1", "user-alice", "Alice")
	if len(userAfterRevoke.Credentials) != 0 {
		t.Errorf("expected 0 active credentials after revocation, got %d", len(userAfterRevoke.Credentials))
	}
}

func TestApprovalVerifierCryptographicBinding(t *testing.T) {
	ctx := context.Background()
	cs := NewCredentialStore()

	// 1. Generate an ECDSA P-256 keypair for simulated passkey
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	credID := []byte("passkey-credential-001")
	testCred := &webauthn.Credential{
		ID:        credID,
		PublicKey: pubKeyBytes,
	}

	tenantID := "tenant-exchange-demo"
	actorID := "user:sec-lead-1"
	if err := cs.SaveCredential(tenantID, actorID, "YubiKey 5C", testCred); err != nil {
		t.Fatalf("failed to save test passkey: %v", err)
	}

	verifier, err := NewApprovalVerifier(cs, "localhost", []string{"http://localhost:3000"})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// 2. Setup change digest and nonce
	sampleChange := []byte(`{"kind":"ROLE_ASSIGN","target":"user:rahul","role":"role:exchange-admin"}`)
	changeDigest := sha256.Sum256(sampleChange)
	nonce := []byte("random-nonce-1234")

	boundChallenge := ComputeApprovalChallenge(tenantID, actorID, changeDigest, nonce)

	// 3. Construct valid WebAuthn clientDataJSON
	clientData := map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(boundChallenge),
		"origin":      "http://localhost:3000",
		"crossOrigin": false,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatalf("failed to marshal clientDataJSON: %v", err)
	}

	// 4. Construct AuthenticatorData (37 bytes: 32 bytes rpIdHash + 1 byte flags + 4 bytes signCount)
	rpIdHash := sha256.Sum256([]byte("localhost"))
	flags := byte(0x01 | 0x04) // UP (User Present) | UV (User Verified)
	authData := make([]byte, 37)
	copy(authData[0:32], rpIdHash[:])
	authData[32] = flags

	// 5. Compute signature over authData || SHA-256(clientDataJSON)
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := append(authData, clientDataHash[:]...)
	sigHash := sha256.Sum256(signedData)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, sigHash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	asn1Sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		t.Fatalf("failed to marshal ASN.1 signature: %v", err)
	}

	validSubmission := ports.ApprovalSubmission{
		TenantID:          tenantID,
		ActorID:           actorID,
		CredentialID:      credID,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: authData,
		Signature:         asn1Sig,
		ChallengeNonce:    nonce,
	}

	// 6. Test valid approval verification
	verified, err := verifier.Verify(ctx, validSubmission, changeDigest)
	if err != nil {
		t.Fatalf("expected valid approval, got error: %v", err)
	}
	if verified.ActorID != actorID {
		t.Errorf("expected actor %s, got %s", actorID, verified.ActorID)
	}
	if !verified.UserVerified {
		t.Errorf("expected UserVerified=true")
	}

	// 7. Test anti-TOCTOU: attempted approval with a different change digest
	differentDigest := sha256.Sum256([]byte(`{"tampered":"payload"}`))
	_, err = verifier.Verify(ctx, validSubmission, differentDigest)
	if err == nil {
		t.Errorf("expected error when verifying tampered change digest, but got success!")
	}

	// 8. Test revocation rejection: revoke passkey and attempt verification again
	_ = cs.RevokeCredential(tenantID, actorID, credID)
	_, err = verifier.Verify(ctx, validSubmission, changeDigest)
	if err == nil {
		t.Errorf("expected error when verifying revoked passkey, but got success!")
	}
}
