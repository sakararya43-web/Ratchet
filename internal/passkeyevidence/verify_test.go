package passkeyevidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func makeAssertion(t *testing.T, key *ecdsa.PrivateKey, tenant, actor string, challenge []byte, nonce []byte, origin, rpID string) ports.ApprovalSubmission {
	t.Helper()
	client, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := make([]byte, 37)
	rp := sha256.Sum256([]byte(rpID))
	copy(auth, rp[:])
	auth[32] = 5 // User Present (0x01) | User Verified (0x04)

	clientHash := sha256.Sum256(client)
	sigData := append(append([]byte(nil), auth...), clientHash[:]...)
	sigDataHash := sha256.Sum256(sigData)

	sig, err := ecdsa.SignASN1(rand.Reader, key, sigDataHash[:])
	if err != nil {
		t.Fatal(err)
	}

	return ports.ApprovalSubmission{
		TenantID:          tenant,
		ActorID:           actor,
		CredentialID:      []byte("test-credential-id"),
		ClientDataJSON:    client,
		AuthenticatorData: auth,
		Signature:         sig,
		ChallengeNonce:    nonce,
	}
}

func TestPasskeyDomainSeparationBetweenApprovalAndContainment(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tenant := "exchange-demo"
	actor := "user:sec-lead"
	rpID := "localhost"
	origins := []string{"https://localhost:8443"}
	digest := ports.Digest{1, 2, 3, 4, 5}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	// 1. Create an approval assertion
	approvalChallenge := Challenge(tenant, actor, digest, nonce)
	approvalSub := makeAssertion(t, key, tenant, actor, approvalChallenge, nonce, origins[0], rpID)

	// 2. Create a containment assertion
	containmentChallenge := ContainmentChallenge(tenant, actor, digest, nonce)
	containmentSub := makeAssertion(t, key, tenant, actor, containmentChallenge, nonce, origins[0], rpID)

	ctx := context.Background()

	// Verify approval succeeds with approval submission
	if _, err := Verify(ctx, approvalSub, digest, pubBytes, rpID, origins); err != nil {
		t.Fatalf("expected approval to succeed: %v", err)
	}

	// Verify containment succeeds with containment submission
	if _, err := VerifyContainment(ctx, containmentSub, digest, pubBytes, rpID, origins); err != nil {
		t.Fatalf("expected containment to succeed: %v", err)
	}

	// Invariant R4/A2: Approval assertion CANNOT authorize containment
	if _, err := VerifyContainment(ctx, approvalSub, digest, pubBytes, rpID, origins); err == nil {
		t.Fatal("SECURITY VIOLATION: approval assertion was accepted as containment authorization")
	}

	// Invariant R4/A2: Containment assertion CANNOT authorize ordinary change approval
	if _, err := Verify(ctx, containmentSub, digest, pubBytes, rpID, origins); err == nil {
		t.Fatal("SECURITY VIOLATION: containment assertion was accepted as change approval")
	}
}

