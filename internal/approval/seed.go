package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

var demoSeedNames = []struct {
	ActorID     string
	DisplayName string
	SeedWord    string
}{
	{ActorID: "user:sec-lead-1", DisplayName: "Alice Vance (Security Lead 1)", SeedWord: "ratchet-passkey-alice-lead-1"},
	{ActorID: "user:sec-lead-2", DisplayName: "Bob Chen (Security Lead 2)", SeedWord: "ratchet-passkey-bob-lead-2"},
	{ActorID: "user:finance-lead", DisplayName: "Priya Patel (Finance Lead)", SeedWord: "ratchet-passkey-priya-finance-lead"},
	{ActorID: "user:rahul", DisplayName: "Rahul Sharma", SeedWord: "ratchet-passkey-rahul-sharma"},
	{ActorID: "user:rahul-assistant", DisplayName: "Finance Intern (Rahul Assistant)", SeedWord: "ratchet-passkey-rahul-assistant"},
}

// DeriveDeterministicPrivateKey derives a deterministic ECDSA P-256 private key from a string seed.
func DeriveDeterministicPrivateKey(seed string) *ecdsa.PrivateKey {
	h := sha256.Sum256([]byte(seed))
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(h[:])
	priv.PublicKey.Curve = priv.Curve
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(h[:])
	return priv
}

// SeedDemoCredentials seeds known demo users with deterministic WebAuthn credentials.
func SeedDemoCredentials(store *CredentialStore, tenantID string) error {
	if tenantID == "" {
		tenantID = "tenant-exchange-demo"
	}

	for _, d := range demoSeedNames {
		priv := DeriveDeterministicPrivateKey(d.SeedWord)
		pubPKIX, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal pubkey for %s: %w", d.ActorID, err)
		}

		credID := sha256.Sum256([]byte("cred-id:" + d.ActorID))
		cred := &webauthn.Credential{
			ID:              credID[:16],
			PublicKey:       pubPKIX,
			AttestationType: "none",
			Authenticator: webauthn.Authenticator{
				AAGUID:    make([]byte, 16),
				SignCount: 1,
			},
		}

		err = store.SaveCredential(tenantID, d.ActorID, fmt.Sprintf("%s YubiKey", d.DisplayName), cred)
		if err != nil {
			return fmt.Errorf("failed to save credential for %s: %w", d.ActorID, err)
		}
	}

	return nil
}

// GenerateSimulatedAssertion creates a valid WebAuthn assertion submission for a known demo actor.
func GenerateSimulatedAssertion(
	tenantID, actorID string,
	changeDigest ports.Digest,
	rpID, origin string,
) (ports.ApprovalSubmission, error) {
	var seedWord string
	for _, d := range demoSeedNames {
		if d.ActorID == actorID {
			seedWord = d.SeedWord
			break
		}
	}
	if seedWord == "" {
		return ports.ApprovalSubmission{}, fmt.Errorf("unknown actor for simulated assertion: %s", actorID)
	}

	if rpID == "" {
		rpID = "localhost"
	}
	if origin == "" {
		origin = "http://localhost:3000"
	}

	priv := DeriveDeterministicPrivateKey(seedWord)
	credIDFull := sha256.Sum256([]byte("cred-id:" + actorID))
	credID := credIDFull[:16]

	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	boundChallenge := ComputeApprovalChallenge(tenantID, actorID, changeDigest, nonce)

	clientData := map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(boundChallenge),
		"origin":      origin,
		"crossOrigin": false,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return ports.ApprovalSubmission{}, fmt.Errorf("failed to marshal clientDataJSON: %w", err)
	}

	rpIdHash := sha256.Sum256([]byte(rpID))
	flags := byte(0x01 | 0x04) // UP | UV
	authData := make([]byte, 37)
	copy(authData[0:32], rpIdHash[:])
	authData[32] = flags
	authData[33] = 0 // signCount
	authData[34] = 0
	authData[35] = 0
	authData[36] = 2

	clientDataHash := sha256.Sum256(clientDataJSON)
	sigData := append(authData, clientDataHash[:]...)
	sigDataHash := sha256.Sum256(sigData)

	r, s, err := ecdsa.Sign(rand.Reader, priv, sigDataHash[:])
	if err != nil {
		return ports.ApprovalSubmission{}, fmt.Errorf("failed to sign assertion: %w", err)
	}

	asn1Sig, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		return ports.ApprovalSubmission{}, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return ports.ApprovalSubmission{
		TenantID:          tenantID,
		ActorID:           actorID,
		CredentialID:      credID,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: authData,
		Signature:         asn1Sig,
		ChallengeNonce:    nonce,
	}, nil
}
