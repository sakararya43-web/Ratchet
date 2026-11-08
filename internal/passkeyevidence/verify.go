package passkeyevidence

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"time"
)

func Challenge(tenantID, actorID string, changeDigest ports.Digest, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("RATCHET_APPROVAL_V1:"))
	h.Write([]byte(tenantID))
	h.Write([]byte(":"))
	h.Write([]byte(actorID))
	h.Write([]byte(":"))
	h.Write(changeDigest[:])
	h.Write([]byte(":"))
	h.Write(nonce)
	return h.Sum(nil)
}

func ContainmentChallenge(tenantID, actorID string, planDigest ports.Digest, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("RATCHET_CONTAINMENT_V1:"))
	h.Write([]byte(tenantID))
	h.Write([]byte(":"))
	h.Write([]byte(actorID))
	h.Write([]byte(":"))
	h.Write(planDigest[:])
	h.Write([]byte(":"))
	h.Write(nonce)
	return h.Sum(nil)
}

func Verify(ctx context.Context, sub ports.ApprovalSubmission, changeDigest ports.Digest, publicKey []byte, rpID string, origins []string) (ports.VerifiedApproval, error) {
	return verifyWithChallenge(ctx, sub, changeDigest, Challenge(sub.TenantID, sub.ActorID, changeDigest, sub.ChallengeNonce), publicKey, rpID, origins)
}

func VerifyContainment(ctx context.Context, sub ports.ApprovalSubmission, planDigest ports.Digest, publicKey []byte, rpID string, origins []string) (ports.VerifiedApproval, error) {
	return verifyWithChallenge(ctx, sub, planDigest, ContainmentChallenge(sub.TenantID, sub.ActorID, planDigest, sub.ChallengeNonce), publicKey, rpID, origins)
}

func verifyWithChallenge(ctx context.Context, sub ports.ApprovalSubmission, changeDigest ports.Digest, expectedChallenge []byte, publicKey []byte, rpID string, origins []string) (ports.VerifiedApproval, error) {
	if err := ctx.Err(); err != nil {
		return ports.VerifiedApproval{}, err
	}
	if len(publicKey) == 0 || rpID == "" || len(origins) == 0 || len(sub.ClientDataJSON) > 16384 || len(sub.AuthenticatorData) > 16384 || len(sub.Signature) > 16384 || len(sub.ChallengeNonce) < 16 || len(sub.ChallengeNonce) > 64 {
		return ports.VerifiedApproval{}, fmt.Errorf("invalid bounded approval context")
	}
	if sub.TenantID == "" || sub.ActorID == "" {
		return ports.VerifiedApproval{}, fmt.Errorf("missing tenant_id or actor_id in submission")
	}
	if changeDigest.IsZero() {
		return ports.VerifiedApproval{}, fmt.Errorf("cannot verify approval for zero change digest")
	}

	var clientData protocol.CollectedClientData
	if err := json.Unmarshal(sub.ClientDataJSON, &clientData); err != nil {
		return ports.VerifiedApproval{}, fmt.Errorf("malformed clientDataJSON: %w", err)
	}

	// In WebAuthn CollectedClientData, Challenge is base64url encoded
	decodedChallenge, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		decodedChallenge, err = base64.URLEncoding.DecodeString(clientData.Challenge)
		if err != nil {
			return ports.VerifiedApproval{}, fmt.Errorf("invalid challenge encoding in clientData: %w", err)
		}
	}

	if hex.EncodeToString(decodedChallenge) != hex.EncodeToString(expectedChallenge) {
		return ports.VerifiedApproval{}, fmt.Errorf("challenge mismatch: passkey assertion does not sign this change digest")
	}
	if err := clientData.Verify(base64.RawURLEncoding.EncodeToString(expectedChallenge), protocol.AssertCeremony, origins, nil, nil, protocol.TopOriginExplicitVerificationMode, false); err != nil {
		return ports.VerifiedApproval{}, fmt.Errorf("WebAuthn client context refused: %w", err)
	}

	// 3. Parse AuthenticatorData flags
	if len(sub.AuthenticatorData) < 37 {
		return ports.VerifiedApproval{}, fmt.Errorf("authenticatorData too short (< 37 bytes)")
	}
	flags := sub.AuthenticatorData[32]
	userPresent := (flags & 0x01) != 0
	userVerified := (flags & 0x04) != 0

	if !userPresent || !userVerified {
		return ports.VerifiedApproval{}, fmt.Errorf("user presence and verification are required")
	}
	var authenticator protocol.AuthenticatorData
	if err := authenticator.Unmarshal(sub.AuthenticatorData); err != nil {
		return ports.VerifiedApproval{}, err
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if err := authenticator.Verify(rpHash[:], nil, true, true); err != nil {
		return ports.VerifiedApproval{}, err
	}

	// 4. Verify cryptographic signature over AuthenticatorData || SHA-256(ClientDataJSON)
	clientDataHash := sha256.Sum256(sub.ClientDataJSON)
	sigData := append(append([]byte(nil), sub.AuthenticatorData...), clientDataHash[:]...)
	sigDataHash := sha256.Sum256(sigData)

	pubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		cose, parseErr := webauthncose.ParsePublicKey(publicKey)
		if parseErr != nil {
			return ports.VerifiedApproval{}, fmt.Errorf("invalid enrolled public key: %w", parseErr)
		}
		valid, verifyErr := webauthncose.VerifySignature(cose, sigData, sub.Signature)
		if verifyErr != nil || !valid {
			return ports.VerifiedApproval{}, fmt.Errorf("COSE assertion signature refused")
		}
		return ports.VerifiedApproval{TenantID: sub.TenantID, ActorID: sub.ActorID, CredentialID: append([]byte(nil), sub.CredentialID...), VerifiedAt: time.Now().UTC(), UserVerified: true, ChangeDigest: changeDigest}, nil
	}

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sigDataHash[:], sub.Signature) {
			return ports.VerifiedApproval{}, fmt.Errorf("cryptographic ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sigDataHash[:], sub.Signature); err != nil {
			return ports.VerifiedApproval{}, fmt.Errorf("cryptographic RSA signature verification failed: %w", err)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, sigData, sub.Signature) {
			return ports.VerifiedApproval{}, fmt.Errorf("cryptographic Ed25519 signature verification failed")
		}
	default:
		return ports.VerifiedApproval{}, fmt.Errorf("unsupported public key type %T", pubKey)
	}

	return ports.VerifiedApproval{
		TenantID:     sub.TenantID,
		ActorID:      sub.ActorID,
		CredentialID: sub.CredentialID,
		VerifiedAt:   time.Now().UTC(),
		UserVerified: userVerified,
		ChangeDigest: changeDigest,
	}, nil
}
