package approval

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sakararya43-web/Ratchet/internal/passkeyevidence"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func ComputeApprovalChallenge(tenant, actor string, digest ports.Digest, nonce []byte) []byte {
	return passkeyevidence.Challenge(tenant, actor, digest, nonce)
}

// ApprovalVerifier implements ports.ApprovalVerifier using WebAuthn passkey assertions.
type ApprovalVerifier struct {
	webauthn *webauthn.WebAuthn
	store    *CredentialStore
}

// NewApprovalVerifier creates an ApprovalVerifier with initialized WebAuthn configuration.
func NewApprovalVerifier(store *CredentialStore, rpID string, rpOrigins []string) (*ApprovalVerifier, error) {
	if store == nil {
		return nil, fmt.Errorf("credential store required")
	}
	if rpID == "" {
		rpID = "localhost"
	}
	if len(rpOrigins) == 0 {
		rpOrigins = []string{"http://localhost:3000", "http://localhost:8080", "http://localhost:8085"}
	}

	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName:          "RATCHET Security Control Plane",
		RPID:                   rpID,
		RPOrigins:              rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	return &ApprovalVerifier{
		webauthn: w,
		store:    store,
	}, nil
}

// Verify implements ports.ApprovalVerifier.
// Validates that the passkey assertion comes from an enrolled RATCHET passkey and signs exactly changeDigest.
func (av *ApprovalVerifier) Verify(
	ctx context.Context,
	sub ports.ApprovalSubmission,
	changeDigest ports.Digest,
) (ports.VerifiedApproval, error) {
	if av.store == nil {
		return ports.VerifiedApproval{}, fmt.Errorf("credential store required")
	}
	user, err := av.store.User(ctx, sub.TenantID, sub.ActorID)
	if err != nil {
		return ports.VerifiedApproval{}, err
	}
	for _, credential := range user.Credentials {
		if hex.EncodeToString(credential.ID) == hex.EncodeToString(sub.CredentialID) {
			return passkeyevidence.Verify(ctx, sub, changeDigest, credential.PublicKey, av.webauthn.Config.RPID, av.webauthn.Config.RPOrigins)
		}
	}
	return ports.VerifiedApproval{}, fmt.Errorf("credential is not enrolled or has been revoked")
}

// VerifyContainment validates that the passkey assertion comes from an enrolled RATCHET passkey
// and signs exactly planDigest bound to the containment domain.
func (av *ApprovalVerifier) VerifyContainment(
	ctx context.Context,
	sub ports.ApprovalSubmission,
	planDigest ports.Digest,
) (ports.VerifiedApproval, error) {
	if av.store == nil {
		return ports.VerifiedApproval{}, fmt.Errorf("credential store required")
	}
	user, err := av.store.User(ctx, sub.TenantID, sub.ActorID)
	if err != nil {
		return ports.VerifiedApproval{}, err
	}
	for _, credential := range user.Credentials {
		if hex.EncodeToString(credential.ID) == hex.EncodeToString(sub.CredentialID) {
			return passkeyevidence.VerifyContainment(ctx, sub, planDigest, credential.PublicKey, av.webauthn.Config.RPID, av.webauthn.Config.RPOrigins)
		}
	}
	return ports.VerifiedApproval{}, fmt.Errorf("credential is not enrolled or has been revoked")
}
