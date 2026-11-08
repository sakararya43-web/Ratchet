package trust

import (
	"context"
	"errors"
	"slices"

	"github.com/sakararya43-web/Ratchet/internal/passkeyevidence"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// Passkey members never fall back to signing a raw hash. Their retained
// assertions bind a purpose-separated artifact digest, actor, tenant and nonce.
func verifyPasskeySignature(member AuthorityMember, signature MemberSignature, tenant string, digest ports.Digest) error {
	if len(member.CredentialID) == 0 || member.RPID == "" || len(member.Origins) == 0 || !slices.Equal(member.CredentialID, signature.CredentialID) || member.ActorID != signature.ActorID {
		return errors.New("exact enrolled Authority passkey required")
	}
	_, err := passkeyevidence.Verify(context.Background(), ports.ApprovalSubmission{
		TenantID: tenant, ActorID: signature.ActorID, CredentialID: signature.CredentialID,
		ClientDataJSON: signature.ClientDataJSON, AuthenticatorData: signature.AuthenticatorData,
		Signature: signature.Signature, ChallengeNonce: signature.ChallengeNonce,
	}, digest, member.PublicKey, member.RPID, member.Origins)
	return err
}
