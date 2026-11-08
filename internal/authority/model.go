// Package authority implements the independent passkey-governed Authority.
// Its database and runtime credentials are separate from the control plane.
package authority

import (
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

var ErrRefused = errors.New("Authority authorization or current artifact context refused")

type Bootstrap struct {
	Tenant     string   `json:"tenant_id"`
	Actors     []string `json:"actors"`
	Threshold  int      `json:"threshold"`
	RPID       string   `json:"rp_id"`
	Origin     string   `json:"origin"`
	CorePublic []byte   `json:"core_public_key"`
}

func (b Bootstrap) Validate() error {
	if b.Tenant == "" || b.Threshold < 1 || b.Threshold > len(b.Actors) || len(b.Actors) > 20 || b.RPID == "" || !strings.HasPrefix(b.Origin, "https://") || len(b.CorePublic) != 32 {
		return ErrRefused
	}
	seen := map[string]bool{}
	for _, actor := range b.Actors {
		if actor == "" || seen[actor] {
			return ErrRefused
		}
		seen[actor] = true
	}
	return nil
}

type Input struct {
	ID          string                   `json:"command_id"`
	Operation   string                   `json:"operation"`
	Epoch       int64                    `json:"expected_epoch"`
	Proposal    string                   `json:"proposal_id,omitempty"`
	Version     string                   `json:"bundle_version,omitempty"`
	Description string                   `json:"description,omitempty"`
	Modules     map[string]string        `json:"modules,omitempty"`
	Data        map[string]any           `json:"data,omitempty"`
	Threshold   int                      `json:"threshold,omitempty"`
	Members     []trust.AuthorityMember  `json:"members,omitempty"`
	Member      *trust.AuthorityMember   `json:"member,omitempty"`
	Proof       ports.ApprovalSubmission `json:"proof"`
}

type Preview struct {
	Input     Input        `json:"input"`
	Canonical []byte       `json:"canonical_input_json"`
	Digest    ports.Digest `json:"signing_digest"`
}

// Preparation and execution use the same exact input. Only the native assertion
// is excluded; its challenge binds this digest, tenant, actor and fresh nonce.
func InputDigest(tenant, actor string, input Input, store *trust.Store) (ports.Digest, error) {
	if id, err := uuid.Parse(input.ID); err != nil || id == uuid.Nil {
		return ports.Digest{}, ErrRefused
	}
	input.Proof = ports.ApprovalSubmission{}
	switch input.Operation {
	case "bundle_sign":
		p, err := store.GetProposal(input.Proposal)
		if err != nil || p.TenantID != tenant || p.Epoch != input.Epoch || p.Status != "PROPOSED" {
			return ports.Digest{}, ErrRefused
		}
		return ports.Digest(trust.ComputePolicySigningDigest(tenant, p.Epoch, p.BundleDigest)), nil
	case "registry_sign":
		for _, p := range store.ListRegistryProposals() {
			if p.ProposalID == input.Proposal && p.TenantID == tenant && p.CurrentEpoch == input.Epoch && p.Status == "PROPOSED" {
				return ports.Digest(trust.ComputeRegistrySigningDigest(tenant, p.CurrentEpoch, p.TargetEpoch, p.ProposalDigest)), nil
			}
		}
		return ports.Digest{}, ErrRefused
	case "enroll", "bundle_propose", "bundle_activate", "registry_propose", "registry_activate":
		return canon.New().Digest(struct {
			Domain, Tenant, Actor string
			Input                 Input
		}{"RATCHET_AUTHORITY_ACTION_V1", tenant, actor, input})
	default:
		return ports.Digest{}, ErrRefused
	}
}

func memberEqual(a, b trust.AuthorityMember) bool {
	x, e1 := canon.New().Digest(a)
	y, e2 := canon.New().Digest(b)
	return e1 == nil && e2 == nil && x == y
}

func signature(proof ports.ApprovalSubmission) trust.MemberSignature {
	return trust.MemberSignature{ActorID: proof.ActorID, CredentialID: proof.CredentialID, Signature: proof.Signature,
		ClientDataJSON: proof.ClientDataJSON, AuthenticatorData: proof.AuthenticatorData, ChallengeNonce: proof.ChallengeNonce}
}

func validMembers(members []trust.AuthorityMember, m int, candidates map[string]trust.AuthorityMember) error {
	if m < 1 || len(members) > 20 || len(members) == 0 {
		return ErrRefused
	}
	active := 0
	seen := map[string]bool{}
	credentials := [][]byte{}
	for _, member := range members {
		candidate, ok := candidates[member.ActorID]
		candidate.IsActive = member.IsActive
		if !ok || seen[member.ActorID] || !memberEqual(candidate, member) {
			return ErrRefused
		}
		seen[member.ActorID] = true
		for _, id := range credentials {
			if slices.Equal(id, member.CredentialID) {
				return ErrRefused
			}
		}
		credentials = append(credentials, member.CredentialID)
		if member.IsActive {
			active++
		}
	}
	if active < m {
		return ErrRefused
	}
	return nil
}
