package trust

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// Domain separation constants to prevent cross-action replay
const (
	DomainApproval     = "RATCHET_APPROVAL_V1:"
	DomainPolicyBundle = "RATCHET_POLICY_BUNDLE_V1:"
	DomainRegistry     = "RATCHET_REGISTRY_V1:"
	DomainContainment  = "RATCHET_CONTAINMENT_V1:"
	DomainCheckpoint   = "RATCHET_CHECKPOINT_V1:"
)

// ComputePolicySigningDigest produces a domain-separated hash binding tenant, epoch, and bundle digest.
func ComputePolicySigningDigest(tenantID string, epoch int64, bundleDigest ports.Digest) [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainPolicyBundle))
	h.Write([]byte(tenantID))
	h.Write([]byte(":epoch:"))
	h.Write([]byte(strconv.FormatInt(epoch, 10)))
	h.Write([]byte(":"))
	h.Write(bundleDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeRegistrySigningDigest produces a domain-separated hash binding tenant, current epoch, target epoch, and proposal.
func ComputeRegistrySigningDigest(tenantID string, currentEpoch, targetEpoch int64, proposalDigest ports.Digest) [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainRegistry))
	h.Write([]byte(tenantID))
	h.Write([]byte(fmt.Sprintf(":epochs:%d->%d:", currentEpoch, targetEpoch)))
	h.Write(proposalDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeContainmentChallenge produces a domain-separated WebAuthn challenge binding tenant, actor, plan digest, and nonce.
func ComputeContainmentChallenge(tenantID, actorID string, planDigest ports.Digest, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(DomainContainment))
	h.Write([]byte(tenantID))
	h.Write([]byte(":"))
	h.Write([]byte(actorID))
	h.Write([]byte(":"))
	h.Write(planDigest[:])
	h.Write([]byte(":"))
	h.Write(nonce)
	return h.Sum(nil)
}

// AuthorityMember represents a security leader enrolled during genesis or approved via quorum.
type AuthorityMember struct {
	ActorID     string    `json:"actor_id"`
	DisplayName string    `json:"display_name"`
	PublicKey   []byte    `json:"public_key"` // X.509 PKIX bytes
	EnrolledAt  time.Time `json:"enrolled_at"`
	IsActive    bool      `json:"is_active"`
}

// GenesisState records the immutable genesis ceremony of the Independent Security Authority.
type GenesisState struct {
	TenantID      string            `json:"tenant_id"`
	ThresholdM    int               `json:"threshold_m"`
	TotalN        int               `json:"total_n"`
	Epoch         int64             `json:"epoch"`
	Members       []AuthorityMember `json:"members"`
	GenesisDigest ports.Digest      `json:"genesis_digest"`
	InitializedAt time.Time         `json:"initialized_at"`
}

// MemberSignature stores a passkey signature from an Authority member over a proposal.
type MemberSignature struct {
	ActorID           string    `json:"actor_id"`
	Signature         []byte    `json:"signature"`
	SignedAt          time.Time `json:"signed_at"`
	ClientDataJSON    []byte    `json:"client_data_json,omitempty"`
	AuthenticatorData []byte    `json:"authenticator_data,omitempty"`
}

// PolicyBundle represents a governed Rego policy bundle protected by M-of-N signatures.
type PolicyBundle struct {
	ProposalID    string            `json:"proposal_id"`
	TenantID      string            `json:"tenant_id"`
	BundleVersion string            `json:"bundle_version"`
	Description   string            `json:"description"`
	Epoch         int64             `json:"epoch"`
	Modules       map[string]string `json:"modules"`
	Data          map[string]any    `json:"data"`
	BundleDigest  ports.Digest      `json:"bundle_digest"`
	Signatures    []MemberSignature `json:"signatures"`
	Status        string            `json:"status"` // PROPOSED, ACTIVE, SUPERSEDED
	ProposedAt    time.Time         `json:"proposed_at"`
	ActivatedAt   *time.Time        `json:"activated_at,omitempty"`
}

// RegistryProposal represents a proposed membership rotation or threshold change.
type RegistryProposal struct {
	ProposalID      string            `json:"proposal_id"`
	TenantID        string            `json:"tenant_id"`
	CurrentEpoch    int64             `json:"current_epoch"`
	TargetEpoch     int64             `json:"target_epoch"`
	ProposedM       int               `json:"proposed_m"`
	ProposedN       int               `json:"proposed_n"`
	ProposedMembers []AuthorityMember `json:"proposed_members"`
	ProposalDigest  ports.Digest      `json:"proposal_digest"`
	Signatures      []MemberSignature `json:"signatures"`
	Status          string            `json:"status"` // PROPOSED, ACTIVATED, SUPERSEDED
	ProposedAt      time.Time         `json:"proposed_at"`
	ActivatedAt     *time.Time        `json:"activated_at,omitempty"`
}

// RegistryHistoryEntry records a past or present epoch of Authority governance.
type RegistryHistoryEntry struct {
	Epoch       int64             `json:"epoch"`
	ThresholdM  int               `json:"threshold_m"`
	TotalN      int               `json:"total_n"`
	Members     []AuthorityMember `json:"members"`
	ActivatedAt time.Time         `json:"activated_at"`
	ApprovedBy  []string          `json:"approved_by"`
}
