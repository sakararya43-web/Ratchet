package trust

import (
	"time"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

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
