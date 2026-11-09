package ports

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// Digest represents a 32-byte cryptographic digest (SHA-256).
type Digest [32]byte

// DigestFromBytes creates a Digest from a 32-byte slice.
func DigestFromBytes(b []byte) (Digest, error) {
	if len(b) != 32 {
		return Digest{}, fmt.Errorf("invalid digest length: got %d, expected 32", len(b))
	}
	var d Digest
	copy(d[:], b)
	return d, nil
}

// DigestFromHex parses a 64-character hexadecimal string into a Digest.
func DigestFromHex(s string) (Digest, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Digest{}, fmt.Errorf("invalid hex digest: %w", err)
	}
	return DigestFromBytes(b)
}

// String returns the 64-character lowercase hexadecimal representation of the Digest.
func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

// Bytes returns a slice copy of the 32-byte digest.
func (d Digest) Bytes() []byte {
	out := make([]byte, 32)
	copy(out, d[:])
	return out
}

// IsZero returns true if the digest is empty/uninitialized.
func (d Digest) IsZero() bool {
	return d == Digest{}
}

// ApprovalSubmission contains raw WebAuthn authentication response data
// submitted by an approver for cryptographic verification.
type ApprovalSubmission struct {
	TenantID          string `json:"tenant_id"`
	ActorID           string `json:"actor_id"`
	CredentialID      []byte `json:"credential_id"`
	ClientDataJSON    []byte `json:"client_data_json"`
	AuthenticatorData []byte `json:"authenticator_data"`
	Signature         []byte `json:"signature"`
	ChallengeNonce    []byte `json:"challenge_nonce"`
}

// VerifiedApproval is the outcome of a successful passkey verification.
type VerifiedApproval struct {
	TenantID     string    `json:"tenant_id"`
	ActorID      string    `json:"actor_id"`
	CredentialID []byte    `json:"credential_id"`
	VerifiedAt   time.Time `json:"verified_at"`
	UserVerified bool      `json:"user_verified"`
	ChangeDigest Digest    `json:"change_digest"`
}

// ApprovalVerifier is implemented by Half B (internal/approval).
// Called by Half A (internal/workflow).
// Checks that the passkey assertion is valid, comes from an enrolled RATCHET passkey,
// and signs exactly changeDigest. It does NOT check independence or quorum; Half A does.
type ApprovalVerifier interface {
	Verify(ctx context.Context, sub ApprovalSubmission, changeDigest Digest) (VerifiedApproval, error)
}

// ContainmentVerifier checks that the passkey assertion is valid, comes from an enrolled
// RATCHET passkey, and signs exactly the containment plan digest in the containment domain.
type ContainmentVerifier interface {
	VerifyContainment(ctx context.Context, sub ApprovalSubmission, planDigest Digest) (VerifiedApproval, error)
}

// VerifiedBundle contains the verified Rego policy modules and metadata
// after passing M-of-N signature verification against the approver registry.
type VerifiedBundle struct {
	BundleVersion string            `json:"bundle_version"`
	BundleDigest  Digest            `json:"bundle_digest"`
	Modules       map[string]string `json:"modules"`
	Data          map[string]any    `json:"data"`
	SignerIDs     []string          `json:"signer_ids"`
	VerifiedAt    time.Time         `json:"verified_at"`
}

// BundleVerifier is implemented by Half B (internal/trust).
// Called by Half A (internal/policy).
// Checks M-of-N signatures against the current approver registry and returns
// the Rego modules and data inside the bundle.
type BundleVerifier interface {
	Verify(ctx context.Context, raw []byte) (VerifiedBundle, error)
}

// Digester is implemented by Half B (internal/canon).
// Used by both halves and mirrored in TypeScript.
// Produces RFC 8785 canonical JSON, then computes SHA-256.
type Digester interface {
	Digest(v any) (Digest, error)
	Canonicalize(v any) ([]byte, error)
}

// PasskeyDeps provides dependencies required to mount passkey HTTP endpoints.
type PasskeyDeps struct {
	RPID       string
	RPOrigins  []string
	SessionAPI any // interface to authenticate caller session
}

// PasskeyHandlerFactory is implemented by Half B (internal/approval).
// Mounted by Half A (internal/api) at /api/passkeys/.
type PasskeyHandlerFactory func(deps PasskeyDeps) http.Handler

