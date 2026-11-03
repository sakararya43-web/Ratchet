package audit

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// Event types
const (
	EventRequestSubmitted    = "REQUEST_SUBMITTED"
	EventApprovalRecorded    = "APPROVAL_RECORDED"
	EventCommandApplied      = "COMMAND_APPLIED"
	EventContainmentExecuted = "CONTAINMENT_EXECUTED"
	EventPolicyActivated     = "POLICY_ACTIVATED"
	EventCheckpointSigned    = "CHECKPOINT_SIGNED"
)

// AuditEvent represents a single immutable, hash-linked ledger record in RATCHET.
type AuditEvent struct {
	Sequence          int64                    `json:"sequence"`
	Timestamp         time.Time                `json:"timestamp"`
	TenantID          string                   `json:"tenant_id"`
	EventType         string                   `json:"event_type"`
	ActorID           string                   `json:"actor_id"`
	TargetIdentity    string                   `json:"target_identity,omitempty"`
	Action            string                   `json:"action,omitempty"`
	Payload           map[string]any           `json:"payload"`
	ApprovalAssertion *ports.ApprovalSubmission `json:"approval_assertion,omitempty"`
	PreviousEventHash ports.Digest             `json:"previous_event_hash"`
	EventDigest       ports.Digest             `json:"event_digest"`
}

// ComputeEventDigest calculates the hash-chain digest: H_i = SHA-256(H_{i-1} || canonicalJSON(EventContent))
func ComputeEventDigest(digester *canon.Digester, prevHash ports.Digest, event *AuditEvent) (ports.Digest, error) {
	// Canonicalize event payload excluding EventDigest itself
	content := map[string]any{
		"action":              event.Action,
		"actor_id":            event.ActorID,
		"event_type":          event.EventType,
		"payload":             event.Payload,
		"previous_event_hash": prevHash.String(),
		"sequence":            event.Sequence,
		"target_identity":     event.TargetIdentity,
		"tenant_id":           event.TenantID,
		"timestamp":           event.Timestamp.UTC().Format(time.RFC3339Nano),
	}

	canonBytes, err := digester.Canonicalize(content)
	if err != nil {
		return ports.Digest{}, fmt.Errorf("failed to canonicalize audit event content: %w", err)
	}

	h := sha256.New()
	h.Write(prevHash[:])
	h.Write(canonBytes)

	var out ports.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}

// StoredCredentialRecord captures an enrolled public key for historical verification.
type StoredCredentialRecord struct {
	TenantID   string    `json:"tenant_id"`
	ActorID    string    `json:"actor_id"`
	PublicKey  []byte    `json:"public_key"` // X.509 PKIX
	EnrolledAt time.Time `json:"enrolled_at"`
	IsRevoked  bool      `json:"is_revoked"`
}

// AuditExportBundle is the complete self-contained package exported for offline verification.
type AuditExportBundle struct {
	TenantID            string                   `json:"tenant_id"`
	ExportedAt          time.Time                `json:"exported_at"`
	Events              []AuditEvent             `json:"events"`
	Checkpoints         []trust.AuditCheckpoint  `json:"checkpoints"`
	Genesis             trust.GenesisState       `json:"genesis"`
	CredentialHistory   []StoredCredentialRecord `json:"credential_history"`
}
