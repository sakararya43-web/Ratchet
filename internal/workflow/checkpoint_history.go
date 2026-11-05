package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

const CheckpointHistoryProfile = "RATCHET_CHECKPOINT_HISTORY_V1"

type CheckpointChainEvent struct {
	Canonical []byte       `json:"canonical_content"`
	Previous  ports.Digest `json:"previous_hash"`
	Hash      ports.Digest `json:"event_hash"`
}

// CheckpointHistory is a transport-independent handoff of the raw chain and
// checkpoint artifacts. It makes no claim to verify historical WebAuthn keys or
// replay every policy decision; those require their separate original evidence.
type CheckpointHistory struct {
	Profile     string                 `json:"profile"`
	Tenant      string                 `json:"tenant_id"`
	Events      []CheckpointChainEvent `json:"events"`
	Checkpoints []CheckpointRecord     `json:"checkpoints"`
}
type CheckpointHistoryResult struct {
	VerifiedEvents       int64        `json:"verified_events"`
	CoveredThrough       int64        `json:"checkpoint_covered_through"`
	LastCheckpointDigest ports.Digest `json:"last_checkpoint_digest"`
}

// VerifyCheckpointHistory requires independently obtained genesis and tip pins.
// Rehashing an invented history cannot replace either trust anchor. Accepted
// artifacts must account for every acceptance event in this complete prefix.
func VerifyCheckpointHistory(ctx context.Context, history CheckpointHistory, root, expectedTip ports.Digest) (CheckpointHistoryResult, error) {
	var result CheckpointHistoryResult
	if history.Profile != CheckpointHistoryProfile || history.Tenant == "" || root.IsZero() || expectedTip.IsZero() || len(history.Events) == 0 || len(history.Events) > 100000 || len(history.Checkpoints) == 0 || len(history.Checkpoints) > 1000 {
		return result, eventstore.ErrIntegrity
	}
	entries := make([]ledger.Entry, len(history.Events))
	contents := make([]ledger.Content, len(history.Events))
	prepared := map[ports.Digest]int64{}
	accepted := map[int64]ports.Digest{}
	var previous ports.Digest
	bytes := 0
	for i, event := range history.Events {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		bytes += len(event.Canonical)
		if len(event.Canonical) > 1<<20 || bytes > 64<<20 {
			return result, eventstore.ErrInvalid
		}
		entry := ledger.Entry{Canonical: event.Canonical, Previous: event.Previous, Hash: event.Hash}
		content, err := ledger.Verify(canon.New(), entry, history.Tenant, int64(i+1), previous)
		if err != nil {
			return result, eventstore.ErrIntegrity
		}
		entries[i], contents[i], previous = entry, content, entry.Hash
		if content.EventType != "AuditCheckpointPrepared" && content.EventType != "AuditCheckpointAccepted" {
			continue
		}
		var payload struct {
			Stream  string `json:"stream_id"`
			Version int64  `json:"stream_version"`
		}
		if json.Unmarshal(content.Payload, &payload) != nil || len(payload.Stream) != len("checkpoint:")+64 || payload.Stream[:len("checkpoint:")] != "checkpoint:" {
			return result, eventstore.ErrIntegrity
		}
		digest, err := ports.DigestFromHex(payload.Stream[len("checkpoint:"):])
		if err != nil {
			return result, eventstore.ErrIntegrity
		}
		if content.EventType == "AuditCheckpointPrepared" {
			if prepared[digest] != 0 || payload.Version != 1 {
				return result, eventstore.ErrIntegrity
			}
			prepared[digest] = content.Sequence
		} else {
			if payload.Version != 2 {
				return result, eventstore.ErrIntegrity
			}
			accepted[content.Sequence] = digest
		}
	}
	if previous != expectedTip || len(accepted) != len(history.Checkpoints) {
		return result, eventstore.ErrIntegrity
	}
	result.VerifiedEvents = int64(len(entries))
	var priorDigest, priorHash ports.Digest
	var lastReference int64
	for _, record := range history.Checkpoints {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		evidence := record.Evidence
		p, c := evidence.Proposal, evidence.Signed
		preparation := prepared[c.CheckpointDigest]
		if c.TenantID != history.Tenant || p.Root != root || c.FromSequence != result.CoveredThrough+1 || c.ToSequence < c.FromSequence || c.ToSequence > int64(len(entries)) || c.PriorCheckpointDigest != priorDigest || p.Candidate.PreviousEventHash != priorHash || record.ReferenceSequence <= lastReference || record.ReferenceSequence > int64(len(entries)) || preparation <= c.ToSequence || preparation >= record.ReferenceSequence || accepted[record.ReferenceSequence] != c.CheckpointDigest || p.CreatedAt.IsZero() || evidence.AcceptedAt.Before(p.CreatedAt) {
			return result, eventstore.ErrIntegrity
		}
		registry, err := policy.VerifyRegistry(p.RegistryProof, root, history.Tenant)
		if err != nil || registry.Digest != p.RegistryDigest || registry.VerifyCheckpoint(p.Candidate, c) != nil {
			return result, eventstore.ErrIntegrity
		}
		candidate, err := ledger.BuildCheckpoint(history.Tenant, c.Epoch, c.FromSequence, c.ToSequence, priorHash, priorDigest, entries[c.FromSequence-1:c.ToSequence])
		if err != nil {
			return result, eventstore.ErrIntegrity
		}
		expected, err := canon.New().Digest(candidate)
		if err != nil {
			return result, eventstore.ErrIntegrity
		}
		actual, err := canon.New().Digest(p.Candidate)
		if err != nil || actual != expected {
			return result, eventstore.ErrIntegrity
		}
		if err := checkpointFacts(eventstore.StoredEvent{Entry: entries[preparation-1]}, p); err != nil {
			return result, err
		}
		if err := checkpointFacts(eventstore.StoredEvent{Entry: entries[record.ReferenceSequence-1]}, evidence); err != nil {
			return result, err
		}
		preparedAt, err := time.Parse(time.RFC3339Nano, contents[preparation-1].Timestamp)
		if err != nil || p.CreatedAt.After(preparedAt) {
			return result, eventstore.ErrIntegrity
		}
		acceptedAt, err := time.Parse(time.RFC3339Nano, contents[record.ReferenceSequence-1].Timestamp)
		if err != nil || evidence.AcceptedAt.After(acceptedAt) {
			return result, eventstore.ErrIntegrity
		}
		result.CoveredThrough = c.ToSequence
		result.LastCheckpointDigest = c.CheckpointDigest
		priorDigest, priorHash, lastReference = c.CheckpointDigest, candidate.LastEventHash, record.ReferenceSequence
	}
	return result, nil
}
