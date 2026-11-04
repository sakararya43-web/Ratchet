package ledger

import (
	"fmt"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

const CheckpointProfile = "RATCHET_LEDGER_CHECKPOINT_V1"

// CheckpointCandidate's profile fixes leaves to final event hashes in ascending
// sequence, binary SHA-256 parents and duplicate-last handling for odd levels.
// It contains no signing key and never calls an unsigned candidate a checkpoint.
type CheckpointCandidate struct {
	Profile           string                `json:"profile"`
	PreviousEventHash ports.Digest          `json:"previous_event_hash"`
	LastEventHash     ports.Digest          `json:"last_event_hash"`
	Checkpoint        trust.AuditCheckpoint `json:"checkpoint"`
}

func CheckpointDigest(c trust.AuditCheckpoint) (ports.Digest, error) {
	return canon.New().Digest(map[string]any{"algorithm": c.Algorithm, "epoch": c.Epoch, "from_sequence": c.FromSequence, "merkle_root": c.MerkleRoot.String(), "prior_checkpoint_digest": c.PriorCheckpointDigest.String(), "tenant_id": c.TenantID, "to_sequence": c.ToSequence})
}
func BuildCheckpoint(tenant string, epoch, from, to int64, previous, prior ports.Digest, entries []Entry) (CheckpointCandidate, error) {
	var candidate CheckpointCandidate
	if tenant == "" || epoch < 1 || epoch > 256 || from < 1 || to < from || to > MaxSafeInteger || int64(len(entries)) != to-from+1 || len(entries) > 100000 || (from == 1 && (!previous.IsZero() || !prior.IsZero())) || (from > 1 && prior.IsZero()) {
		return candidate, fmt.Errorf("invalid checkpoint range or predecessor")
	}
	leaves := make([]ports.Digest, 0, len(entries))
	head := previous
	for i, entry := range entries {
		if _, err := Verify(canon.New(), entry, tenant, from+int64(i), head); err != nil {
			return candidate, err
		}
		head = entry.Hash
		leaves = append(leaves, entry.Hash)
	}
	c := trust.AuditCheckpoint{CheckpointID: fmt.Sprintf("chk-%s-%d-%d", tenant, from, to), TenantID: tenant, Epoch: epoch, FromSequence: from, ToSequence: to, MerkleRoot: trust.ComputeMerkleRoot(leaves), PriorCheckpointDigest: prior, Algorithm: "SHA-256"}
	digest, err := CheckpointDigest(c)
	if err != nil {
		return candidate, err
	}
	c.CheckpointDigest = digest
	return CheckpointCandidate{CheckpointProfile, previous, head, c}, nil
}
