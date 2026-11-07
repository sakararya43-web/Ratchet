package policy

import (
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// VerifyCheckpoint verifies against the already root-verified historical
// registry. The peer's VerifyCheckpointSignatures counts signatures only, so
// every returned signature is first verified through its actual SignCheckpoint
// boundary, including membership and duplicate-signer checks.
func (r *Registry) VerifyCheckpoint(candidate ledger.CheckpointCandidate, returned trust.AuditCheckpoint) error {
	ready, err := r.CheckpointStatus(candidate, returned)
	if err != nil || !ready {
		return ErrInvalid
	}
	return nil
}

// CheckpointStatus verifies metadata and every supplied signature. A valid
// partial quorum is pending, not an accepted checkpoint or a malformed response.
func (r *Registry) CheckpointStatus(candidate ledger.CheckpointCandidate, returned trust.AuditCheckpoint) (bool, error) {
	if r == nil || r.store == nil || candidate.Profile != ledger.CheckpointProfile {
		return false, ErrInvalid
	}
	expected := candidate.Checkpoint
	expectedDigest, err := ledger.CheckpointDigest(expected)
	if err != nil || expected.Algorithm != "SHA-256" || expected.FromSequence < 1 || expected.ToSequence < expected.FromSequence || expectedDigest != expected.CheckpointDigest {
		return false, ErrInvalid
	}
	if expected.Epoch != r.Epoch || returned.Epoch != expected.Epoch || returned.TenantID != expected.TenantID || returned.CheckpointID != expected.CheckpointID || returned.FromSequence != expected.FromSequence || returned.ToSequence != expected.ToSequence || returned.MerkleRoot != expected.MerkleRoot || returned.PriorCheckpointDigest != expected.PriorCheckpointDigest || returned.Algorithm != "SHA-256" {
		return false, ErrInvalid
	}
	digest, err := ledger.CheckpointDigest(returned)
	if err != nil || digest != expected.CheckpointDigest || returned.CheckpointDigest != digest {
		return false, ErrInvalid
	}
	verified := returned
	verified.Signatures = nil
	for _, signature := range returned.Signatures {
		if r.store.SignCheckpoint(&verified, signature) != nil {
			return false, ErrInvalid
		}
	}
	if r.store.VerifyCheckpointSignatures(&verified) != nil {
		return false, nil
	}
	return true, nil
}
