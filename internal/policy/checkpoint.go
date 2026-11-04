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
	if r == nil || r.store == nil || candidate.Profile != ledger.CheckpointProfile {
		return ErrInvalid
	}
	expected := candidate.Checkpoint
	expectedDigest, err := ledger.CheckpointDigest(expected)
	if err != nil || expected.Algorithm != "SHA-256" || expected.FromSequence < 1 || expected.ToSequence < expected.FromSequence || expectedDigest != expected.CheckpointDigest {
		return ErrInvalid
	}
	if expected.Epoch != r.Epoch || returned.Epoch != expected.Epoch || returned.TenantID != expected.TenantID || returned.CheckpointID != expected.CheckpointID || returned.FromSequence != expected.FromSequence || returned.ToSequence != expected.ToSequence || returned.MerkleRoot != expected.MerkleRoot || returned.PriorCheckpointDigest != expected.PriorCheckpointDigest || returned.Algorithm != "SHA-256" {
		return ErrInvalid
	}
	digest, err := ledger.CheckpointDigest(returned)
	if err != nil || digest != expected.CheckpointDigest || returned.CheckpointDigest != digest {
		return ErrInvalid
	}
	verified := returned
	verified.Signatures = nil
	for _, signature := range returned.Signatures {
		if r.store.SignCheckpoint(&verified, signature) != nil {
			return ErrInvalid
		}
	}
	if r.store.VerifyCheckpointSignatures(&verified) != nil {
		return ErrInvalid
	}
	return nil
}
