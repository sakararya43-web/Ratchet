package trust

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strconv"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// AuditCheckpoint represents an Authority-signed Merkle checkpoint over an event sequence range.
type AuditCheckpoint struct {
	CheckpointID            string            `json:"checkpoint_id"`
	TenantID                string            `json:"tenant_id"`
	Epoch                   int64             `json:"epoch"`
	FromSequence            int64             `json:"from_sequence"`
	ToSequence              int64             `json:"to_sequence"`
	MerkleRoot              ports.Digest      `json:"merkle_root"`
	PriorCheckpointDigest   ports.Digest      `json:"prior_checkpoint_digest"`
	Algorithm               string            `json:"algorithm"` // e.g. "SHA-256"
	CheckpointDigest        ports.Digest      `json:"checkpoint_digest"`
	Signatures              []MemberSignature `json:"signatures"`
	SignedAt                time.Time         `json:"signed_at"`
}

// ComputeCheckpointSigningDigest produces a domain-separated hash binding the checkpoint to RATCHET_CHECKPOINT_V1:.
func ComputeCheckpointSigningDigest(tenantID string, epoch int64, checkpointDigest ports.Digest) [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainCheckpoint))
	h.Write([]byte(tenantID))
	h.Write([]byte(":epoch:"))
	h.Write([]byte(strconv.FormatInt(epoch, 10)))
	h.Write([]byte(":"))
	h.Write(checkpointDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeMerkleRoot computes a binary SHA-256 Merkle root over an ordered list of leaf digests.
func ComputeMerkleRoot(leaves []ports.Digest) ports.Digest {
	if len(leaves) == 0 {
		return ports.Digest{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	currentLevel := make([]ports.Digest, len(leaves))
	copy(currentLevel, leaves)

	for len(currentLevel) > 1 {
		var nextLevel []ports.Digest
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				h := sha256.New()
				h.Write(currentLevel[i][:])
				h.Write(currentLevel[i+1][:])
				var parent ports.Digest
				copy(parent[:], h.Sum(nil))
				nextLevel = append(nextLevel, parent)
			} else {
				// Duplicate last leaf if odd count
				h := sha256.New()
				h.Write(currentLevel[i][:])
				h.Write(currentLevel[i][:])
				var parent ports.Digest
				copy(parent[:], h.Sum(nil))
				nextLevel = append(nextLevel, parent)
			}
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// CreateCheckpoint builds and digests an AuditCheckpoint candidate.
func (s *Store) CreateCheckpoint(
	tenantID string,
	fromSeq, toSeq int64,
	eventDigests []ports.Digest,
	priorCheckpointDigest ports.Digest,
) (*AuditCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.genesis == nil {
		return nil, fmt.Errorf("authority genesis not initialized")
	}

	merkleRoot := ComputeMerkleRoot(eventDigests)

	payload := map[string]any{
		"algorithm":                 "SHA-256",
		"epoch":                     s.genesis.Epoch,
		"from_sequence":             fromSeq,
		"merkle_root":               merkleRoot.String(),
		"prior_checkpoint_digest":   priorCheckpointDigest.String(),
		"tenant_id":                 tenantID,
		"to_sequence":               toSeq,
	}

	digest, err := s.digester.Digest(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checkpoint digest: %w", err)
	}

	checkpointID := fmt.Sprintf("chk-%s-%d-%d", tenantID, fromSeq, toSeq)
	checkpoint := &AuditCheckpoint{
		CheckpointID:          checkpointID,
		TenantID:              tenantID,
		Epoch:                 s.genesis.Epoch,
		FromSequence:          fromSeq,
		ToSequence:            toSeq,
		MerkleRoot:            merkleRoot,
		PriorCheckpointDigest: priorCheckpointDigest,
		Algorithm:             "SHA-256",
		CheckpointDigest:      digest,
		Signatures:            nil,
		SignedAt:              time.Now().UTC(),
	}

	return checkpoint, nil
}

// SignCheckpoint adds an Authority member's signature over a checkpoint.
func (s *Store) SignCheckpoint(checkpoint *AuditCheckpoint, sig MemberSignature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.genesis == nil {
		return fmt.Errorf("authority genesis not initialized")
	}

	var member *AuthorityMember
	for i := range s.genesis.Members {
		if s.genesis.Members[i].ActorID == sig.ActorID && s.genesis.Members[i].IsActive {
			member = &s.genesis.Members[i]
			break
		}
	}
	if member == nil {
		return fmt.Errorf("signer %q is not an active Authority member", sig.ActorID)
	}

	for _, existing := range checkpoint.Signatures {
		if existing.ActorID == sig.ActorID {
			return fmt.Errorf("member %q has already signed this checkpoint", sig.ActorID)
		}
	}

	pubKey, err := x509.ParsePKIXPublicKey(member.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid member public key: %w", err)
	}

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		domainDigest := ComputeCheckpointSigningDigest(checkpoint.TenantID, checkpoint.Epoch, checkpoint.CheckpointDigest)
		if !ecdsa.VerifyASN1(pub, domainDigest[:], sig.Signature) {
			rawDigest := checkpoint.CheckpointDigest[:]
			if !ecdsa.VerifyASN1(pub, rawDigest, sig.Signature) {
				return fmt.Errorf("invalid checkpoint signature from %s", sig.ActorID)
			}
		}
	default:
		return fmt.Errorf("unsupported key type: %T", pubKey)
	}

	sig.SignedAt = time.Now().UTC()
	checkpoint.Signatures = append(checkpoint.Signatures, sig)
	return nil
}

// VerifyCheckpointSignatures checks that the checkpoint has collected sufficient valid signatures.
func (s *Store) VerifyCheckpointSignatures(checkpoint *AuditCheckpoint) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(checkpoint.Signatures) < s.genesis.ThresholdM {
		return fmt.Errorf("checkpoint quorum not met: got %d signatures, required %d",
			len(checkpoint.Signatures), s.genesis.ThresholdM)
	}
	return nil
}
