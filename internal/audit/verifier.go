package audit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// VerifyOptions configures the offline verifier.
type VerifyOptions struct {
	PinnedGenesis            *trust.GenesisState // If provided, bundle.Genesis must match
	ExpectedTipDigest        *ports.Digest       // If provided, verifies chain tip
	ExpectedCheckpointDigest *ports.Digest       // If provided, verifies inclusion of checkpoint
}

// VerificationReport contains structured evidence of the offline audit verification.
type VerificationReport struct {
	Valid               bool         `json:"valid"`
	TenantID            string       `json:"tenant_id"`
	EventsVerified      int          `json:"events_verified"`
	SequenceStart       int64        `json:"sequence_start"`
	SequenceEnd         int64        `json:"sequence_end"`
	TipDigest           ports.Digest `json:"tip_digest"`
	CheckpointsVerified int          `json:"checkpoints_verified"`
	ApprovalsVerified   int          `json:"approvals_verified"`
	OffendingSequence   int64        `json:"offending_sequence,omitempty"`
	OffendingReference  string       `json:"offending_reference,omitempty"`
	Errors              []string     `json:"errors,omitempty"`
	Warnings            []string     `json:"warnings,omitempty"`
	VerifiedAt          time.Time    `json:"verified_at"`
}

// OfflineVerifier executes cryptographically independent verification over exported audit bundles.
type OfflineVerifier struct {
	digester *canon.Digester
}

// NewOfflineVerifier creates a new offline verifier instance.
func NewOfflineVerifier() *OfflineVerifier {
	return &OfflineVerifier{
		digester: canon.New(),
	}
}

// VerifyBundle checks the cryptographic integrity of an entire exported audit bundle.
func (v *OfflineVerifier) VerifyBundle(bundle *AuditExportBundle, opts VerifyOptions) (*VerificationReport, error) {
	if bundle == nil {
		return &VerificationReport{Errors: []string{"audit bundle required"}}, nil
	}
	report := &VerificationReport{
		Valid:      false,
		TenantID:   bundle.TenantID,
		VerifiedAt: time.Now().UTC(),
	}

	if bundle.TenantID == "" {
		report.Errors = append(report.Errors, "bundle missing tenant_id")
		return report, nil
	}

	// 1. Validate Genesis against pinned genesis if provided
	genesis := &bundle.Genesis
	if opts.PinnedGenesis != nil {
		if opts.PinnedGenesis.TenantID != bundle.TenantID {
			report.Errors = append(report.Errors, fmt.Sprintf("pinned genesis tenant_id mismatch: expected %q, got %q", opts.PinnedGenesis.TenantID, bundle.TenantID))
			report.OffendingReference = "genesis"
			return report, nil
		}
		if opts.PinnedGenesis.ThresholdM != bundle.Genesis.ThresholdM ||
			len(opts.PinnedGenesis.Members) != len(bundle.Genesis.Members) {
			report.Errors = append(report.Errors, "bundle genesis does not match pinned genesis parameters")
			report.OffendingReference = "genesis"
			return report, nil
		}
		genesis = opts.PinnedGenesis
	}

	if len(genesis.Members) == 0 || genesis.ThresholdM <= 0 {
		report.Errors = append(report.Errors, "invalid genesis: empty members or non-positive threshold")
		report.OffendingReference = "genesis"
		return report, nil
	}

	// 2. Validate events sequence and unbroken hash chain
	if len(bundle.Events) == 0 {
		if len(bundle.Checkpoints) > 0 || opts.ExpectedTipDigest != nil || opts.ExpectedCheckpointDigest != nil {
			report.Errors = append(report.Errors, "empty log cannot satisfy evidence anchors")
			return report, nil
		}
		report.Warnings = append(report.Warnings, "empty event log in bundle")
		report.Valid = true
		return report, nil
	}

	report.SequenceStart = bundle.Events[0].Sequence
	report.SequenceEnd = bundle.Events[len(bundle.Events)-1].Sequence
	if report.SequenceStart != 1 {
		report.Errors = append(report.Errors, "full export must begin at sequence 1")
		return report, nil
	}

	var currentHash ports.Digest
	eventMap := make(map[int64]*AuditEvent)

	for i, evt := range bundle.Events {
		eventMap[evt.Sequence] = &bundle.Events[i]

		// Sequence order check: must start at 1 (or sequence start) and increment monotonically by 1
		expectedSeq := report.SequenceStart + int64(i)
		if evt.Sequence != expectedSeq {
			report.OffendingSequence = evt.Sequence
			report.OffendingReference = fmt.Sprintf("event-seq-%d", evt.Sequence)
			report.Errors = append(report.Errors, fmt.Sprintf("broken sequence numbering: expected %d, got %d", expectedSeq, evt.Sequence))
			return report, nil
		}

		if evt.TenantID != bundle.TenantID {
			report.OffendingSequence = evt.Sequence
			report.OffendingReference = fmt.Sprintf("event-seq-%d", evt.Sequence)
			report.Errors = append(report.Errors, fmt.Sprintf("event tenant_id %q does not match bundle tenant_id %q", evt.TenantID, bundle.TenantID))
			return report, nil
		}

		// Hash chain link check
		if evt.PreviousEventHash != currentHash {
			report.OffendingSequence = evt.Sequence
			report.OffendingReference = fmt.Sprintf("event-seq-%d", evt.Sequence)
			report.Errors = append(report.Errors, fmt.Sprintf("hash chain discontinuity at sequence %d: prevHash is %s, expected %s",
				evt.Sequence, evt.PreviousEventHash.String(), currentHash.String()))
			return report, nil
		}

		// Recompute event digest
		computedDigest, err := ComputeEventDigest(v.digester, currentHash, &evt)
		if err != nil {
			report.OffendingSequence = evt.Sequence
			report.OffendingReference = fmt.Sprintf("event-seq-%d", evt.Sequence)
			report.Errors = append(report.Errors, fmt.Sprintf("failed to compute event digest at sequence %d: %v", evt.Sequence, err))
			return report, nil
		}

		if computedDigest != evt.EventDigest {
			report.OffendingSequence = evt.Sequence
			report.OffendingReference = fmt.Sprintf("event-seq-%d", evt.Sequence)
			report.Errors = append(report.Errors, fmt.Sprintf("tampered event data at sequence %d: computed %s, recorded %s",
				evt.Sequence, computedDigest.String(), evt.EventDigest.String()))
			return report, nil
		}

		// Verify Approval Assertion if present on event
		if evt.ApprovalAssertion != nil {
			if err := v.verifyApprovalAssertion(evt, bundle.CredentialHistory); err != nil {
				report.OffendingSequence = evt.Sequence
				report.OffendingReference = fmt.Sprintf("approval-seq-%d", evt.Sequence)
				report.Errors = append(report.Errors, fmt.Sprintf("invalid approval assertion at sequence %d: %v", evt.Sequence, err))
				return report, nil
			}
			report.ApprovalsVerified++
		}

		currentHash = computedDigest
		report.EventsVerified++
	}

	report.TipDigest = currentHash

	// 3. Verify Checkpoints
	var priorCheckpoint ports.Digest
	var previousEnd int64
	for _, chk := range bundle.Checkpoints {
		// Signatures bind a recomputed metadata digest, never an unchecked
		// digest supplied alongside mutable range/link/algorithm fields.
		computed, err := v.digester.Digest(map[string]any{"algorithm": chk.Algorithm, "epoch": chk.Epoch, "from_sequence": chk.FromSequence, "merkle_root": chk.MerkleRoot.String(), "prior_checkpoint_digest": chk.PriorCheckpointDigest.String(), "tenant_id": chk.TenantID, "to_sequence": chk.ToSequence})
		if err != nil || computed != chk.CheckpointDigest || chk.Algorithm != "SHA-256" || chk.Epoch < 1 || chk.PriorCheckpointDigest != priorCheckpoint || chk.FromSequence != previousEnd+1 {
			report.OffendingReference = chk.CheckpointID
			report.Errors = append(report.Errors, "checkpoint metadata or history continuity mismatch")
			return report, nil
		}
		if chk.TenantID != bundle.TenantID {
			report.OffendingReference = chk.CheckpointID
			report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s tenant_id mismatch", chk.CheckpointID))
			return report, nil
		}

		// Sequence range bounds check
		if chk.FromSequence < report.SequenceStart || chk.ToSequence > report.SequenceEnd || chk.FromSequence > chk.ToSequence {
			report.OffendingReference = chk.CheckpointID
			report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s range [%d, %d] outside verified sequence range [%d, %d]",
				chk.CheckpointID, chk.FromSequence, chk.ToSequence, report.SequenceStart, report.SequenceEnd))
			return report, nil
		}

		// Reconstruct leaf digests for the checkpoint range
		var leaves []ports.Digest
		for seq := chk.FromSequence; seq <= chk.ToSequence; seq++ {
			ev, ok := eventMap[seq]
			if !ok {
				report.OffendingReference = chk.CheckpointID
				report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s references missing sequence %d", chk.CheckpointID, seq))
				return report, nil
			}
			leaves = append(leaves, ev.EventDigest)
		}

		computedMerkleRoot := trust.ComputeMerkleRoot(leaves)
		if computedMerkleRoot != chk.MerkleRoot {
			report.OffendingReference = chk.CheckpointID
			report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s Merkle root mismatch: computed %s, recorded %s",
				chk.CheckpointID, computedMerkleRoot.String(), chk.MerkleRoot.String()))
			return report, nil
		}

		// Verify Authority signatures
		validSigners := make(map[string]bool)
		for _, sig := range chk.Signatures {
			// Signer must be in genesis members
			var member *trust.AuthorityMember
			for i := range genesis.Members {
				if genesis.Members[i].ActorID == sig.ActorID && genesis.Members[i].IsActive {
					member = &genesis.Members[i]
					break
				}
			}
			if member == nil {
				report.OffendingReference = chk.CheckpointID
				report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s signed by unknown or inactive member %q", chk.CheckpointID, sig.ActorID))
				return report, nil
			}

			// Verify signature over domain-separated checkpoint digest
			domainDigest := trust.ComputeCheckpointSigningDigest(chk.TenantID, chk.Epoch, chk.CheckpointDigest)
			if err := verifyAuthoritySignature(member.PublicKey, domainDigest[:], chk.CheckpointDigest[:], sig.Signature); err != nil {
				report.OffendingReference = chk.CheckpointID
				report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s has invalid signature from %q: %v", chk.CheckpointID, sig.ActorID, err))
				return report, nil
			}
			validSigners[sig.ActorID] = true
		}

		if len(validSigners) < genesis.ThresholdM {
			report.OffendingReference = chk.CheckpointID
			report.Errors = append(report.Errors, fmt.Sprintf("checkpoint %s has insufficient signatures: got %d, required threshold %d",
				chk.CheckpointID, len(validSigners), genesis.ThresholdM))
			return report, nil
		}

		report.CheckpointsVerified++
		priorCheckpoint = chk.CheckpointDigest
		previousEnd = chk.ToSequence
	}

	// 4. Verify expected tip or expected checkpoint if supplied
	if opts.ExpectedTipDigest != nil {
		if *opts.ExpectedTipDigest != report.TipDigest {
			// Check if expected tip matches an earlier event in the chain (truncation)
			var matchedSeq int64 = -1
			for _, ev := range bundle.Events {
				if ev.EventDigest == *opts.ExpectedTipDigest {
					matchedSeq = ev.Sequence
					break
				}
			}

			if matchedSeq != -1 {
				report.OffendingReference = "tip"
				report.Errors = append(report.Errors, fmt.Sprintf("log truncation detected: expected tip %s was found at sequence %d, but bundle contains subsequent events ending at %d",
					opts.ExpectedTipDigest.String(), matchedSeq, report.SequenceEnd))
			} else {
				report.OffendingReference = "tip"
				report.Errors = append(report.Errors, fmt.Sprintf("tip digest mismatch: expected %s, got %s",
					opts.ExpectedTipDigest.String(), report.TipDigest.String()))
			}
			return report, nil
		}
	}

	if opts.ExpectedCheckpointDigest != nil {
		found := false
		for _, chk := range bundle.Checkpoints {
			if chk.CheckpointDigest == *opts.ExpectedCheckpointDigest {
				found = true
				break
			}
		}
		if !found {
			report.OffendingReference = "checkpoint"
			report.Errors = append(report.Errors, fmt.Sprintf("expected checkpoint %s not present in bundle", opts.ExpectedCheckpointDigest.String()))
			return report, nil
		}
	}

	report.Valid = true
	return report, nil
}

// verifyApprovalAssertion validates that an event's approval assertion matches historical credentials and canonical challenge.
func (v *OfflineVerifier) verifyApprovalAssertion(evt AuditEvent, credHistory []StoredCredentialRecord) error {
	sub := evt.ApprovalAssertion
	if sub == nil {
		return nil
	}

	// 1. Locate credential record
	var credRecord *StoredCredentialRecord
	for i := range credHistory {
		rec := &credHistory[i]
		if rec.TenantID == evt.TenantID && rec.ActorID == sub.ActorID {
			// Check temporal validity: must be enrolled on or before event timestamp
			if !rec.EnrolledAt.After(evt.Timestamp) {
				// If revoked, must NOT be revoked before event timestamp
				if rec.IsRevoked {
					// We treat actively revoked credentials as invalid for subsequent events
					continue
				}
				credRecord = rec
				break
			}
		}
	}

	if credRecord == nil {
		return fmt.Errorf("no valid historical credential found for actor %q at event time %s", sub.ActorID, evt.Timestamp.Format(time.RFC3339))
	}

	// 2. Extract change digest from event payload or target action
	var changeDigest ports.Digest
	if cdStr, ok := evt.Payload["change_digest"].(string); ok && cdStr != "" {
		parsed, err := ports.DigestFromHex(cdStr)
		if err == nil {
			changeDigest = parsed
		}
	}
	if changeDigest.IsZero() {
		// Digest the payload as fallback
		cd, err := v.digester.Digest(evt.Payload)
		if err != nil {
			return fmt.Errorf("failed to compute change digest from payload: %w", err)
		}
		changeDigest = cd
	}

	// 3. Verify challenge binding
	var expectedChallenge []byte
	if evt.Action == "CONFIRM_CONTAINMENT" || evt.EventType == EventContainmentExecuted {
		expectedChallenge = trust.ComputeContainmentChallenge(evt.TenantID, sub.ActorID, changeDigest, sub.ChallengeNonce)
	} else {
		expectedChallenge = approval.ComputeApprovalChallenge(evt.TenantID, sub.ActorID, changeDigest, sub.ChallengeNonce)
	}

	var clientData protocol.CollectedClientData
	if err := json.Unmarshal(sub.ClientDataJSON, &clientData); err != nil {
		return fmt.Errorf("malformed clientDataJSON: %w", err)
	}

	decodedChallenge, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		decodedChallenge, err = base64.URLEncoding.DecodeString(clientData.Challenge)
		if err != nil {
			return fmt.Errorf("invalid base64 challenge in clientDataJSON: %w", err)
		}
	}

	if hex.EncodeToString(decodedChallenge) != hex.EncodeToString(expectedChallenge) {
		return fmt.Errorf("challenge mismatch: passkey assertion does not bind to change digest %s", changeDigest.String())
	}

	// 4. Verify AuthenticatorData user presence
	if len(sub.AuthenticatorData) < 37 {
		return fmt.Errorf("authenticatorData too short (< 37 bytes)")
	}
	flags := sub.AuthenticatorData[32]
	if (flags & 0x01) == 0 {
		return fmt.Errorf("user presence flag not set in authenticatorData")
	}

	// 5. Verify cryptographic signature
	clientDataHash := sha256.Sum256(sub.ClientDataJSON)
	sigData := append(sub.AuthenticatorData, clientDataHash[:]...)
	sigDataHash := sha256.Sum256(sigData)

	pubKey, err := x509.ParsePKIXPublicKey(credRecord.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid stored public key: %w", err)
	}

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sigDataHash[:], sub.Signature) {
			return fmt.Errorf("cryptographic ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, 0, sigDataHash[:], sub.Signature); err != nil {
			return fmt.Errorf("cryptographic RSA signature verification failed: %w", err)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, sigData, sub.Signature) {
			return fmt.Errorf("cryptographic Ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	return nil
}

// verifyAuthoritySignature verifies an ECDSA ASN.1 signature over either domain-separated or raw digest.
func verifyAuthoritySignature(pkixBytes, domainDigest, rawDigest, signature []byte) error {
	pubKey, err := x509.ParsePKIXPublicKey(pkixBytes)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(pub, domainDigest, signature) {
			return nil
		}
		if ecdsa.VerifyASN1(pub, rawDigest, signature) {
			return nil
		}
		return fmt.Errorf("signature verification failed")
	default:
		return fmt.Errorf("unsupported authority key type: %T", pubKey)
	}
}

// FormatReportText returns a human-readable summary of the verification report.
func FormatReportText(rep *VerificationReport) string {
	var sb strings.Builder
	sb.WriteString("=== RATCHET AUDIT VERIFICATION REPORT ===\n")
	sb.WriteString(fmt.Sprintf("Status:               %s\n", map[bool]string{true: "VALID", false: "FAILED"}[rep.Valid]))
	sb.WriteString(fmt.Sprintf("Tenant:               %s\n", rep.TenantID))
	sb.WriteString(fmt.Sprintf("Events Verified:      %d\n", rep.EventsVerified))
	sb.WriteString(fmt.Sprintf("Sequence Range:       %d -> %d\n", rep.SequenceStart, rep.SequenceEnd))
	sb.WriteString(fmt.Sprintf("Chain Tip:            %s\n", rep.TipDigest.String()))
	sb.WriteString(fmt.Sprintf("Approvals Verified:   %d\n", rep.ApprovalsVerified))
	sb.WriteString(fmt.Sprintf("Checkpoints Verified: %d\n", rep.CheckpointsVerified))

	if len(rep.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range rep.Warnings {
			sb.WriteString(fmt.Sprintf("  - [WARNING] %s\n", w))
		}
	}

	if len(rep.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range rep.Errors {
			sb.WriteString(fmt.Sprintf("  - [FAIL] %s\n", e))
		}
		if rep.OffendingSequence > 0 {
			sb.WriteString(fmt.Sprintf("Offending Sequence:   %d\n", rep.OffendingSequence))
		}
		if rep.OffendingReference != "" {
			sb.WriteString(fmt.Sprintf("Offending Reference:  %s\n", rep.OffendingReference))
		}
	}
	sb.WriteString("=========================================\n")
	return sb.String()
}
