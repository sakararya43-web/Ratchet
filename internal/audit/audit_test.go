package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func TestOfflineVerifier_Comprehensive(t *testing.T) {
	digester := canon.New()

	// 1. Generate Authority Members
	authKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authBytes1, _ := x509.MarshalPKIXPublicKey(&authKey1.PublicKey)
	authKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authBytes2, _ := x509.MarshalPKIXPublicKey(&authKey2.PublicKey)

	baseTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

	genesis := trust.GenesisState{
		TenantID:   "tenant-demo",
		Epoch:      1,
		ThresholdM: 2,
		Members: []trust.AuthorityMember{
			{ActorID: "user:sec-lead-1", DisplayName: "Lead 1", PublicKey: authBytes1, EnrolledAt: baseTime.Add(-48 * time.Hour), IsActive: true},
			{ActorID: "user:sec-lead-2", DisplayName: "Lead 2", PublicKey: authBytes2, EnrolledAt: baseTime.Add(-48 * time.Hour), IsActive: true},
		},
	}

	// 2. Generate Passkey for Approver
	userKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	userBytes, _ := x509.MarshalPKIXPublicKey(&userKey.PublicKey)

	credHistory := []StoredCredentialRecord{
		{
			TenantID:     "tenant-demo",
			ActorID:      "user:sec-lead-1",
			CredentialID: []byte("cred-123"),
			PublicKey:    userBytes,
			EnrolledAt:   baseTime.Add(-24 * time.Hour),
			IsRevoked:    false,
		},
	}

	// 3. Build a sequence of 5 events
	var events []AuditEvent
	var currentHash ports.Digest

	for i := int64(1); i <= 5; i++ {
		evtTime := baseTime.Add(time.Duration(i) * time.Minute)
		evt := AuditEvent{
			Sequence:          i,
			Timestamp:         evtTime,
			TenantID:          "tenant-demo",
			EventType:         EventRequestSubmitted,
			ActorID:           "user:sec-lead-1",
			Action:            "SUBMIT",
			Payload:           map[string]any{"seq": i, "desc": "request description"},
			PreviousEventHash: currentHash,
		}

		// On event 2, attach a valid WebAuthn approval assertion
		if i == 2 {
			evt.EventType = EventApprovalRecorded
			changeDigest, _ := digester.Digest(map[string]any{"change_id": "chg-100", "target": "grant:role"})
			evt.Payload["change_digest"] = changeDigest.String()

			nonce := []byte("test-random-nonce-123456789012")
			expectedChallenge := approval.ComputeApprovalChallenge("tenant-demo", "user:sec-lead-1", changeDigest, nonce)

			clientData := map[string]any{
				"type":      "webauthn.get",
				"challenge": base64.RawURLEncoding.EncodeToString(expectedChallenge),
				"origin":    "http://localhost:3000",
			}
			clientDataJSON, _ := digester.Canonicalize(clientData)

			authData := make([]byte, 37)
			authData[32] = 0x05 // userPresent (0x01) | userVerified (0x04)

			clientDataHash := sha256.Sum256(clientDataJSON)
			sigData := append(authData, clientDataHash[:]...)
			sigDataHash := sha256.Sum256(sigData)
			sig, err := ecdsa.SignASN1(rand.Reader, userKey, sigDataHash[:])
			if err != nil {
				t.Fatalf("failed to sign approval assertion: %v", err)
			}

			evt.ApprovalAssertion = &ports.ApprovalSubmission{
				TenantID:          "tenant-demo",
				ActorID:           "user:sec-lead-1",
				CredentialID:      []byte("cred-123"),
				ClientDataJSON:    clientDataJSON,
				AuthenticatorData: authData,
				Signature:         sig,
				ChallengeNonce:    nonce,
			}
		}

		h, err := ComputeEventDigest(digester, currentHash, &evt)
		if err != nil {
			t.Fatalf("failed to compute event digest: %v", err)
		}
		evt.EventDigest = h
		currentHash = h
		events = append(events, evt)
	}

	// 4. Build a Merkle Checkpoint covering events 1..4
	var chkLeaves []ports.Digest
	for i := 0; i < 4; i++ {
		chkLeaves = append(chkLeaves, events[i].EventDigest)
	}
	merkleRoot := trust.ComputeMerkleRoot(chkLeaves)

	chkPayload := map[string]any{
		"algorithm":               "SHA-256",
		"epoch":                   int64(1),
		"from_sequence":           int64(1),
		"merkle_root":             merkleRoot.String(),
		"prior_checkpoint_digest": ports.Digest{}.String(),
		"tenant_id":               "tenant-demo",
		"to_sequence":             int64(4),
	}
	chkDigest, _ := digester.Digest(chkPayload)

	// Sign checkpoint with both authority members
	domainDigest := trust.ComputeCheckpointSigningDigest("tenant-demo", 1, chkDigest)
	sig1, _ := ecdsa.SignASN1(rand.Reader, authKey1, domainDigest[:])
	sig2, _ := ecdsa.SignASN1(rand.Reader, authKey2, domainDigest[:])

	checkpoint := trust.AuditCheckpoint{
		CheckpointID:          "chk-demo-1-4",
		TenantID:              "tenant-demo",
		Epoch:                 1,
		FromSequence:          1,
		ToSequence:            4,
		MerkleRoot:            merkleRoot,
		PriorCheckpointDigest: ports.Digest{},
		Algorithm:             "SHA-256",
		CheckpointDigest:      chkDigest,
		Signatures: []trust.MemberSignature{
			{ActorID: "user:sec-lead-1", Signature: sig1, SignedAt: time.Now().UTC()},
			{ActorID: "user:sec-lead-2", Signature: sig2, SignedAt: time.Now().UTC()},
		},
		SignedAt: time.Now().UTC(),
	}

	// Build master export bundle
	bundle := AuditExportBundle{
		TenantID:          "tenant-demo",
		ExportedAt:        time.Now().UTC(),
		Events:            events,
		Checkpoints:       []trust.AuditCheckpoint{checkpoint},
		Genesis:           genesis,
		CredentialHistory: credHistory,
	}

	verifier := NewOfflineVerifier()

	// Test 1: Full Happy Path
	t.Run("HappyPathFullVerification", func(t *testing.T) {
		rep, err := verifier.VerifyBundle(&bundle, VerifyOptions{
			PinnedGenesis: &genesis,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !rep.Valid {
			t.Fatalf("expected valid report, got errors: %v", rep.Errors)
		}
		if rep.EventsVerified != 5 {
			t.Errorf("expected 5 events verified, got %d", rep.EventsVerified)
		}
		if rep.ApprovalsVerified != 1 {
			t.Errorf("expected 1 approval verified, got %d", rep.ApprovalsVerified)
		}
		if rep.CheckpointsVerified != 1 {
			t.Errorf("expected 1 checkpoint verified, got %d", rep.CheckpointsVerified)
		}
		if rep.TipDigest != events[4].EventDigest {
			t.Errorf("expected tip digest %s, got %s", events[4].EventDigest, rep.TipDigest)
		}
	})

	// Test 2: Tampered Event Data
	t.Run("TamperedEventData", func(t *testing.T) {
		corrupted := bundle
		corrupted.Events = make([]AuditEvent, len(bundle.Events))
		copy(corrupted.Events, bundle.Events)
		corrupted.Events[2].Payload = map[string]any{"seq": int64(3), "desc": "FORGED TAMPERED DATA"}

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure on tampered event, but got valid")
		}
		if rep.OffendingSequence != 3 {
			t.Errorf("expected offending sequence 3, got %d", rep.OffendingSequence)
		}
	})

	// Test 3: Broken Sequence Numbering
	t.Run("BrokenSequenceNumbering", func(t *testing.T) {
		corrupted := bundle
		corrupted.Events = make([]AuditEvent, len(bundle.Events))
		copy(corrupted.Events, bundle.Events)
		corrupted.Events[3].Sequence = 99 // broke sequence

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure on broken sequence, got valid")
		}
	})

	// Test 4: Forged WebAuthn Approval Signature
	t.Run("ForgedApprovalSignature", func(t *testing.T) {
		corrupted := bundle
		corrupted.Events = make([]AuditEvent, len(bundle.Events))
		copy(corrupted.Events, bundle.Events)

		// Tamper assertion signature on event 2
		clonedSub := *corrupted.Events[1].ApprovalAssertion
		clonedSub.Signature = append([]byte(nil), clonedSub.Signature...)
		clonedSub.Signature[len(clonedSub.Signature)-1] ^= 0xFF
		corrupted.Events[1].ApprovalAssertion = &clonedSub

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure on forged approval assertion, got valid")
		}
		if rep.OffendingSequence != 2 {
			t.Errorf("expected offending sequence 2, got %d", rep.OffendingSequence)
		}
	})

	// Test 5: Tampered Checkpoint Merkle Root
	t.Run("TamperedCheckpointMerkleRoot", func(t *testing.T) {
		corrupted := bundle
		corrupted.Checkpoints = make([]trust.AuditCheckpoint, 1)
		corrupted.Checkpoints[0] = bundle.Checkpoints[0]
		corrupted.Checkpoints[0].MerkleRoot[0] ^= 0xFF

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure on corrupted Merkle root, got valid")
		}
	})

	// Test 6: Insufficient Checkpoint Signatures
	t.Run("InsufficientCheckpointSignatures", func(t *testing.T) {
		corrupted := bundle
		corrupted.Checkpoints = make([]trust.AuditCheckpoint, 1)
		corrupted.Checkpoints[0] = bundle.Checkpoints[0]
		// Retain only 1 of 2 required signatures
		corrupted.Checkpoints[0].Signatures = bundle.Checkpoints[0].Signatures[:1]

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure on insufficient checkpoint signatures, got valid")
		}
	})

	// Test 7: Truncation Detection with Expected Tip
	t.Run("TruncationDetection", func(t *testing.T) {
		// Expect tip to be event 3
		expectedTip := events[2].EventDigest
		rep, err := verifier.VerifyBundle(&bundle, VerifyOptions{
			PinnedGenesis:     &genesis,
			ExpectedTipDigest: &expectedTip,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure due to log truncation mismatch, got valid")
		}
		if rep.OffendingReference != "tip" {
			t.Errorf("expected offending reference 'tip', got %q", rep.OffendingReference)
		}
	})

	// Test 8: Revoked Credential Before Event Timestamp
	t.Run("RevokedCredentialBeforeEventTimestamp", func(t *testing.T) {
		corrupted := bundle
		corrupted.CredentialHistory = []StoredCredentialRecord{
			{
				TenantID:   "tenant-demo",
				ActorID:    "user:sec-lead-1",
				PublicKey:  userBytes,
				EnrolledAt: time.Now().Add(-12 * time.Hour),
				IsRevoked:  true, // Revoked!
			},
		}

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure due to revoked credential, got valid")
		}
		if rep.OffendingSequence != 2 {
			t.Errorf("expected offending sequence 2, got %d", rep.OffendingSequence)
		}
	})

	// Test 9: Broken Previous Event Hash Link
	t.Run("BrokenPreviousEventHashLink", func(t *testing.T) {
		corrupted := bundle
		corrupted.Events = make([]AuditEvent, len(bundle.Events))
		copy(corrupted.Events, bundle.Events)
		corrupted.Events[3].PreviousEventHash[0] ^= 0xFF

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure on broken prevHash link, got valid")
		}
		if rep.OffendingSequence != 4 {
			t.Errorf("expected offending sequence 4, got %d", rep.OffendingSequence)
		}
	})

	// Test 10: Removed Approval Assertion from Approval Event Rejected
	t.Run("RemovedApprovalAssertionRejected", func(t *testing.T) {
		corrupted := bundle
		corrupted.Events = make([]AuditEvent, len(bundle.Events))
		copy(corrupted.Events, bundle.Events)
		corrupted.Events[1].ApprovalAssertion = nil

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure when required approval assertion is removed, got valid")
		}
		if rep.OffendingSequence != 2 {
			t.Errorf("expected offending sequence 2, got %d", rep.OffendingSequence)
		}
	})

	// Test 11: Unenrolled Credential ID Rejected
	t.Run("UnenrolledCredentialIDRejected", func(t *testing.T) {
		corrupted := bundle
		corrupted.Events = make([]AuditEvent, len(bundle.Events))
		copy(corrupted.Events, bundle.Events)
		clonedSub := *corrupted.Events[1].ApprovalAssertion
		clonedSub.CredentialID = []byte("unenrolled-fake-credential-999")
		corrupted.Events[1].ApprovalAssertion = &clonedSub

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure for unenrolled credential ID, got valid")
		}
		if rep.OffendingSequence != 2 {
			t.Errorf("expected offending sequence 2, got %d", rep.OffendingSequence)
		}
	})

	// Test 12: Duplicate Policy Signatures Rejected
	t.Run("DuplicatePolicySignaturesRejected", func(t *testing.T) {
		corrupted := bundle
		policyBundle := &trust.PolicyBundle{
			ProposalID:    "prop-dup-1",
			TenantID:      "tenant-demo",
			BundleVersion: "v1.0.0",
			Epoch:         1,
			Description:   "Duplicate signature test policy",
			Modules:       map[string]string{"main.rego": "package main"},
			Data:          map[string]any{},
		}
		pDigest, err := digester.Digest(map[string]any{
			"bundle_version": policyBundle.BundleVersion,
			"data":           policyBundle.Data,
			"description":    policyBundle.Description,
			"epoch":          policyBundle.Epoch,
			"modules":        policyBundle.Modules,
			"tenant_id":      policyBundle.TenantID,
		})
		if err != nil {
			t.Fatal(err)
		}
		policyBundle.BundleDigest = pDigest
		domainDig := trust.ComputePolicySigningDigest("tenant-demo", 1, pDigest)
		sigAlice, _ := ecdsa.SignASN1(rand.Reader, authKey1, domainDig[:])

		// Duplicate signature from Alice
		policyBundle.Signatures = []trust.MemberSignature{
			{ActorID: "user:sec-lead-1", Signature: sigAlice, SignedAt: time.Now().UTC()},
			{ActorID: "user:sec-lead-1", Signature: sigAlice, SignedAt: time.Now().UTC()},
		}
		corrupted.PolicyHistory = []*trust.PolicyBundle{policyBundle}

		rep, err := verifier.VerifyBundle(&corrupted, VerifyOptions{PinnedGenesis: &genesis})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Valid {
			t.Fatalf("expected verification failure for duplicate policy signatures, got valid")
		}
	})
}
