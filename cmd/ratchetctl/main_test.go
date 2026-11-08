package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/audit"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func createTestBundle(t *testing.T) (*audit.AuditExportBundle, *trust.GenesisState, ports.Digest, ports.Digest) {
	t.Helper()
	digester := canon.New()

	authKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authBytes1, _ := x509.MarshalPKIXPublicKey(&authKey1.PublicKey)
	authKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authBytes2, _ := x509.MarshalPKIXPublicKey(&authKey2.PublicKey)

	baseTime := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	tenantID := "tenant-offline-verify-demo"

	genesis := trust.GenesisState{
		TenantID:   tenantID,
		Epoch:      1,
		ThresholdM: 2,
		TotalN:     2,
		Members: []trust.AuthorityMember{
			{ActorID: "user:sec-lead-1", DisplayName: "Sec Lead 1", PublicKey: authBytes1, EnrolledAt: baseTime.Add(-48 * time.Hour), IsActive: true},
			{ActorID: "user:sec-lead-2", DisplayName: "Sec Lead 2", PublicKey: authBytes2, EnrolledAt: baseTime.Add(-48 * time.Hour), IsActive: true},
		},
	}

	userKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	userBytes, _ := x509.MarshalPKIXPublicKey(&userKey.PublicKey)

	credHistory := []audit.StoredCredentialRecord{
		{
			TenantID:   tenantID,
			ActorID:    "user:sec-lead-1",
			PublicKey:  userBytes,
			EnrolledAt: baseTime.Add(-24 * time.Hour),
			IsRevoked:  false,
		},
	}

	var events []audit.AuditEvent
	var currentHash ports.Digest

	for i := int64(1); i <= 3; i++ {
		evtTime := baseTime.Add(time.Duration(i) * time.Minute)
		evt := audit.AuditEvent{
			Sequence:          i,
			Timestamp:         evtTime,
			TenantID:          tenantID,
			EventType:         audit.EventRequestSubmitted,
			ActorID:           "user:sec-lead-1",
			Action:            "SUBMIT",
			Payload:           map[string]any{"sequence_index": i},
			PreviousEventHash: currentHash,
		}

		if i == 2 {
			evt.EventType = audit.EventApprovalRecorded
			changeDigest, _ := digester.Digest(map[string]any{"change_id": "chg-test-1", "action": "grant"})
			evt.Payload["change_digest"] = changeDigest.String()

			nonce := []byte("test-nonce-123456789012")
			expectedChallenge := approval.ComputeApprovalChallenge(tenantID, "user:sec-lead-1", changeDigest, nonce)

			clientData := map[string]any{
				"type":      "webauthn.get",
				"challenge": base64.RawURLEncoding.EncodeToString(expectedChallenge),
				"origin":    "http://localhost:3000",
			}
			clientDataJSON, _ := digester.Canonicalize(clientData)

			authData := make([]byte, 37)
			authData[32] = 0x05 // userPresent | userVerified

			clientDataHash := sha256.Sum256(clientDataJSON)
			sigData := append(authData, clientDataHash[:]...)
			sigDataHash := sha256.Sum256(sigData)
			sig, err := ecdsa.SignASN1(rand.Reader, userKey, sigDataHash[:])
			if err != nil {
				t.Fatalf("failed to sign approval: %v", err)
			}

			evt.ApprovalAssertion = &ports.ApprovalSubmission{
				TenantID:          tenantID,
				ActorID:           "user:sec-lead-1",
				ClientDataJSON:    clientDataJSON,
				AuthenticatorData: authData,
				Signature:         sig,
				ChallengeNonce:    nonce,
			}
		}

		digest, err := audit.ComputeEventDigest(digester, currentHash, &evt)
		if err != nil {
			t.Fatalf("failed to compute event digest: %v", err)
		}
		evt.EventDigest = digest
		events = append(events, evt)
		currentHash = digest
	}

	merkleRoot := trust.ComputeMerkleRoot([]ports.Digest{events[0].EventDigest, events[1].EventDigest, events[2].EventDigest})
	chkMetadata := map[string]any{
		"algorithm":               "SHA-256",
		"epoch":                   int64(1),
		"from_sequence":           int64(1),
		"merkle_root":             merkleRoot.String(),
		"prior_checkpoint_digest": ports.Digest{}.String(),
		"tenant_id":               tenantID,
		"to_sequence":             int64(3),
	}
	chkDigest, _ := digester.Digest(chkMetadata)

	signingDigest := trust.ComputeCheckpointSigningDigest(tenantID, 1, chkDigest)
	sig1, _ := ecdsa.SignASN1(rand.Reader, authKey1, signingDigest[:])
	sig2, _ := ecdsa.SignASN1(rand.Reader, authKey2, signingDigest[:])

	checkpoints := []trust.AuditCheckpoint{
		{
			CheckpointID:          "chk-001",
			TenantID:              tenantID,
			Epoch:                 1,
			FromSequence:          1,
			ToSequence:            3,
			MerkleRoot:            merkleRoot,
			PriorCheckpointDigest: ports.Digest{},
			CheckpointDigest:      chkDigest,
			Algorithm:             "SHA-256",
			SignedAt:              baseTime.Add(10 * time.Minute),
			Signatures: []trust.MemberSignature{
				{ActorID: "user:sec-lead-1", Signature: sig1, SignedAt: baseTime.Add(10 * time.Minute)},
				{ActorID: "user:sec-lead-2", Signature: sig2, SignedAt: baseTime.Add(10 * time.Minute)},
			},
		},
	}

	bundle := &audit.AuditExportBundle{
		TenantID:          tenantID,
		ExportedAt:        baseTime.Add(15 * time.Minute),
		Events:            events,
		Checkpoints:       checkpoints,
		Genesis:           genesis,
		CredentialHistory: credHistory,
	}

	return bundle, &genesis, currentHash, chkDigest
}

func TestRatchetctlAuditVerify_EndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	bundle, genesis, tipDigest, chkDigest := createTestBundle(t)

	bundlePath := filepath.Join(tempDir, "bundle.json")
	bundleBytes, _ := json.MarshalIndent(bundle, "", "  ")
	_ = os.WriteFile(bundlePath, bundleBytes, 0644)

	genesisPath := filepath.Join(tempDir, "genesis.json")
	genBytes, _ := json.MarshalIndent(genesis, "", "  ")
	_ = os.WriteFile(genesisPath, genBytes, 0644)

	t.Run("ValidBundleStandardTextOutput", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + bundlePath}, &stdout, &stderr)
		if code != ExitSuccess {
			t.Fatalf("expected ExitSuccess (0), got %d; stderr: %s", code, stderr.String())
		}
		outStr := stdout.String()
		if !bytes.Contains([]byte(outStr), []byte("Status:               VALID")) {
			t.Fatalf("expected report status VALID, got:\n%s", outStr)
		}
		if !bytes.Contains([]byte(outStr), []byte("Events Verified:      3")) {
			t.Fatalf("expected 3 events verified, got:\n%s", outStr)
		}
	})

	t.Run("ValidBundleWithPinnedGenesisAndExpectedAnchors", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{
			"--export-file=" + bundlePath,
			"--genesis-file=" + genesisPath,
			"--expected-tip=" + tipDigest.String(),
			"--expected-checkpoint=" + chkDigest.String(),
		}, &stdout, &stderr)
		if code != ExitSuccess {
			t.Fatalf("expected ExitSuccess (0), got %d; stderr: %s", code, stderr.String())
		}
	})

	t.Run("ValidBundleJSONOutputFormat", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{
			"--export-file=" + bundlePath,
			"--json",
		}, &stdout, &stderr)
		if code != ExitSuccess {
			t.Fatalf("expected ExitSuccess (0), got %d; stderr: %s", code, stderr.String())
		}
		var rep audit.VerificationReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("failed to parse JSON verification report: %v", err)
		}
		if !rep.Valid || rep.EventsVerified != 3 || rep.ApprovalsVerified != 1 || rep.CheckpointsVerified != 1 {
			t.Fatalf("unexpected report content: %+v", rep)
		}
	})

	t.Run("MissingExportFileFlag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{}, &stdout, &stderr)
		if code != ExitBadArgs {
			t.Fatalf("expected ExitBadArgs (1), got %d", code)
		}
	})

	t.Run("NonExistentExportFile", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + filepath.Join(tempDir, "does-not-exist.json")}, &stdout, &stderr)
		if code != ExitBadArgs {
			t.Fatalf("expected ExitBadArgs (1), got %d", code)
		}
	})

	t.Run("CorruptedExportJSON", func(t *testing.T) {
		corruptPath := filepath.Join(tempDir, "corrupt.json")
		_ = os.WriteFile(corruptPath, []byte("{invalid json"), 0644)
		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + corruptPath}, &stdout, &stderr)
		if code != ExitBadArgs {
			t.Fatalf("expected ExitBadArgs (1), got %d", code)
		}
	})

	t.Run("TamperedEventDigestDetected", func(t *testing.T) {
		var tamperedBundle audit.AuditExportBundle
		_ = json.Unmarshal(bundleBytes, &tamperedBundle)
		tamperedBundle.Events[1].Payload["injected"] = "tampered-unauthorized"

		tamperedPath := filepath.Join(tempDir, "tampered.json")
		b, _ := json.Marshal(tamperedBundle)
		_ = os.WriteFile(tamperedPath, b, 0644)

		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + tamperedPath}, &stdout, &stderr)
		if code != ExitSigFailed {
			t.Fatalf("expected ExitSigFailed (3) on tampered data, got %d", code)
		}
	})

	t.Run("InsufficientQuorumDetected", func(t *testing.T) {
		var quorumBundle audit.AuditExportBundle
		_ = json.Unmarshal(bundleBytes, &quorumBundle)
		// Drop one of the 2 required signatures
		quorumBundle.Checkpoints[0].Signatures = quorumBundle.Checkpoints[0].Signatures[:1]

		qPath := filepath.Join(tempDir, "insufficient-quorum.json")
		b, _ := json.Marshal(quorumBundle)
		_ = os.WriteFile(qPath, b, 0644)

		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + qPath}, &stdout, &stderr)
		if code != ExitQuorum {
			t.Fatalf("expected ExitQuorum (2) on insufficient quorum, got %d; stdout: %s", code, stdout.String())
		}
	})

	t.Run("TruncationDetectedViaExpectedTip", func(t *testing.T) {
		var truncBundle audit.AuditExportBundle
		_ = json.Unmarshal(bundleBytes, &truncBundle)
		truncBundle.Events = truncBundle.Events[:2] // Truncate last event
		truncPath := filepath.Join(tempDir, "truncated.json")
		b, _ := json.Marshal(truncBundle)
		_ = os.WriteFile(truncPath, b, 0644)

		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{
			"--export-file=" + truncPath,
			"--expected-tip=" + tipDigest.String(),
		}, &stdout, &stderr)
		if code != ExitSigFailed {
			t.Fatalf("expected ExitSigFailed (3) on truncation, got %d", code)
		}
	})

	t.Run("HistoricalCredentialRevokedAfterApprovalStillValid", func(t *testing.T) {
		var histBundle audit.AuditExportBundle
		_ = json.Unmarshal(bundleBytes, &histBundle)
		// Mark revoked, but with RevokedAt AFTER the approval event timestamp (12:02)
		revokedLater := histBundle.Events[1].Timestamp.Add(2 * time.Hour)
		histBundle.CredentialHistory[0].IsRevoked = true
		histBundle.CredentialHistory[0].RevokedAt = &revokedLater

		histPath := filepath.Join(tempDir, "hist-valid.json")
		b, _ := json.Marshal(histBundle)
		_ = os.WriteFile(histPath, b, 0644)

		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + histPath}, &stdout, &stderr)
		if code != ExitSuccess {
			t.Fatalf("expected ExitSuccess (0) for historical credential valid at event time, got %d; stdout: %s", code, stdout.String())
		}
	})

	t.Run("HistoricalCredentialRevokedBeforeApprovalRejected", func(t *testing.T) {
		var histBundle audit.AuditExportBundle
		_ = json.Unmarshal(bundleBytes, &histBundle)
		// Mark revoked BEFORE event timestamp (12:02)
		revokedEarlier := histBundle.Events[1].Timestamp.Add(-10 * time.Minute)
		histBundle.CredentialHistory[0].IsRevoked = true
		histBundle.CredentialHistory[0].RevokedAt = &revokedEarlier

		histPath := filepath.Join(tempDir, "hist-invalid.json")
		b, _ := json.Marshal(histBundle)
		_ = os.WriteFile(histPath, b, 0644)

		var stdout, stderr bytes.Buffer
		code := executeAuditVerify([]string{"--export-file=" + histPath}, &stdout, &stderr)
		if code != ExitSigFailed {
			t.Fatalf("expected ExitSigFailed (3) for credential revoked before event time, got %d", code)
		}
	})
}
