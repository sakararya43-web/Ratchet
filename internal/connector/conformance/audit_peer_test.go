//go:build peerintegration

package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/audit"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

// Exercise the actual peer verifier using the checked-in handoff evidence. This
// test remains a real failing gate if altered checkpoint metadata is accepted.
func TestPeerAuditVerifierCheckpointHandoffConformance(t *testing.T) {
	dir := "../../../testdata/audit/checkpoints"
	var pins struct {
		Root string `json:"genesis_digest"`
		Tip  string `json:"tip_digest"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pins); err != nil {
		t.Fatal(err)
	}
	root, err := ports.DigestFromHex(pins.Root)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := ports.DigestFromHex(pins.Tip)
	if err != nil {
		t.Fatal(err)
	}
	load := func(kind string) workflow.CheckpointHistory {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, kind+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var history workflow.CheckpointHistory
		if err := json.Unmarshal(raw, &history); err != nil {
			t.Fatal(err)
		}
		return history
	}
	valid := load("valid")
	registry, err := policy.VerifyRegistry(valid.Checkpoints[0].Evidence.Proposal.RegistryProof, root, valid.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	var proof policy.RegistryProof
	if err := json.Unmarshal(registry.Proof, &proof); err != nil {
		t.Fatal(err)
	}
	last := valid.Checkpoints[len(valid.Checkpoints)-1].Evidence.Signed.CheckpointDigest
	for _, kind := range []string{"valid", "missing-event", "duplicate-event", "reordered-events", "truncated-tail", "forged-signature", "wrong-prior-checkpoint", "missing-checkpoint", "rehashed-fork"} {
		t.Run(kind, func(t *testing.T) {
			history := load(kind)
			bundle := audit.AuditExportBundle{TenantID: history.Tenant, Genesis: proof.Genesis}
			for _, event := range history.Events {
				var content ledger.Content
				if err := json.Unmarshal(event.Canonical, &content); err != nil {
					t.Fatal(err)
				}
				stamp, err := time.Parse(time.RFC3339Nano, content.Timestamp)
				if err != nil {
					t.Fatal(err)
				}
				var payload map[string]any
				if err := json.Unmarshal(content.Payload, &payload); err != nil {
					t.Fatal(err)
				}
				bundle.Events = append(bundle.Events, audit.AuditEvent{Sequence: content.Sequence, Timestamp: stamp, TenantID: content.TenantID, EventType: content.EventType, ActorID: content.ActorID, TargetIdentity: content.TargetIdentity, Action: content.Action, Payload: payload, PreviousEventHash: event.Previous, EventDigest: event.Hash})
			}
			for _, record := range history.Checkpoints {
				bundle.Checkpoints = append(bundle.Checkpoints, record.Evidence.Signed)
			}
			report, err := audit.NewOfflineVerifier().VerifyBundle(&bundle, audit.VerifyOptions{PinnedGenesis: &proof.Genesis, ExpectedTipDigest: &tip, ExpectedCheckpointDigest: &last})
			if err != nil {
				t.Fatal(err)
			}
			if kind == "valid" {
				if !report.Valid || report.EventsVerified != 7 || report.CheckpointsVerified != 2 {
					t.Fatalf("actual peer rejected valid core handoff: %+v", report)
				}
			} else if report.Valid {
				t.Fatalf("actual peer accepted deliberately corrupted %s export", kind)
			}
		})
	}
}
