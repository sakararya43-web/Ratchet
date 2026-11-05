package workflow_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestCheckpointHistoryHandoffFixtures(t *testing.T) {
	dir := "../../testdata/audit/checkpoints"
	var pins struct {
		Root    string `json:"genesis_digest"`
		Tip     string `json:"tip_digest"`
		Events  int64  `json:"verified_events"`
		Covered int64  `json:"checkpoint_covered_through"`
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
	for _, kind := range []string{"valid", "changed-canonical", "missing-event", "duplicate-event", "reordered-events", "truncated-tail", "forged-signature", "wrong-prior-checkpoint", "missing-checkpoint", "rehashed-fork"} {
		t.Run(kind, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, kind+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var history workflow.CheckpointHistory
			if err := json.Unmarshal(raw, &history); err != nil {
				t.Fatal(err)
			}
			result, err := workflow.VerifyCheckpointHistory(context.Background(), history, root, tip)
			if kind == "valid" {
				if err != nil || result.VerifiedEvents != pins.Events || result.CoveredThrough != pins.Covered || result.LastCheckpointDigest != history.Checkpoints[1].Evidence.Signed.CheckpointDigest {
					t.Fatal("valid history verification", result, err)
				}
				if _, err := workflow.VerifyCheckpointHistory(context.Background(), history, ports.Digest{1}, tip); err == nil {
					t.Fatal("invented genesis accepted")
				}
				if _, err := workflow.VerifyCheckpointHistory(context.Background(), history, root, ports.Digest{2}); err == nil {
					t.Fatal("unwitnessed tip accepted")
				}
				canceled, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := workflow.VerifyCheckpointHistory(canceled, history, root, tip); err != context.Canceled {
					t.Fatal("cancellation ignored", err)
				}
			} else {
				if err == nil {
					t.Fatal("deliberately corrupted history accepted")
				}
				// Even an internally consistent fork with a substituted tip must fail the
				// original quorum's signed Merkle commitment, beyond the external tip check.
				if kind == "rehashed-fork" {
					if _, err := workflow.VerifyCheckpointHistory(context.Background(), history, root, history.Events[len(history.Events)-1].Hash); err == nil {
						t.Fatal("rehashed fork bypassed signed root")
					}
				}
			}
		})
	}
}
