package policy_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func TestCheckpointCandidatesVerifyEveryReturnedSignature(t *testing.T) {
	authority, root, keys, members := governed(t)
	registry, err := policy.RegistryFromStore(authority, root, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	entries := []ledger.Entry{}
	var previous ports.Digest
	for i := range 3 {
		entry, err := ledger.Build(canon.New(), previous, ledger.Content{TenantID: "tenant", Sequence: int64(i + 1), EventType: "CoreEvidence", Timestamp: time.Date(2026, 11, 5, 0, 0, i, 0, time.UTC).Format(time.RFC3339Nano), Payload: json.RawMessage(`{"format_version":1}`)})
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
		previous = entry.Hash
	}
	candidate, err := ledger.BuildCheckpoint("tenant", 1, 1, 3, ports.Digest{}, ports.Digest{}, entries)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Checkpoint.MerkleRoot != trust.ComputeMerkleRoot([]ports.Digest{entries[0].Hash, entries[1].Hash, entries[2].Hash}) {
		t.Fatal("wrong event-hash leaf encoding")
	}
	returned := candidate.Checkpoint
	d := trust.ComputeCheckpointSigningDigest("tenant", 1, returned.CheckpointDigest)
	for i := range 2 {
		sig, err := ecdsa.SignASN1(rand.Reader, keys[i], d[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := authority.SignCheckpoint(&returned, trust.MemberSignature{ActorID: members[i].ActorID, Signature: sig}); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.VerifyCheckpoint(candidate, returned); err != nil {
		t.Fatal("valid signed checkpoint", err)
	}
	for _, kind := range []string{"invalid-signatures", "duplicate", "missing-quorum", "wrong-range", "wrong-root", "wrong-prior"} {
		t.Run(kind, func(t *testing.T) {
			raw, err := json.Marshal(returned)
			if err != nil {
				t.Fatal(err)
			}
			var changed trust.AuditCheckpoint
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "invalid-signatures":
				for i := range changed.Signatures {
					changed.Signatures[i].Signature = []byte("invalid")
				}
			case "duplicate":
				changed.Signatures[1] = changed.Signatures[0]
			case "missing-quorum":
				changed.Signatures = changed.Signatures[:1]
			case "wrong-range":
				changed.ToSequence++
			case "wrong-root":
				changed.MerkleRoot = ports.Digest{9}
			case "wrong-prior":
				changed.PriorCheckpointDigest = ports.Digest{8}
			}
			if registry.VerifyCheckpoint(candidate, changed) == nil {
				t.Fatal("unverified checkpoint accepted")
			}
		})
	}
	if _, err := ledger.BuildCheckpoint("tenant", 1, 1, 3, ports.Digest{}, ports.Digest{}, entries[:2]); err == nil {
		t.Fatal("truncated range accepted")
	}
	swapped := []ledger.Entry{entries[1], entries[0], entries[2]}
	if _, err := ledger.BuildCheckpoint("tenant", 1, 1, 3, ports.Digest{}, ports.Digest{}, swapped); err == nil {
		t.Fatal("reordered leaves accepted")
	}
	if _, err := ledger.BuildCheckpoint("tenant", 1, 2, 3, entries[0].Hash, ports.Digest{}, entries[1:]); err == nil {
		t.Fatal("range omitted prior checkpoint")
	}
}
