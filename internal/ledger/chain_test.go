package ledger_test

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestPeerCompatibleChainAndTampering(t *testing.T) {
	d := canon.New()
	c := ledger.Content{ActorID: "actor-ref", EventType: "CoreEvidenceRecorded", Payload: json.RawMessage(`{"format_version":1}`), Sequence: 1, TenantID: "exchange", Timestamp: "2026-11-04T08:00:00.123456Z"}
	entry, err := ledger.Build(d, ports.Digest{}, c)
	if err != nil {
		t.Fatal(err)
	}
	// This map and concatenation are the peer's public audit-v1 encoding, independent of Content's Go layout.
	wire, err := d.Canonicalize(map[string]any{"action": "", "actor_id": "actor-ref", "event_type": "CoreEvidenceRecorded", "payload": map[string]any{"format_version": 1}, "previous_event_hash": ports.Digest{}.String(), "sequence": 1, "target_identity": "", "tenant_id": "exchange", "timestamp": c.Timestamp})
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(append(make([]byte, 32), wire...)); entry.Hash != want {
		t.Fatal("chain does not match peer audit-v1 hash")
	}
	if _, err := ledger.Verify(d, entry, "exchange", 1, ports.Digest{}); err != nil {
		t.Fatal(err)
	}
	entry.Canonical[10] ^= 1
	if _, err := ledger.Verify(d, entry, "exchange", 1, ports.Digest{}); err == nil {
		t.Fatal("accepted tampered event")
	}
}

func TestRejectsUnreplayableTimestampAndSequence(t *testing.T) {
	for _, tc := range []struct {
		sequence int64
		stamp    string
	}{
		{0, "2026-11-04T08:00:00Z"},
		{ledger.MaxSafeInteger + 1, "2026-11-04T08:00:00Z"},
		{1, "2026-11-04T08:00:00.123456789Z"},
		{1, "2026-11-04T09:00:00+01:00"},
	} {
		_, err := ledger.Build(canon.New(), ports.Digest{}, ledger.Content{Sequence: tc.sequence, Timestamp: tc.stamp, TenantID: "exchange", EventType: "X", Payload: json.RawMessage(`{}`)})
		if err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
