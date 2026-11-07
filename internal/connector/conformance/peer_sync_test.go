//go:build peerintegration

package conformance_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector/conformance"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Run on an isolated combined checkout. A failing real adapter remains a failing
// integration gate; no expected-failure assertion hides incomplete acceptance.
func TestPeerSimulatorSnapshotConformance(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "sim.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(simserver.NewServer(store, "conformance-only-broker-token").Routes())
	defer server.Close()
	adapter := sim.NewAdapter(server.URL, "conformance-only-broker-token", "tenant-exchange-demo", "source")
	snapshot, err := adapter.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	wire := new(v1.GraphSnapshot)
	if err := protojson.Unmarshal(raw, wire); err != nil {
		t.Fatal(err)
	}
	t.Run("complete-envelope", func(t *testing.T) {
		if _, err := conformance.Snapshot(wire); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("graph-semantics", func(t *testing.T) {
		if _, err := conformance.Graph(wire); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("all-edge-endpoints-exist", func(t *testing.T) {
		nodes := map[string]bool{}
		for _, n := range wire.Nodes {
			nodes[n.Id] = true
		}
		for _, e := range wire.Edges {
			if !nodes[e.Source] || !nodes[e.Target] {
				t.Errorf("dangling %s edge: %s -> %s", e.Kind, e.Source, e.Target)
			}
		}
	})
	t.Run("session-state-retained", func(t *testing.T) {
		seed := domain.NewSeedOrgState()
		nodes := map[string]bool{}
		for _, n := range wire.Nodes {
			if n.Type == "Session" {
				nodes[n.Id] = true
			}
		}
		for _, session := range seed.Sessions {
			if !nodes[session.SessionID] {
				t.Errorf("target session omitted: %s", session.SessionID)
			}
		}
	})
	t.Run("grant-provenance-retained", func(t *testing.T) {
		for _, e := range wire.Edges {
			if e.Kind == "ASSIGNED" && e.Properties["grant_id"] == "" {
				t.Errorf("grant identity omitted: %s -> %s", e.Source, e.Target)
			}
		}
	})
}
