package graph_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func organization(t *testing.T) *graph.Snapshot {
	t.Helper()
	s, err := graph.Build(12, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "user:b", Type: "Human"}, {ID: "group:g", Type: "Group"}, {ID: "role:r", Type: "Role"}, {ID: "role:admin", Type: "Role"}, {ID: "wallet", Type: "Resource", Tier: 0}, {ID: "reports", Type: "Resource", Tier: 2}, {ID: "guard", Type: "Safeguard", Tier: 0}}, Edges: []graph.Edge{
		{Source: "user:a", Target: "group:g", Kind: "MEMBER_OF"}, {Source: "group:g", Target: "role:r", Kind: "ASSIGNED"},
		{Source: "role:r", Target: "user:b", Kind: "CAN_ADMINISTER"}, {Source: "user:b", Target: "role:r", Kind: "ASSIGNED"},
		{Source: "role:r", Target: "reports", Kind: "GRANTS", Action: "read"}, {Source: "role:admin", Target: "wallet", Kind: "GRANTS", Action: "sign"},
		{Source: "role:admin", Target: "guard", Kind: "CAN_MODIFY"}, {Source: "wallet", Target: "guard", Kind: "PROTECTED_BY"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIndirectControlRoleAdministrationAndSimulationIsolation(t *testing.T) {
	s := organization(t)
	control, err := s.ControlSet("user:a")
	if err != nil || !slices.Equal(control, []string{"user:b"}) {
		t.Fatalf("control=%v %v", control, err)
	}
	d := graph.Delta{EdgesAdded: []graph.Edge{{Source: "role:r", Target: "role:admin", Kind: "CAN_MODIFY"}}}
	impact, err := s.ImpactDiff(d)
	if err != nil {
		t.Fatal(err)
	}
	if impact.MonotonicReduction || len(impact.Affected) != 2 || len(impact.Weakened) != 1 {
		t.Fatalf("impact=%+v", impact)
	}
	for _, i := range impact.Affected {
		if len(i.NewResources) != 1 || i.NewResources[0].ID != "wallet" || len(i.NewRoutes) == 0 {
			t.Fatalf("missing wallet route: %+v", i)
		}
	}
	after, err := s.Overlay(13, d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := after.Reach("user:a")
	if err != nil || r.ByTier[0] != 1 {
		t.Fatalf("after=%+v %v", r, err)
	}
	r, err = s.Reach("user:a")
	if err != nil || r.ByTier[0] != 0 || s.Version() != 12 {
		t.Fatal("simulation mutated base")
	}
	data := s.Data()
	data.Nodes[0].ID = "mutated"
	if _, err := s.Node("user:a"); err != nil {
		t.Fatal("escaped mutable arrays")
	}
}

func TestDenyRemovalAndApprovalRemovalAreNotReductions(t *testing.T) {
	s := organization(t)
	d := graph.Delta{EdgesAdded: []graph.Edge{{ID: "grant", Source: "user:a", Target: "wallet", Kind: "GRANTS", Action: "read"}, {ID: "deny", Source: "group:g", Target: "wallet", Kind: "DENIES", Action: "read"}}}
	s, err := s.Overlay(13, d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Reach("user:a")
	if err != nil || r.ByTier[0] != 0 {
		t.Fatal("deny not enforced")
	}
	impact, err := s.ImpactDiff(graph.Delta{EdgesRemoved: []string{"deny"}})
	if err != nil || impact.MonotonicReduction || len(impact.Weakened) != 1 {
		t.Fatalf("deny removal=%+v %v", impact, err)
	}
}

func TestMissingNodesAndUnknownSemanticsFailClosed(t *testing.T) {
	s := organization(t)
	for _, edge := range []graph.Edge{{Source: "user:a", Target: "missing", Kind: "CAN_ASSUME"}, {Source: "user:a", Target: "wallet", Kind: "MYSTERY"}} {
		if _, err := s.Overlay(13, graph.Delta{EdgesAdded: []graph.Edge{edge}}); !errors.Is(err, graph.ErrInvalid) {
			t.Fatalf("accepted malformed edge: %v", err)
		}
	}
	if _, err := s.Reach("missing"); !errors.Is(err, graph.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestRegistryVersionWaitAndConcurrentSimulations(t *testing.T) {
	s := organization(t)
	registry, err := graph.NewRegistry(30 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Publish("tenant", s); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Get(context.Background(), "tenant", 13); !errors.Is(err, graph.ErrUnavailable) {
		t.Fatal("stale graph served")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			delta, err := s.Draft("ROLE_ASSIGN", "user:a", "role:admin")
			if err == nil {
				_, err = s.ImpactDiff(delta)
			}
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	registry.Invalidate("tenant")
	if _, err := registry.Get(context.Background(), "tenant", 0); !errors.Is(err, graph.ErrUnavailable) {
		t.Fatal("invalidated graph served")
	}
}
