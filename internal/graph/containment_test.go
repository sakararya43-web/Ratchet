package graph_test

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/graph"
	"pgregory.net/rapid"
)

func containmentGraph(t *testing.T) *graph.Snapshot {
	t.Helper()
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "finance", Type: "Role"}, {ID: "admin-a", Type: "Role"}, {ID: "admin-b", Type: "Role"}, {ID: "reports", Type: "Resource", Tier: 2}, {ID: "wallet-a", Type: "Resource", Tier: 0}, {ID: "wallet-b", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{ID: "finance-binding", Source: "human", Target: "finance", Kind: "ASSIGNED"}, {ID: "admin-binding-a", Source: "human", Target: "admin-a", Kind: "ASSIGNED"}, {ID: "admin-binding-b", Source: "human", Target: "admin-b", Kind: "ASSIGNED"}, {ID: "reports", Source: "finance", Target: "reports", Kind: "GRANTS", Action: "read"}, {ID: "sign-a", Source: "admin-a", Target: "wallet-a", Kind: "GRANTS", Action: "sign"}, {ID: "sign-b", Source: "admin-b", Target: "wallet-b", Kind: "GRANTS", Action: "sign"}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestWeightedSuperSinkCutsAllCriticalAssetsAndPreservesReports(t *testing.T) {
	s := containmentGraph(t)
	catalog := []graph.Revocation{{Kind: "ROLE_REVOKE", Target: "human", Access: "admin-a", Cost: 2}, {Kind: "ROLE_REVOKE", Target: "human", Access: "admin-b", Cost: 3}, {Kind: "RESTRICT_ACCOUNT", Target: "human", Cost: 100}}
	p, err := s.PlanContainment(context.Background(), []string{"human"}, catalog, 100)
	if err != nil || !p.MinimumProved || p.Cost != 5 || len(p.Actions) != 2 || p.Algorithm != "weighted-min-cut" {
		t.Fatal("minimum weighted super-sink cut", p, err)
	}
	after, _, err := s.ApplyRevocations(p.Actions)
	if err != nil {
		t.Fatal(err)
	}
	reach, err := after.Reach("human")
	if err != nil || reach.ByTier[0] != 0 || reach.ByTier[2] != 1 {
		t.Fatal("critical access or continuity proof failed", err)
	}
	if len(p.Preserved) != 1 || p.Preserved[0].Resource != "reports" || len(p.Removed) != 0 {
		t.Fatal("business activity report", p)
	}
}
func TestSharedServiceGrantCostsOnceAndRetainsSeparateGrant(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "service", Type: "ServiceAccount"}, {ID: "wallet-a", Type: "Resource", Tier: 0}, {ID: "wallet-b", Type: "Resource", Tier: 0}, {ID: "reports", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{ID: "a", Source: "service", Target: "wallet-a", Kind: "GRANTS", Action: "sign", Properties: map[string]string{"grant_id": "shared"}}, {ID: "b", Source: "service", Target: "wallet-b", Kind: "GRANTS", Action: "sign", Properties: map[string]string{"grant_id": "shared"}}, {ID: "report", Source: "service", Target: "reports", Kind: "GRANTS", Action: "read", Properties: map[string]string{"grant_id": "finance"}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PlanContainment(context.Background(), []string{"service"}, []graph.Revocation{{Kind: "REMOVE_SERVICE_PERMISSION", Target: "service", Access: "shared", Cost: 2}, {Kind: "RESTRICT_ACCOUNT", Target: "service", Cost: 50}}, 100)
	if err != nil || !p.MinimumProved || p.Cost != 2 || len(p.Delta.EdgesRemoved) != 2 || len(p.Preserved) != 1 {
		t.Fatal("shared grant cost/effects", p, err)
	}
}
func TestNonlinearContainmentDisclosesBoundedOptimality(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "session", Type: "Session"}, {ID: "service", Type: "ServiceAccount"}, {ID: "wallet", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{Source: "human", Target: "session", Kind: "GRANTS", Action: "use"}, {Source: "session", Target: "service", Kind: "CAN_ASSUME"}, {Source: "service", Target: "wallet", Kind: "GRANTS", Action: "sign"}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog := []graph.Revocation{{Kind: "TERMINATE_SESSION", Target: "session", Cost: 1}, {Kind: "RESTRICT_ACCOUNT", Target: "human", Cost: 100}}
	bounded, err := s.PlanContainment(context.Background(), []string{"human"}, catalog, 1)
	if err != nil || bounded.MinimumProved || bounded.Algorithm != "verified-bounded-alternative" || bounded.Checks > 1 {
		t.Fatal("unproved optimum advertised", bounded, err)
	}
	exact, err := s.PlanContainment(context.Background(), []string{"human"}, catalog, 100)
	if err != nil || !exact.MinimumProved || exact.Cost != 1 {
		t.Fatal("small exact search", exact, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.PlanContainment(cancelled, []string{"human"}, catalog, 100); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled analysis continued", err)
	}
}
func TestProtectedCatalogCannotProduceInventedContainment(t *testing.T) {
	s := containmentGraph(t)
	if _, err := s.PlanContainment(context.Background(), []string{"human"}, []graph.Revocation{{Kind: "RESTRICT_ACCOUNT", Target: "human", Cost: 1, Protected: true}}, 100); !errors.Is(err, graph.ErrNoContainment) {
		t.Fatal("unexecutable plan returned", err)
	}
}
func TestOptimisticFlowCutIsRejectedByRealTakeoverSemantics(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "service", Type: "ServiceAccount"}, {ID: "wallet", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{Source: "human", Target: "service", Kind: "CAN_ASSUME"}, {Source: "service", Target: "wallet", Kind: "GRANTS", Action: "sign", Properties: map[string]string{"grant_id": "permission"}}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog := []graph.Revocation{{Kind: "RESTRICT_ACCOUNT", Target: "service", Cost: 1}, {Kind: "REMOVE_SERVICE_PERMISSION", Target: "service", Access: "permission", Cost: 10}, {Kind: "RESTRICT_ACCOUNT", Target: "human", Cost: 100}}
	p, err := s.PlanContainment(context.Background(), []string{"human"}, catalog, 100)
	if err != nil || !p.MinimumProved || p.Cost != 10 || len(p.Actions) != 1 || p.Actions[0].Kind != "REMOVE_SERVICE_PERMISSION" {
		t.Fatal("linear approximation bypassed actual graph verification", p, err)
	}
}
func TestRandomLinearMinCutMatchesExhaustiveExecutableCatalog(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := containmentGraphForProperty(t)
		catalog := []graph.Revocation{{Kind: "ROLE_REVOKE", Target: "human", Access: "admin-a", Cost: int64(rapid.IntRange(1, 20).Draw(t, "a"))}, {Kind: "ROLE_REVOKE", Target: "human", Access: "admin-b", Cost: int64(rapid.IntRange(1, 20).Draw(t, "b"))}, {Kind: "RESTRICT_ACCOUNT", Target: "human", Cost: int64(rapid.IntRange(1, 50).Draw(t, "restriction"))}}
		best := int64(math.MaxInt64)
		for mask := 0; mask < 1<<len(catalog); mask++ {
			actions := []graph.Revocation{}
			var cost int64
			for i, a := range catalog {
				if mask&(1<<i) != 0 {
					actions = append(actions, a)
					cost += a.Cost
				}
			}
			after, _, err := s.ApplyRevocations(actions)
			if err != nil {
				continue
			}
			reach, err := after.Reach("human")
			if err != nil {
				t.Fatal(err)
			}
			if reach.ByTier[0] == 0 && cost < best {
				best = cost
			}
		}
		p, err := s.PlanContainment(context.Background(), []string{"human"}, catalog, 100)
		if err != nil || !p.MinimumProved || p.Cost != best {
			t.Fatal("min-cut differs from exhaustive oracle", p, best, err)
		}
	})
}
func containmentGraphForProperty(t *rapid.T) *graph.Snapshot {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "admin-a", Type: "Role"}, {ID: "admin-b", Type: "Role"}, {ID: "wallet-a", Type: "Resource", Tier: 0}, {ID: "wallet-b", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{Source: "human", Target: "admin-a", Kind: "ASSIGNED"}, {Source: "human", Target: "admin-b", Kind: "ASSIGNED"}, {Source: "admin-a", Target: "wallet-a", Kind: "GRANTS", Action: "sign"}, {Source: "admin-b", Target: "wallet-b", Kind: "GRANTS", Action: "sign"}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
