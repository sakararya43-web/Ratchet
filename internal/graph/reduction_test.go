package graph_test

import (
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestReductionRefusesProtectiveMembershipAndAssetRelabeling(t *testing.T) {
	data := graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "protective-role", Type: "Role"}, {ID: "guard", Type: "Safeguard", Tier: 0, Properties: map[string]string{"guard_kind": "withdrawal_threshold_v1", "required_checks": "2", "threshold_usd": "1000"}}, {ID: "wallet", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{ID: "membership", Source: "human", Target: "protective-role", Kind: "ASSIGNED"}, {ID: "requirement", Source: "guard", Target: "protective-role", Kind: "REQUIRES_APPROVAL"}}}
	s, err := graph.Build(1, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range []graph.Delta{
		{EdgesRemoved: []string{"membership"}},
		{EdgesRemoved: []string{"requirement"}},
		{NodesRemoved: []string{"wallet"}},
		{NodesAdded: []graph.Node{{ID: "wallet", Type: "Resource", Tier: 3}}},
		{NodesAdded: []graph.Node{{ID: "guard", Type: "Role", Tier: 0}}},
	} {
		if safe, err := s.IsMonotonicReduction(delta); err == nil && safe {
			t.Fatal("structural weakening certified as a reduction", delta)
		}
	}
	node, err := s.Node("human")
	if err != nil {
		t.Fatal(err)
	}
	node.Properties = map[string]string{"disabled": "true"}
	if safe, err := s.IsMonotonicReduction(graph.Delta{NodesAdded: []graph.Node{node}}); err != nil || !safe {
		t.Fatal("account restriction not proved", err)
	}
}
func TestReductionRefusesDenyRemovalEvenWithoutAnImmediateGrant(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "wallet", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{ID: "deny", Source: "human", Target: "wallet", Kind: "DENIES", Action: "sign"}}})
	if err != nil {
		t.Fatal(err)
	}
	if safe, err := s.IsMonotonicReduction(graph.Delta{EdgesRemoved: []string{"deny"}}); err != nil || safe {
		t.Fatal("deny removal entered reduction path", err)
	}
}
