package graph

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

func TestBoundedImpactMatchesAllPrincipalReference(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		seed := rapid.Uint64().Draw(t, "seed")
		r := rand.New(rand.NewPCG(seed, 20261105))
		data := Data{}
		for i := 0; i < 6; i++ {
			data.Nodes = append(data.Nodes, Node{ID: fmt.Sprintf("user:%d", i), Type: "Human"}, Node{ID: fmt.Sprintf("role:%d", i), Type: "Role"}, Node{ID: fmt.Sprintf("asset:%d", i), Type: "Resource", Tier: i % 4})
		}
		data.Nodes = append(data.Nodes, Node{ID: "guard", Type: "Safeguard", Tier: 0, Properties: map[string]string{"guard_kind": "withdrawal_threshold_v1", "required_checks": "2", "threshold_usd": "100"}})
		for i := 0; i < 6; i++ {
			data.Edges = append(data.Edges, Edge{ID: fmt.Sprintf("assignment:%d", i), Source: fmt.Sprintf("user:%d", i), Target: fmt.Sprintf("role:%d", r.IntN(6)), Kind: "ASSIGNED"})
			data.Edges = append(data.Edges, Edge{ID: fmt.Sprintf("grant:%d", i), Source: fmt.Sprintf("role:%d", i), Target: fmt.Sprintf("asset:%d", i), Kind: "GRANTS", Action: "read"})
			if r.IntN(2) == 0 {
				data.Edges = append(data.Edges, Edge{ID: fmt.Sprintf("control:%d", i), Source: fmt.Sprintf("user:%d", i), Target: fmt.Sprintf("user:%d", r.IntN(6)), Kind: "CAN_ASSUME"})
			}
			if r.IntN(2) == 0 {
				data.Edges = append(data.Edges, Edge{ID: fmt.Sprintf("deny:%d", i), Source: fmt.Sprintf("role:%d", i), Target: fmt.Sprintf("asset:%d", r.IntN(6)), Kind: "DENIES", Action: "read"})
			}
		}
		data.Edges = append(data.Edges, Edge{ID: "protection", Source: "asset:0", Target: "guard", Kind: "PROTECTED_BY"}, Edge{ID: "approval", Source: "asset:1", Target: "role:1", Kind: "REQUIRES_APPROVAL"})
		s, err := Build(1, data)
		if err != nil {
			t.Fatal(err)
		}
		var delta Delta
		switch r.IntN(5) {
		case 0:
			delta = Delta{EdgesAdded: []Edge{{ID: "new", Source: fmt.Sprintf("user:%d", r.IntN(6)), Target: fmt.Sprintf("role:%d", r.IntN(6)), Kind: "ASSIGNED"}}}
		case 1:
			delta = Delta{EdgesRemoved: []string{s.edges[r.IntN(len(s.edges))].ID}}
		case 2:
			delta = Delta{NodesAdded: []Node{{ID: fmt.Sprintf("user:%d", r.IntN(6)), Type: "Human", Properties: map[string]string{"disabled": "true"}}}}
		case 3:
			delta = Delta{NodesAdded: []Node{{ID: "guard", Type: "Safeguard", Tier: 0, Properties: map[string]string{"guard_kind": "withdrawal_threshold_v1", "required_checks": "1", "threshold_usd": "1000"}}}}
		case 4:
			delta = Delta{EdgesAdded: []Edge{{ID: "new", Source: fmt.Sprintf("role:%d", r.IntN(6)), Target: fmt.Sprintf("user:%d", r.IntN(6)), Kind: "CAN_ADMINISTER"}}}
		}
		got, gotErr := s.impactDiff(delta, true)
		want, wantErr := s.impactDiff(delta, false)
		if (gotErr == nil) != (wantErr == nil) || (gotErr == nil && !reflect.DeepEqual(got, want)) {
			t.Fatalf("seed %d: bounded %v %v reference %v %v", seed, got, gotErr, want, wantErr)
		}
	})
}

func TestEdgeOverlayKeepsSnapshotsIsolated(t *testing.T) {
	s, err := Build(1, Data{Nodes: []Node{{ID: "user", Type: "Human"}, {ID: "role", Type: "Role"}}})
	if err != nil {
		t.Fatal(err)
	}
	properties := map[string]string{"granted_by": "user"}
	after, err := s.Overlay(2, Delta{EdgesAdded: []Edge{{ID: "assignment", Source: "user", Target: "role", Kind: "ASSIGNED", Properties: properties}}})
	if err != nil {
		t.Fatal(err)
	}
	properties["granted_by"] = "changed"
	exported := after.Data()
	exported.Nodes[0].Type = "Resource"
	exported.Edges[0].Properties["granted_by"] = "changed"
	if len(s.edges) != 0 || after.edges[0].Properties["granted_by"] != "user" || after.nodes[0].Type == "Resource" {
		t.Fatal("overlay leaked mutable storage")
	}
}
