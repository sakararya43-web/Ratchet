package graph_test

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/graph"
	"pgregory.net/rapid"
)

// The reference computes a fixed point by repeatedly scanning the logical edge
// list. It does not use CSR, production traversal helpers or production queries.
func reference(data graph.Data, identity string) ([]string, []graph.Power) {
	seen := map[string]bool{identity: true}
	controlled := map[string]bool{}
	powers := map[graph.Power]bool{}
	kinds := map[string]string{}
	for _, n := range data.Nodes {
		kinds[n.ID] = n.Type
	}
	for changed := true; changed; {
		changed = false
		for _, e := range data.Edges {
			if !seen[e.Source] {
				continue
			}
			walk := false
			switch e.Kind {
			case "MEMBER_OF", "ASSIGNED":
				walk = true
			case "CAN_ADMINISTER", "CAN_ASSUME":
				walk = true
				controlled[e.Target] = true
				powers[graph.Power{NodeID: e.Target, Action: "takeover"}] = true
			case "CAN_MODIFY":
				walk = true
				powers[graph.Power{NodeID: e.Target, Action: "modify"}] = true
			case "GRANTS":
				powers[graph.Power{NodeID: e.Target, Action: e.Action}] = true
				walk = kinds[e.Target] == "Permission" || kinds[e.Target] == "Credential" || kinds[e.Target] == "Session"
			}
			if walk && !seen[e.Target] {
				seen[e.Target] = true
				changed = true
			}
		}
	}
	for _, e := range data.Edges {
		if e.Kind == "DENIES" && seen[e.Source] {
			for p := range powers {
				if p.NodeID == e.Target && (p.Action == e.Action || e.Action == "*") {
					delete(powers, p)
				}
			}
		}
	}
	delete(controlled, identity)
	c := []string{}
	p := []graph.Power{}
	for id := range controlled {
		c = append(c, id)
	}
	for power := range powers {
		p = append(p, power)
	}
	slices.Sort(c)
	slices.SortFunc(p, func(a, b graph.Power) int {
		if a.NodeID < b.NodeID {
			return -1
		}
		if a.NodeID > b.NodeID {
			return 1
		}
		if a.Action < b.Action {
			return -1
		}
		if a.Action > b.Action {
			return 1
		}
		return 0
	})
	return c, p
}

func TestCSRMatchesIndependentFixedPoint(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		seed := rapid.Uint64().Draw(t, "seed")
		r := rand.New(rand.NewPCG(seed, 20261104))
		data := graph.Data{}
		for i := 0; i < 12; i++ {
			kind := "Human"
			if i >= 4 && i < 8 {
				kind = "Role"
			}
			if i >= 8 {
				kind = "Resource"
			}
			data.Nodes = append(data.Nodes, graph.Node{ID: fmt.Sprintf("n:%d", i), Type: kind, Tier: 2})
		}
		for i := 0; i < 80; i++ {
			source := r.IntN(8)
			target := r.IntN(12)
			e := graph.Edge{ID: fmt.Sprintf("e:%d", i), Source: fmt.Sprintf("n:%d", source), Target: fmt.Sprintf("n:%d", target)}
			if target < 4 {
				e.Kind = "CAN_ADMINISTER"
			} else if target < 8 {
				e.Kind = "ASSIGNED"
				if r.IntN(2) == 0 {
					e.Kind = "CAN_MODIFY"
				}
			} else {
				e.Kind = "GRANTS"
				e.Action = "read"
				if r.IntN(8) == 0 {
					e.Kind = "DENIES"
				}
			}
			data.Edges = append(data.Edges, e)
		}
		s, err := graph.Build(1, data)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			id := fmt.Sprintf("n:%d", i)
			control, powers := reference(data, id)
			got, err := s.Reach(id)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(control, got.Controlled) || !reflect.DeepEqual(powers, got.Powers) {
				t.Fatalf("seed=%d identity=%s reference=%v,%v actual=%v,%v", seed, id, control, powers, got.Controlled, got.Powers)
			}
		}
	})
}

// Reproducible dataset: two humans, one role and 100,000 tier-2 resources,
// one unique grant per resource. This benchmarks analysis, not fixture loading.
func BenchmarkImpact100kEdges(b *testing.B) {
	data := graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "user:b", Type: "Human"}, {ID: "role:r", Type: "Role"}}}
	for i := 0; i < 100000; i++ {
		id := fmt.Sprintf("resource:%06d", i)
		data.Nodes = append(data.Nodes, graph.Node{ID: id, Type: "Resource", Tier: 2})
		data.Edges = append(data.Edges, graph.Edge{ID: fmt.Sprintf("grant:%06d", i), Source: "role:r", Target: id, Kind: "GRANTS", Action: "read"})
	}
	s, err := graph.Build(1, data)
	if err != nil {
		b.Fatal(err)
	}
	d, err := s.Draft("ROLE_ASSIGN", "user:b", "role:r")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := s.ImpactDiff(d); err != nil {
			b.Fatal(err)
		}
	}
}
