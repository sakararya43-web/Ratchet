package workflow

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"pgregory.net/rapid"
)

// Independent logical-edge fixed point; it does not call graph reach/control or
// workflow eligibility. Generated control edges form a DAG to bound path counts.
func referenceAuthority(data graph.Data, identity string) (map[string]bool, map[string]bool) {
	seen := map[string]bool{identity: true}
	control := map[string]bool{}
	powers := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, e := range data.Edges {
			if !seen[e.Source] {
				continue
			}
			walk := e.Kind == "ASSIGNED" || e.Kind == "MEMBER_OF" || e.Kind == "CAN_MODIFY"
			if e.Kind == "CAN_ADMINISTER" || e.Kind == "CAN_ASSUME" {
				walk = true
				control[e.Target] = true
				powers[e.Target+"/takeover"] = true
			}
			if e.Kind == "CAN_MODIFY" {
				powers[e.Target+"/modify"] = true
			}
			if e.Kind == "GRANTS" {
				powers[e.Target+"/"+e.Action] = true
			}
			if walk && !seen[e.Target] {
				seen[e.Target] = true
				changed = true
			}
		}
	}
	for _, e := range data.Edges {
		if e.Kind == "DENIES" && seen[e.Source] {
			delete(powers, e.Target+"/"+e.Action)
		}
	}
	delete(control, identity)
	return control, powers
}
func TestRandomOrganizationsRejectDecidingSelfBenefitAndFalseReductions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		r := rand.New(rand.NewPCG(rapid.Uint64().Draw(t, "organization"), 20261105))
		data := graph.Data{}
		for i := range 5 {
			data.Nodes = append(data.Nodes, graph.Node{ID: fmt.Sprintf("human:%d", i), Type: "Human"})
		}
		for i := range 3 {
			data.Nodes = append(data.Nodes, graph.Node{ID: fmt.Sprintf("role:%d", i), Type: "Role"}, graph.Node{ID: fmt.Sprintf("resource:%d", i), Type: "Resource", Tier: 2})
		}
		add := func(e graph.Edge) {
			e.ID = fmt.Sprintf("grant:%d", len(data.Edges))
			data.Edges = append(data.Edges, e)
		}
		for human := range 5 {
			for role := range 3 {
				if r.IntN(3) == 0 {
					add(graph.Edge{Source: fmt.Sprintf("human:%d", human), Target: fmt.Sprintf("role:%d", role), Kind: "ASSIGNED"})
				}
			}
			for target := human + 1; target < 5; target++ {
				if r.IntN(4) == 0 {
					add(graph.Edge{Source: fmt.Sprintf("human:%d", human), Target: fmt.Sprintf("human:%d", target), Kind: "CAN_ADMINISTER"})
				}
			}
		}
		for role := range 3 {
			add(graph.Edge{Source: fmt.Sprintf("role:%d", role), Target: fmt.Sprintf("resource:%d", role), Kind: "GRANTS", Action: "read"})
		}
		if r.IntN(2) == 0 {
			add(graph.Edge{Source: "human:0", Target: "resource:0", Kind: "DENIES", Action: "read"})
		}
		snapshot, err := graph.Build(1, data)
		if err != nil {
			t.Fatal(err)
		}
		target := fmt.Sprintf("human:%d", r.IntN(5))
		approver := fmt.Sprintf("human:%d", r.IntN(5))
		c := domain.Change{Requester: "human:0", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: target, Access: fmt.Sprintf("role:%d", r.IntN(3))}, Decision: domain.Decision{Groups: []string{"resource-owner"}}}
		result, delta, err := impact(snapshot, c.Intent)
		if err != nil {
			t.Fatal(err)
		}
		after := graph.Data{Nodes: data.Nodes, Edges: append(append([]graph.Edge(nil), data.Edges...), delta.EdgesAdded...)}
		unsafe := approver == c.Requester
		for _, view := range []graph.Data{data, after} {
			control, _ := referenceAuthority(view, c.Requester)
			unsafe = unsafe || control[approver]
		}
		beneficiaries := map[string]bool{approver: true}
		for _, view := range []graph.Data{data, after} {
			control, _ := referenceAuthority(view, approver)
			for id := range control {
				beneficiaries[id] = true
			}
		}
		for id := range beneficiaries {
			_, old := referenceAuthority(data, id)
			_, next := referenceAuthority(after, id)
			for power := range next {
				if !old[power] {
					unsafe = true
				}
			}
		}
		if unsafe && eligible(snapshot, c, result, delta, approver, []string{approver}) == nil {
			t.Fatal("R1: deciding self-benefit accepted")
		}
		if len(data.Edges) > 0 {
			removed := r.IntN(len(data.Edges))
			d := graph.Delta{EdgesRemoved: []string{data.Edges[removed].ID}}
			change, err := snapshot.ImpactDiff(d)
			if err != nil {
				t.Fatal(err)
			}
			remaining := graph.Data{Nodes: data.Nodes}
			for i, e := range data.Edges {
				if i != removed {
					remaining.Edges = append(remaining.Edges, e)
				}
			}
			if change.MonotonicReduction {
				for i := range 5 {
					id := fmt.Sprintf("human:%d", i)
					_, old := referenceAuthority(data, id)
					_, next := referenceAuthority(remaining, id)
					for power := range next {
						if !old[power] {
							t.Fatal("R2: edge removal claimed reduction while creating authority")
						}
					}
				}
			}
		}
	})
}
