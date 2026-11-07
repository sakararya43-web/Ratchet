package graph

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var ErrNoContainment = errors.New("no verified containment in executable action catalog")

type Activity struct {
	Identity string `json:"identity"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Tier     int    `json:"tier"`
}
type Containment struct {
	GraphVersion    int64        `json:"graph_version"`
	Origins         []string     `json:"origins"`
	Actions         []Revocation `json:"actions"`
	Cost            int64        `json:"cost"`
	MinimumProved   bool         `json:"minimum_proved"`
	Algorithm       string       `json:"algorithm"`
	OptimalityScope string       `json:"optimality_scope"`
	Checks          int          `json:"checks"`
	Delta           Delta        `json:"delta"`
	Preserved       []Activity   `json:"preserved"`
	Removed         []Activity   `json:"removed"`
}

func (s *Snapshot) criticalReach(origins []string) (bool, error) {
	for _, id := range origins {
		reach, err := s.Reach(id)
		if err != nil {
			return false, err
		}
		for _, power := range reach.Powers {
			if critical(s.nodes[s.index[power.NodeID]]) {
				return true, nil
			}
		}
	}
	return false, nil
}
func (s *Snapshot) linearContainment() bool {
	for _, node := range s.nodes {
		if !Identity(node.Type) && node.Type != "Group" && node.Type != "Role" && node.Type != "Resource" {
			return false
		}
	}
	for _, edge := range s.edges {
		if edge.Kind != "ASSIGNED" && edge.Kind != "MEMBER_OF" && (edge.Kind != "GRANTS" || s.nodes[s.index[edge.Target]].Type != "Resource") {
			return false
		}
	}
	return true
}

// PlanContainment minimizes explicit operator costs over a supplied executable
// catalog. It never calls a connector. Every returned set is simulated with the
// real graph semantics and proves both reduction and zero remaining tier-0 power.
func (s *Snapshot) PlanContainment(ctx context.Context, origins []string, catalog []Revocation, maxChecks int) (Containment, error) {
	var plan Containment
	if len(origins) == 0 || len(origins) > 64 || len(catalog) > 256 || maxChecks < 1 || maxChecks > 10000 {
		return plan, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return plan, err
	}
	origins = slices.Clone(origins)
	slices.Sort(origins)
	origins = slices.Compact(origins)
	for _, id := range origins {
		n, err := s.Node(id)
		if err != nil || !Identity(n.Type) {
			return plan, ErrInvalid
		}
	}
	actions := []Revocation{}
	seen := map[string]bool{}
	var total int64
	for _, a := range catalog {
		if a.Kind != "ROLE_REVOKE" && a.Kind != "REMOVE_SERVICE_PERMISSION" && a.Kind != "TERMINATE_SESSION" && a.Kind != "RESTRICT_ACCOUNT" {
			return plan, ErrInvalid
		}
		if seen[a.key()] || a.Cost < 1 || a.Cost > 1_000_000_000 {
			return plan, ErrInvalid
		}
		seen[a.key()] = true
		if a.Protected {
			continue
		}
		if _, _, err := s.ApplyRevocations([]Revocation{a}); err != nil {
			continue
		}
		actions = append(actions, a)
		total += a.Cost
	}
	slices.SortFunc(actions, func(a, b Revocation) int {
		if a.Cost < b.Cost {
			return -1
		}
		if a.Cost > b.Cost {
			return 1
		}
		return strings.Compare(a.key(), b.key())
	})
	plan = Containment{GraphVersion: s.version, Origins: origins, Actions: []Revocation{}, OptimalityScope: "supplied executable revocation catalog", Preserved: []Activity{}, Removed: []Activity{}}
	present, err := s.criticalReach(origins)
	if err != nil {
		return plan, err
	}
	if !present {
		plan.MinimumProved = true
		plan.Algorithm = "already-isolated"
		if err := plan.activities(s, s); err != nil {
			return plan, err
		}
		return plan, nil
	}
	var best []Revocation
	var bestAfter *Snapshot
	var bestDelta Delta
	bestCost := total + 1
	checks := 0
	evaluate := func(candidate []Revocation) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		checks++
		after, delta, err := s.ApplyRevocations(candidate)
		if err != nil {
			return false, nil
		}
		remaining, err := after.criticalReach(origins)
		if err != nil {
			return false, err
		}
		if remaining {
			return false, nil
		}
		var cost int64
		for _, a := range candidate {
			cost += a.Cost
		}
		if bestAfter == nil || cost < bestCost || (cost == bestCost && len(candidate) < len(best)) {
			best = slices.Clone(candidate)
			bestAfter = after
			bestDelta = delta
			bestCost = cost
		}
		return true, nil
	}
	cut, finite, err := s.weightedCut(ctx, origins, actions, total+1)
	if err != nil {
		return plan, err
	}
	valid := false
	if finite {
		valid, err = evaluate(cut)
		if err != nil {
			return plan, err
		}
	}
	if valid && s.linearContainment() {
		plan.MinimumProved = true
		plan.Algorithm = "weighted-min-cut"
	} else {
		if checks < maxChecks {
			if _, err := evaluate(actions); err != nil {
				return plan, err
			}
		}
		exhausted := false
		var search func(int, []Revocation, int64) error
		search = func(start int, chosen []Revocation, cost int64) error {
			if cost > bestCost {
				return nil
			}
			if checks >= maxChecks {
				exhausted = true
				return nil
			}
			cut, err := evaluate(chosen)
			if err != nil {
				return err
			}
			if cut {
				return nil
			}
			for i := start; i < len(actions); i++ {
				if exhausted {
					break
				}
				if err := search(i+1, append(slices.Clone(chosen), actions[i]), cost+actions[i].Cost); err != nil {
					return err
				}
			}
			return nil
		}
		if err := search(0, nil, 0); err != nil {
			return plan, err
		}
		if bestAfter == nil {
			if exhausted {
				return plan, ErrAnalysisLimit
			}
			return plan, ErrNoContainment
		}
		plan.MinimumProved = !exhausted
		plan.Algorithm = "exact-catalog-search"
		if exhausted {
			plan.Algorithm = "verified-bounded-alternative"
		}
	}
	plan.Actions = best
	plan.Cost = bestCost
	plan.Delta = bestDelta
	plan.Checks = checks
	if err := plan.activities(s, bestAfter); err != nil {
		return plan, err
	}
	return plan, nil
}
func (p *Containment) activities(before, after *Snapshot) error {
	for _, n := range before.nodes {
		if !Identity(n.Type) {
			continue
		}
		old, err := before.Reach(n.ID)
		if err != nil {
			return err
		}
		current, err := after.Reach(n.ID)
		if err != nil {
			return err
		}
		kept := map[Power]bool{}
		for _, power := range current.Powers {
			kept[power] = true
		}
		for _, power := range old.Powers {
			resource := before.nodes[before.index[power.NodeID]]
			if resource.Type != "Resource" || resource.Tier == 0 {
				continue
			}
			activity := Activity{n.ID, resource.ID, power.Action, resource.Tier}
			if kept[power] || kept[Power{power.NodeID, "*"}] {
				p.Preserved = append(p.Preserved, activity)
			} else {
				p.Removed = append(p.Removed, activity)
			}
		}
	}
	sortActivity := func(a, b Activity) int {
		return strings.Compare(fmt.Sprintf("%s\x00%s\x00%s", a.Identity, a.Resource, a.Action), fmt.Sprintf("%s\x00%s\x00%s", b.Identity, b.Resource, b.Action))
	}
	slices.SortFunc(p.Preserved, sortActivity)
	slices.SortFunc(p.Removed, sortActivity)
	return nil
}
func (s *Snapshot) weightedCut(ctx context.Context, origins []string, actions []Revocation, infinity int64) ([]Revocation, bool, error) {
	count := 2*len(s.nodes) + len(actions) + 2
	source, sink := count-2, count-1
	f := newFlow(count)
	arcs := []flowArc{}
	byKey := map[string]int{}
	for i, a := range actions {
		byKey[a.key()] = i
	}
	for i, n := range s.nodes {
		capacity := infinity
		index := -1
		for _, kind := range []string{"RESTRICT_ACCOUNT", "TERMINATE_SESSION"} {
			if a, ok := byKey[(Revocation{Kind: kind, Target: n.ID}).key()]; ok {
				capacity = actions[a].Cost
				index = a
			}
		}
		arc := f.add(2*i, 2*i+1, capacity)
		if index >= 0 {
			arcs = append(arcs, flowArc{2 * i, arc, index})
		}
		if critical(n) {
			f.add(2*i+1, sink, infinity)
		}
	}
	for _, id := range origins {
		if s.nodes[s.index[id]].Properties["disabled"] != "true" {
			f.add(source, 2*int(s.index[id]), infinity)
		}
	}
	inserted := map[int]bool{}
	for _, e := range s.edges {
		if e.Kind != "ASSIGNED" && e.Kind != "MEMBER_OF" && e.Kind != "GRANTS" && e.Kind != "CAN_ASSUME" && e.Kind != "CAN_ADMINISTER" && e.Kind != "CAN_MODIFY" && e.Kind != "CAN_APPROVE" {
			continue
		}
		from, to := 2*int(s.index[e.Source])+1, 2*int(s.index[e.Target])
		capacity := infinity
		if a, ok := byKey[(Revocation{Kind: "ROLE_REVOKE", Target: e.Source, Access: e.Target}).key()]; ok && e.Kind == "ASSIGNED" {
			if inserted[a] {
				continue
			}
			inserted[a] = true
			arc := f.add(from, to, actions[a].Cost)
			arcs = append(arcs, flowArc{from, arc, a})
			continue
		}
		if a, ok := byKey[(Revocation{Kind: "REMOVE_SERVICE_PERMISSION", Target: e.Source, Access: e.Properties["grant_id"]}).key()]; ok && e.Kind == "GRANTS" {
			gadget := 2*len(s.nodes) + a
			if !inserted[a] {
				inserted[a] = true
				arc := f.add(from, gadget, actions[a].Cost)
				arcs = append(arcs, flowArc{from, arc, a})
			}
			f.add(gadget, to, infinity)
			continue
		}
		if from != to {
			f.add(from, to, capacity)
		}
	}
	flow, reachable, err := f.cut(ctx, source, sink, infinity)
	if err != nil {
		return nil, false, err
	}
	if flow >= infinity {
		return nil, false, nil
	}
	selected := map[int]bool{}
	for _, arc := range arcs {
		if reachable[arc.from] && !reachable[f.edges[arc.from][arc.index].to] {
			selected[arc.action] = true
		}
	}
	result := []Revocation{}
	for i, a := range actions {
		if selected[i] {
			result = append(result, a)
		}
	}
	return result, true, nil
}
