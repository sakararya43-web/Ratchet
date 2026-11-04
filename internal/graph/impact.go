package graph

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type IdentityImpact struct {
	IdentityID    string      `json:"identity_id"`
	NewResources  []Node      `json:"new_resources"`
	NewControlled []string    `json:"new_controlled_identities"`
	NewPowers     []Power     `json:"new_powers"`
	NewRoutes     []Route     `json:"new_tier0_routes"`
	Weakened      []Node      `json:"safeguards_weakened"`
	BlastDelta    map[int]int `json:"blast_radius_delta"`
}
type Impact struct {
	Version            int64            `json:"graph_version"`
	MonotonicReduction bool             `json:"monotonic_reduction"`
	Affected           []IdentityImpact `json:"affected_identities"`
	Weakened           []Node           `json:"safeguards_weakened"`
}

// ImpactDiff assesses every principal, including beneficiaries other than the
// requester. Analysis limits are errors, never an incomplete safe assessment.
func (s *Snapshot) ImpactDiff(delta Delta) (Impact, error) {
	after, err := s.Overlay(s.version, delta)
	if err != nil {
		return Impact{}, err
	}
	out := Impact{Version: s.version, MonotonicReduction: true, Affected: []IdentityImpact{}, Weakened: []Node{}}
	weakened := map[string]Node{}
	for _, n := range after.nodes {
		if n.Type == "Safeguard" {
			if oldIndex, exists := s.index[n.ID]; exists {
				weak, err := guardWeakened(s.nodes[oldIndex], n)
				if err != nil {
					return Impact{}, err
				}
				if weak {
					weakened[n.ID] = cloneNode(n)
				}
			}
		}
	}
	for _, id := range delta.EdgesRemoved {
		for _, e := range s.edges {
			if e.ID == id && (e.Kind == "DENIES" || e.Kind == "PROTECTED_BY" || e.Kind == "REQUIRES_APPROVAL") {
				n := s.nodes[s.index[e.Target]]
				if e.Kind == "PROTECTED_BY" && n.Type != "Safeguard" {
					n = s.nodes[s.index[e.Source]]
				}
				weakened[n.ID] = cloneNode(n)
			}
		}
	}
	for _, n := range after.nodes {
		if !Identity(n.Type) {
			continue
		}
		old := Reach{ByTier: map[int]int{}}
		oldA := analysis{weakened: map[string]bool{}}
		if _, exists := s.index[n.ID]; exists {
			old, err = s.Reach(n.ID)
			if err != nil {
				return Impact{}, err
			}
			oldA, err = s.analyze(n.ID)
			if err != nil {
				return Impact{}, err
			}
		}
		current, err := after.Reach(n.ID)
		if err != nil {
			return Impact{}, err
		}
		newA, err := after.analyze(n.ID)
		if err != nil {
			return Impact{}, err
		}
		item := IdentityImpact{IdentityID: n.ID, NewResources: []Node{}, NewControlled: []string{}, NewPowers: []Power{}, NewRoutes: []Route{}, Weakened: []Node{}, BlastDelta: map[int]int{}}
		oldP := map[Power]bool{}
		for _, p := range old.Powers {
			oldP[p] = true
		}
		addedResource := map[string]bool{}
		for _, p := range current.Powers {
			if !oldP[p] && !oldP[Power{p.NodeID, "*"}] {
				item.NewPowers = append(item.NewPowers, p)
				target := after.nodes[after.index[p.NodeID]]
				if target.Type == "Resource" && !addedResource[p.NodeID] {
					item.NewResources = append(item.NewResources, cloneNode(target))
					addedResource[p.NodeID] = true
				}
			}
		}
		for _, id := range current.Controlled {
			if !slices.Contains(old.Controlled, id) {
				item.NewControlled = append(item.NewControlled, id)
			}
		}
		for id := range newA.weakened {
			if !oldA.weakened[id] {
				sg := after.nodes[after.index[id]]
				item.Weakened = append(item.Weakened, cloneNode(sg))
				weakened[id] = cloneNode(sg)
			}
		}
		slices.SortFunc(item.Weakened, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
		for tier := 0; tier < 4; tier++ {
			item.BlastDelta[tier] = current.ByTier[tier] - old.ByTier[tier]
		}
		// Enumerate only where the identity can reach critical assets in either
		// state. Comparison includes provenance, so alternate grants are visible.
		if current.ByTier[0] > 0 || old.ByTier[0] > 0 || len(item.Weakened) > 0 {
			oldPaths := Paths{}
			if _, exists := s.index[n.ID]; exists {
				oldPaths, err = s.PathsTo(n.ID, 1000, 1_000_000)
				if err != nil {
					return Impact{}, err
				}
			}
			newPaths, err := after.PathsTo(n.ID, 1000, 1_000_000)
			if err != nil {
				return Impact{}, err
			}
			if oldPaths.Truncated || newPaths.Truncated {
				return Impact{}, ErrAnalysisLimit
			}
			oldRoutes := map[string]bool{}
			for _, route := range oldPaths.Routes {
				oldRoutes[routeKey(route)] = true
			}
			for _, route := range newPaths.Routes {
				if !oldRoutes[routeKey(route)] {
					item.NewRoutes = append(item.NewRoutes, route)
				}
			}
		}
		changed := len(item.NewPowers) > 0 || len(item.NewControlled) > 0 || len(item.NewRoutes) > 0 || len(item.Weakened) > 0
		for _, d := range item.BlastDelta {
			changed = changed || d != 0
		}
		if changed {
			out.Affected = append(out.Affected, item)
		}
		if len(item.NewPowers) > 0 || len(item.NewControlled) > 0 {
			out.MonotonicReduction = false
		}
	}
	for _, n := range weakened {
		out.Weakened = append(out.Weakened, n)
	}
	slices.SortFunc(out.Weakened, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
	if len(weakened) > 0 {
		out.MonotonicReduction = false
	}
	return out, nil
}

func routeKey(route Route) string { raw, _ := json.Marshal(route.EdgeIDs); return string(raw) }

// Draft supports exact operations the graph can prove. Unknown rule edits are
// refused instead of inventing safeguard semantics from free text.
func (s *Snapshot) Draft(kind, target, access string) (Delta, error) {
	n, err := s.Node(target)
	if err != nil {
		return Delta{}, err
	}
	switch kind {
	case "ROLE_ASSIGN", "ROLE_REVOKE":
		role, err := s.Node(access)
		if err != nil {
			return Delta{}, err
		}
		if !Identity(n.Type) || role.Type != "Role" {
			return Delta{}, ErrInvalid
		}
		if kind == "ROLE_ASSIGN" {
			return Delta{EdgesAdded: []Edge{{ID: "draft:" + target + ":" + access, Source: target, Target: access, Kind: "ASSIGNED"}}}, nil
		}
		d := Delta{}
		for _, e := range s.edges {
			if e.Source == target && e.Target == access && e.Kind == "ASSIGNED" {
				d.EdgesRemoved = append(d.EdgesRemoved, e.ID)
			}
		}
		if len(d.EdgesRemoved) == 0 {
			return Delta{}, ErrNotFound
		}
		return d, nil
	case "MODIFY_SAFEGUARD":
		if n.Type != "Safeguard" || access != "remove" {
			return Delta{}, fmt.Errorf("%w: only explicit safeguard removal is supported", ErrInvalid)
		}
		d := Delta{}
		for _, e := range s.edges {
			if e.Kind == "PROTECTED_BY" && (e.Source == target || e.Target == target) {
				d.EdgesRemoved = append(d.EdgesRemoved, e.ID)
			}
		}
		if len(d.EdgesRemoved) == 0 {
			return Delta{}, ErrNotFound
		}
		return d, nil
	default:
		return Delta{}, fmt.Errorf("%w: unsupported draft kind", ErrInvalid)
	}
}
