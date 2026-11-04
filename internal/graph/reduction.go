package graph

import "maps"

// IsMonotonicReduction proves the change for every affected identity, including
// denied authority and safeguards. Unknown structural edits cannot use fast paths.
func (s *Snapshot) IsMonotonicReduction(delta Delta) (bool, error) {
	impact, err := s.ImpactDiff(delta)
	return impact.MonotonicReduction, err
}
func (s *Snapshot) reductionStructure(after *Snapshot, delta Delta) (bool, error) {
	if len(delta.NodesRemoved) > 0 {
		return false, nil
	}
	for _, n := range delta.NodesAdded {
		old, err := s.Node(n.ID)
		if err != nil {
			return false, nil
		}
		if old.Type != n.Type || old.Tier != n.Tier {
			return false, nil
		}
		if n.Type == "Safeguard" {
			weak, err := guardWeakened(old, n)
			if err != nil {
				return false, err
			}
			if weak {
				return false, nil
			}
			continue
		}
		beforeProps := maps.Clone(old.Properties)
		afterProps := maps.Clone(n.Properties)
		if n.Type == "Human" || n.Type == "ServiceAccount" || n.Type == "Session" || n.Type == "Credential" {
			if old.Properties["disabled"] == "true" && n.Properties["disabled"] != "true" {
				return false, nil
			}
			delete(beforeProps, "disabled")
			delete(afterProps, "disabled")
		}
		if !maps.Equal(beforeProps, afterProps) {
			return false, nil
		}
	}
	remaining := map[string]Edge{}
	for _, e := range after.edges {
		remaining[e.ID] = e
	}
	for _, e := range s.edges {
		if next, exists := remaining[e.ID]; exists && next.Source == e.Source && next.Target == e.Target && next.Kind == e.Kind && next.Action == e.Action && maps.Equal(next.Properties, e.Properties) {
			continue
		}
		if e.Kind == "DENIES" || e.Kind == "REQUIRES_APPROVAL" || e.Kind == "PROTECTED_BY" || e.Properties["protected"] == "true" {
			return false, nil
		}
		if (e.Kind == "MEMBER_OF" || e.Kind == "ASSIGNED") && s.protectiveMembership(e.Target) {
			return false, nil
		}
	}
	return true, nil
}
func (s *Snapshot) protectiveMembership(target string) bool {
	seen := map[string]bool{target: true}
	queue := []string{target}
	for at := 0; at < len(queue); at++ {
		i := s.index[queue[at]]
		for _, index := range s.reverse[s.reverseOffsets[i]:s.reverseOffsets[i+1]] {
			if s.edges[index].Kind == "REQUIRES_APPROVAL" {
				return true
			}
		}
		for _, index := range s.forward[s.offsets[i]:s.offsets[i+1]] {
			e := s.edges[index]
			if e.Kind == "DENIES" || e.Kind == "REQUIRES_APPROVAL" {
				return true
			}
			if (e.Kind == "MEMBER_OF" || e.Kind == "ASSIGNED" || e.Kind == "CAN_MODIFY") && !seen[e.Target] {
				seen[e.Target] = true
				queue = append(queue, e.Target)
			}
		}
	}
	return false
}
