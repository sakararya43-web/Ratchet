package graph

// Any changed authority must pass through a changed node or the source of a
// changed relation. Reverse closure in both graphs conservatively includes all
// principals that can depend on it, including controllers, inherited roles,
// denied grants and approval/safeguard relations. It is not requester-only scope.
func (s *Snapshot) impactCandidates(after *Snapshot, delta Delta) map[string]bool {
	seeds := map[string]bool{}
	for _, n := range delta.NodesAdded {
		seeds[n.ID] = true
	}
	for _, id := range delta.NodesRemoved {
		seeds[id] = true
	}
	for _, e := range delta.EdgesAdded {
		seeds[e.Source] = true
	}
	removed := map[string]bool{}
	for _, id := range delta.EdgesRemoved {
		removed[id] = true
	}
	if len(removed) > 0 {
		for _, e := range s.edges {
			if removed[e.ID] {
				seeds[e.Source] = true
			}
		}
	}
	candidates := map[string]bool{}
	for _, view := range []*Snapshot{s, after} {
		seen := make([]bool, len(view.nodes))
		queue := make([]uint32, 0, len(seeds))
		for id := range seeds {
			if i, ok := view.index[id]; ok && !seen[i] {
				seen[i] = true
				queue = append(queue, i)
			}
		}
		for at := 0; at < len(queue); at++ {
			i := queue[at]
			if Identity(view.nodes[i].Type) {
				candidates[view.nodes[i].ID] = true
			}
			for _, edge := range view.reverse[view.reverseOffsets[i]:view.reverseOffsets[i+1]] {
				parent := view.index[view.edges[edge].Source]
				if !seen[parent] {
					seen[parent] = true
					queue = append(queue, parent)
				}
			}
		}
	}
	return candidates
}
