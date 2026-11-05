package graph

import "slices"

// Edge-only proposals share immutable node/index storage and merge sorted edges.
// The base snapshot remains unchanged; new relations receive full validation.
func (s *Snapshot) overlayEdges(version int64, d Delta) (*Snapshot, error) {
	if version < 0 || version > 1<<53-1 {
		return nil, ErrInvalid
	}
	removed := map[string]bool{}
	for _, id := range d.EdgesRemoved {
		if removed[id] {
			return nil, ErrInvalid
		}
		removed[id] = true
	}
	added := slices.Clone(d.EdgesAdded)
	for i, e := range added {
		e = cloneEdge(e)
		e.ID = EdgeID(e)
		a, okA := s.index[e.Source]
		b, okB := s.index[e.Target]
		if !okA || !okB {
			return nil, ErrInvalid
		}
		if !idPattern.MatchString(e.ID) || validateEdge(s.nodes[a], s.nodes[b], e) != nil {
			return nil, ErrInvalid
		}
		added[i] = e
	}
	slices.SortFunc(added, func(a, b Edge) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for i := 1; i < len(added); i++ {
		if added[i-1].ID == added[i].ID {
			return nil, ErrInvalid
		}
	}
	after := &Snapshot{version: version, nodes: s.nodes, index: s.index, edges: make([]Edge, 0, len(s.edges)+len(added))}
	after.kubernetes = s.kubernetes
	after.kubernetesDigests = s.kubernetesDigests
	after.edgeSources, after.edgeTargets = make([]uint32, 0, cap(after.edges)), make([]uint32, 0, cap(after.edges))
	appendEdge := func(e Edge, source, target uint32) {
		after.edges = append(after.edges, e)
		after.edgeSources = append(after.edgeSources, source)
		after.edgeTargets = append(after.edgeTargets, target)
	}
	j, found := 0, 0
	for i, e := range s.edges {
		if removed[e.ID] {
			found++
			continue
		}
		for j < len(added) && added[j].ID < e.ID {
			appendEdge(added[j], s.index[added[j].Source], s.index[added[j].Target])
			j++
		}
		if j < len(added) && added[j].ID == e.ID {
			return nil, ErrInvalid
		}
		appendEdge(e, s.edgeSources[i], s.edgeTargets[i])
	}
	if found != len(removed) {
		return nil, ErrNotFound
	}
	for _, e := range added[j:] {
		appendEdge(e, s.index[e.Source], s.index[e.Target])
	}
	if len(after.edges) > 20_000_000 {
		return nil, ErrInvalid
	}
	after.offsets = make([]uint32, len(s.nodes)+1)
	after.reverseOffsets = make([]uint32, len(s.nodes)+1)
	for i := range after.edges {
		after.offsets[after.edgeSources[i]+1]++
		after.reverseOffsets[after.edgeTargets[i]+1]++
	}
	for i := 1; i < len(after.offsets); i++ {
		after.offsets[i] += after.offsets[i-1]
		after.reverseOffsets[i] += after.reverseOffsets[i-1]
	}
	after.forward, after.reverse = make([]uint32, len(after.edges)), make([]uint32, len(after.edges))
	f, r := slices.Clone(after.offsets), slices.Clone(after.reverseOffsets)
	for i := range after.edges {
		a, b := after.edgeSources[i], after.edgeTargets[i]
		after.forward[f[a]] = uint32(i)
		f[a]++
		after.reverse[r[b]] = uint32(i)
		r[b]++
	}
	return after, nil
}
