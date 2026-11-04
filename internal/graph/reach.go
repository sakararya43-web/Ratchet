package graph

import (
	"fmt"
	"slices"
)

type Power struct {
	NodeID string `json:"node_id"`
	Action string `json:"action"`
}
type Reach struct {
	Version    int64       `json:"graph_version"`
	Nodes      []Node      `json:"nodes"`
	Controlled []string    `json:"controlled_identities"`
	Powers     []Power     `json:"powers"`
	ByTier     map[int]int `json:"by_tier"`
}
type analysis struct {
	seen     []bool
	powers   map[Power]bool
	control  map[string]bool
	weakened map[string]bool
}

func (s *Snapshot) analyze(identity string) (analysis, error) {
	start, ok := s.index[identity]
	if !ok {
		return analysis{}, ErrNotFound
	}
	if !Identity(s.nodes[start].Type) {
		return analysis{}, fmt.Errorf("%w: reach requires identity", ErrInvalid)
	}
	a := analysis{seen: make([]bool, len(s.nodes)), powers: map[Power]bool{}, control: map[string]bool{}, weakened: map[string]bool{}}
	q := make([]uint32, 1, len(s.nodes))
	q[0] = start
	a.seen[start] = true
	queued := make([]bool, len(s.nodes))
	queued[start] = true
	if s.nodes[start].Properties["disabled"] == "true" {
		return a, nil
	}
	denies := map[Power]bool{}
	for at := 0; at < len(q); at++ {
		i := q[at]
		if (s.nodes[i].Type == "Session" || s.nodes[i].Type == "Credential") && s.nodes[i].Properties["disabled"] == "true" {
			continue
		}
		for _, ei := range s.forward[s.offsets[i]:s.offsets[i+1]] {
			e := s.edges[ei]
			target := s.index[e.Target]
			n := s.nodes[target]
			walk := false
			switch e.Kind {
			case "MEMBER_OF", "ASSIGNED":
				walk = true
			case "CAN_ASSUME", "CAN_ADMINISTER":
				walk = true
				if e.Target != identity {
					a.control[e.Target] = true
				}
				a.powers[Power{e.Target, "takeover"}] = true
			case "CAN_MODIFY":
				walk = true
				a.powers[Power{e.Target, "modify"}] = true
				if n.Type == "Safeguard" {
					a.weakened[n.ID] = true
				}
			case "CAN_APPROVE":
				a.powers[Power{e.Target, "approve"}] = true
				a.seen[target] = true
			case "GRANTS":
				a.powers[Power{e.Target, e.Action}] = true
				walk = n.Type == "Permission" || ((n.Type == "Credential" || n.Type == "Session") && usableSecret(e.Action))
				if !walk {
					a.seen[target] = true
				}
				if n.Type == "Safeguard" && (e.Action == "modify" || e.Action == "admin" || e.Action == "*") {
					a.weakened[n.ID] = true
				}
			case "DENIES":
				denies[Power{e.Target, e.Action}] = true
			}
			if walk {
				a.seen[target] = true
				if !queued[target] {
					queued[target] = true
					q = append(q, target)
				}
			}
		}
	}
	for p := range a.powers {
		if denies[p] || denies[Power{p.NodeID, "*"}] {
			delete(a.powers, p)
		}
	}
	for _, i := range s.index {
		if s.nodes[i].Type == "Resource" {
			a.seen[i] = false
		}
	}
	for p := range a.powers {
		a.seen[s.index[p.NodeID]] = true
	}
	return a, nil
}

func (s *Snapshot) Reach(identity string) (Reach, error) {
	a, err := s.analyze(identity)
	if err != nil {
		return Reach{}, err
	}
	r := Reach{Version: s.version, Nodes: []Node{}, Controlled: []string{}, Powers: []Power{}, ByTier: map[int]int{0: 0, 1: 0, 2: 0, 3: 0}}
	for i, seen := range a.seen {
		if seen {
			n := s.nodes[i]
			r.Nodes = append(r.Nodes, cloneNode(n))
			if n.Type == "Resource" {
				r.ByTier[n.Tier]++
			}
		}
	}
	for id := range a.control {
		r.Controlled = append(r.Controlled, id)
	}
	slices.Sort(r.Controlled)
	for p := range a.powers {
		r.Powers = append(r.Powers, p)
	}
	sortPowers(r.Powers)
	return r, nil
}

func (s *Snapshot) ControlSet(identity string) ([]string, error) {
	r, err := s.Reach(identity)
	return r.Controlled, err
}
func sortPowers(p []Power) {
	slices.SortFunc(p, func(a, b Power) int {
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
}

type Route struct {
	NodeIDs   []string `json:"node_ids"`
	EdgeKinds []string `json:"edge_kinds"`
	EdgeIDs   []string `json:"edge_ids"`
}
type Paths struct {
	Version   int64   `json:"graph_version"`
	Routes    []Route `json:"routes"`
	Truncated bool    `json:"truncated"`
}

// PathsTo enumerates bounded simple paths. Edge identities preserve provenance
// and distinguish separate grants along otherwise identical node routes.
func (s *Snapshot) PathsTo(identity string, limit, workLimit int) (Paths, error) {
	if limit < 1 || limit > 1000 || workLimit < 1 || workLimit > 1_000_000 {
		return Paths{}, ErrInvalid
	}
	a, err := s.analyze(identity)
	if err != nil {
		return Paths{}, err
	}
	result := Paths{Version: s.version, Routes: []Route{}}
	visited := make([]bool, len(s.nodes))
	work := 0
	var walk func(uint32, Route)
	walk = func(i uint32, path Route) {
		if work >= workLimit {
			result.Truncated = true
			return
		}
		work++
		if len(path.NodeIDs) > 64 {
			result.Truncated = true
			return
		}
		visited[i] = true
		defer func() { visited[i] = false }()
		if (s.nodes[i].Type == "Session" || s.nodes[i].Type == "Credential") && s.nodes[i].Properties["disabled"] == "true" {
			return
		}
		if critical(s.nodes[i]) && a.seen[i] && len(path.EdgeIDs) > 0 {
			if len(result.Routes) >= limit {
				result.Truncated = true
				return
			}
			result.Routes = append(result.Routes, Route{NodeIDs: slices.Clone(path.NodeIDs), EdgeKinds: slices.Clone(path.EdgeKinds), EdgeIDs: slices.Clone(path.EdgeIDs)})
		}
		for _, ei := range s.forward[s.offsets[i]:s.offsets[i+1]] {
			e := s.edges[ei]
			j := s.index[e.Target]
			if visited[j] || !a.seen[j] {
				continue
			}
			pass := e.Kind == "MEMBER_OF" || e.Kind == "ASSIGNED" || e.Kind == "CAN_ASSUME" || e.Kind == "CAN_ADMINISTER" || e.Kind == "CAN_MODIFY" || e.Kind == "CAN_APPROVE"
			if e.Kind == "GRANTS" {
				pass = a.powers[Power{e.Target, e.Action}]
				if (s.nodes[j].Type == "Session" || s.nodes[j].Type == "Credential") && !usableSecret(e.Action) {
					pass = false
				}
			}
			if pass {
				walk(j, Route{NodeIDs: append(path.NodeIDs, e.Target), EdgeKinds: append(path.EdgeKinds, e.Kind), EdgeIDs: append(path.EdgeIDs, e.ID)})
			}
			if work >= workLimit || len(result.Routes) > limit {
				return
			}
		}
	}
	walk(s.index[identity], Route{NodeIDs: []string{identity}})
	return result, nil
}

func usableSecret(action string) bool {
	return action == "use" || action == "read_secret" || action == "admin" || action == "*"
}

func (s *Snapshot) Neighbourhood(id string, depth, limit int) (Data, bool, error) {
	start, ok := s.index[id]
	if !ok {
		return Data{}, false, ErrNotFound
	}
	if depth < 0 || depth > 4 || limit < 1 || limit > 1000 {
		return Data{}, false, ErrInvalid
	}
	seen := map[uint32]bool{start: true}
	q := []uint32{start}
	at := 0
	truncated := false
	for level := 0; level < depth; level++ {
		end := len(q)
		for ; at < end; at++ {
			i := q[at]
			for _, indices := range [][]uint32{s.forward[s.offsets[i]:s.offsets[i+1]], s.reverse[s.reverseOffsets[i]:s.reverseOffsets[i+1]]} {
				for _, ei := range indices {
					e := s.edges[ei]
					j := s.index[e.Target]
					if j == i {
						j = s.index[e.Source]
					}
					if !seen[j] {
						if len(q) >= limit {
							truncated = true
							continue
						}
						seen[j] = true
						q = append(q, j)
					}
				}
			}
		}
	}
	d := Data{Nodes: []Node{}, Edges: []Edge{}}
	for i, n := range s.nodes {
		if seen[uint32(i)] {
			d.Nodes = append(d.Nodes, cloneNode(n))
		}
	}
	for _, e := range s.edges {
		if seen[s.index[e.Source]] && seen[s.index[e.Target]] {
			d.Edges = append(d.Edges, cloneEdge(e))
		}
	}
	return d, truncated, nil
}
