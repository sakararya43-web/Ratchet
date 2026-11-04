// Package graph implements immutable, escalation-aware organization snapshots.
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

var (
	ErrInvalid       = errors.New("invalid graph")
	ErrNotFound      = errors.New("graph node not found")
	ErrUnavailable   = errors.New("graph unavailable or stale")
	ErrAnalysisLimit = errors.New("graph analysis bound exceeded")
	idPattern        = regexp.MustCompile(`^[A-Za-z0-9_:/.-]{1,256}$`)
)

type Node struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Tier        int               `json:"tier"`
	DisplayName string            `json:"display_name,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

type Edge struct {
	ID         string            `json:"id"`
	Source     string            `json:"source"`
	Target     string            `json:"target"`
	Kind       string            `json:"kind"`
	Action     string            `json:"action,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type Data struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
type Delta struct {
	NodesAdded   []Node   `json:"nodes_added"`
	NodesRemoved []string `json:"nodes_removed"`
	EdgesAdded   []Edge   `json:"edges_added"`
	EdgesRemoved []string `json:"edges_removed"`
}

// Snapshot owns dense node IDs, forward/reverse CSR and a fixed event position.
// None of its backing arrays or maps escape to callers.
type Snapshot struct {
	version                 int64
	nodes                   []Node
	edges                   []Edge
	index                   map[string]uint32
	offsets, reverseOffsets []uint32
	forward, reverse        []uint32
}

func Identity(kind string) bool { return kind == "Human" || kind == "ServiceAccount" }
func critical(n Node) bool      { return (n.Type == "Resource" || n.Type == "Safeguard") && n.Tier == 0 }
func cloneNode(n Node) Node     { n.Properties = maps.Clone(n.Properties); return n }
func cloneEdge(e Edge) Edge     { e.Properties = maps.Clone(e.Properties); return e }

func EdgeID(e Edge) string {
	if e.ID != "" {
		return e.ID
	}
	if id := e.Properties["grant_id"]; id != "" {
		return id
	}
	h := sha256.Sum256([]byte(e.Source + "\x00" + e.Target + "\x00" + e.Kind + "\x00" + e.Action))
	return "edge:" + hex.EncodeToString(h[:])
}

func Build(version int64, data Data) (*Snapshot, error) {
	if version < 0 || version > 1<<53-1 || len(data.Nodes) > 2_000_000 || len(data.Edges) > 20_000_000 {
		return nil, ErrInvalid
	}
	s := &Snapshot{version: version, index: make(map[string]uint32, len(data.Nodes)), nodes: make([]Node, len(data.Nodes)), edges: make([]Edge, len(data.Edges))}
	for i, n := range data.Nodes {
		if !idPattern.MatchString(n.ID) || n.Tier < 0 || n.Tier > 3 {
			return nil, fmt.Errorf("%w: node identity or tier", ErrInvalid)
		}
		switch n.Type {
		case "Human", "ServiceAccount", "Group", "Role", "Permission", "Resource", "Safeguard", "Session", "Credential":
		default:
			return nil, fmt.Errorf("%w: unsupported node type %q", ErrInvalid, n.Type)
		}
		if disabled, exists := n.Properties["disabled"]; exists && disabled != "true" && disabled != "false" {
			return nil, fmt.Errorf("%w: invalid disabled state", ErrInvalid)
		}
		if n.Type == "Safeguard" {
			kind := n.Properties["guard_kind"]
			if kind != "" && kind != "withdrawal_threshold_v1" {
				return nil, fmt.Errorf("%w: unknown safeguard semantics", ErrInvalid)
			}
			if kind == "" && (n.Properties["required_checks"] != "" || n.Properties["threshold_usd"] != "") {
				return nil, fmt.Errorf("%w: declared safeguard semantics required", ErrInvalid)
			}
			if kind != "" {
				if _, err := guardNumber(n, "required_checks"); err != nil {
					return nil, err
				}
				if _, err := guardNumber(n, "threshold_usd"); err != nil {
					return nil, err
				}
			}
		}
		s.nodes[i] = cloneNode(n)
	}
	slices.SortFunc(s.nodes, func(a, b Node) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for i, n := range s.nodes {
		if _, exists := s.index[n.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate node", ErrInvalid)
		}
		s.index[n.ID] = uint32(i)
	}
	seen := make(map[string]bool, len(data.Edges))
	for i, edge := range data.Edges {
		e := cloneEdge(edge)
		e.ID = EdgeID(e)
		if !idPattern.MatchString(e.ID) || seen[e.ID] {
			return nil, fmt.Errorf("%w: duplicate or invalid edge identity", ErrInvalid)
		}
		seen[e.ID] = true
		source, ok := s.index[e.Source]
		if !ok {
			return nil, fmt.Errorf("%w: missing source %s", ErrInvalid, e.Source)
		}
		target, ok := s.index[e.Target]
		if !ok {
			return nil, fmt.Errorf("%w: missing target %s", ErrInvalid, e.Target)
		}
		if err := validateEdge(s.nodes[source], s.nodes[target], e); err != nil {
			return nil, err
		}
		s.edges[i] = e
	}
	slices.SortFunc(s.edges, func(a, b Edge) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	s.offsets = make([]uint32, len(s.nodes)+1)
	s.reverseOffsets = make([]uint32, len(s.nodes)+1)
	for _, e := range s.edges {
		s.offsets[s.index[e.Source]+1]++
		s.reverseOffsets[s.index[e.Target]+1]++
	}
	for i := 1; i < len(s.offsets); i++ {
		s.offsets[i] += s.offsets[i-1]
		s.reverseOffsets[i] += s.reverseOffsets[i-1]
	}
	s.forward = make([]uint32, len(s.edges))
	s.reverse = make([]uint32, len(s.edges))
	f, r := slices.Clone(s.offsets), slices.Clone(s.reverseOffsets)
	for i, e := range s.edges {
		a, b := s.index[e.Source], s.index[e.Target]
		s.forward[f[a]] = uint32(i)
		f[a]++
		s.reverse[r[b]] = uint32(i)
		r[b]++
	}
	return s, nil
}

func validateEdge(a, b Node, e Edge) error {
	valid := false
	switch e.Kind {
	case "MEMBER_OF", "ASSIGNED":
		valid = (Identity(a.Type) || a.Type == "Group" || a.Type == "Role") && (b.Type == "Group" || b.Type == "Role")
	case "GRANTS":
		valid = (Identity(a.Type) || a.Type == "Group" || a.Type == "Role" || a.Type == "Permission") && e.Action != "" && (b.Type == "Resource" || b.Type == "Permission" || b.Type == "Safeguard" || b.Type == "Credential" || b.Type == "Session")
	case "CAN_ASSUME", "CAN_ADMINISTER":
		valid = Identity(b.Type) && (Identity(a.Type) || a.Type == "Role" || a.Type == "Group" || a.Type == "Permission" || a.Type == "Credential" || a.Type == "Session")
	case "CAN_MODIFY":
		valid = (Identity(a.Type) || a.Type == "Role" || a.Type == "Group" || a.Type == "Permission") && (b.Type == "Role" || b.Type == "Group" || b.Type == "Safeguard")
	case "CAN_APPROVE":
		valid = (Identity(a.Type) || a.Type == "Role" || a.Type == "Group") && (b.Type == "Resource" || b.Type == "Safeguard")
	case "PROTECTED_BY":
		valid = (a.Type == "Safeguard" && b.Type != "Safeguard") || (b.Type == "Safeguard" && a.Type != "Safeguard")
	case "DENIES":
		valid = (Identity(a.Type) || a.Type == "Role" || a.Type == "Group") && b.Type == "Resource" && e.Action != ""
	case "REQUIRES_APPROVAL":
		valid = (a.Type == "Resource" || a.Type == "Safeguard") && (Identity(b.Type) || b.Type == "Group" || b.Type == "Role")
	}
	if !valid {
		return fmt.Errorf("%w: unsupported %s relation %s -> %s", ErrInvalid, e.Kind, a.Type, b.Type)
	}
	if len(e.Action) > 128 {
		return ErrInvalid
	}
	return nil
}

func (s *Snapshot) Version() int64 { return s.version }
func (s *Snapshot) Data() Data {
	d := Data{Nodes: make([]Node, len(s.nodes)), Edges: make([]Edge, len(s.edges))}
	for i, n := range s.nodes {
		d.Nodes[i] = cloneNode(n)
	}
	for i, e := range s.edges {
		d.Edges[i] = cloneEdge(e)
	}
	return d
}
func (s *Snapshot) Node(id string) (Node, error) {
	i, ok := s.index[id]
	if !ok {
		return Node{}, ErrNotFound
	}
	return cloneNode(s.nodes[i]), nil
}
func (s *Snapshot) IncidentEdges(id string) ([]Edge, []Edge, error) {
	i, ok := s.index[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	in, out := []Edge{}, []Edge{}
	for _, j := range s.reverse[s.reverseOffsets[i]:s.reverseOffsets[i+1]] {
		in = append(in, cloneEdge(s.edges[j]))
	}
	for _, j := range s.forward[s.offsets[i]:s.offsets[i+1]] {
		out = append(out, cloneEdge(s.edges[j]))
	}
	return in, out, nil
}

// Overlay compiles an isolated proposed view; readers retain their base CSR.
// Node deletion cannot silently discard incoming grants: all incident edges
// must be explicitly removed in the same delta.
func (s *Snapshot) Overlay(version int64, d Delta) (*Snapshot, error) {
	nodes := make(map[string]Node, len(s.nodes))
	edges := make(map[string]Edge, len(s.edges))
	for _, n := range s.nodes {
		nodes[n.ID] = n
	}
	for _, e := range s.edges {
		edges[e.ID] = e
	}
	for _, id := range d.EdgesRemoved {
		if _, ok := edges[id]; !ok {
			return nil, fmt.Errorf("%w: removed edge", ErrNotFound)
		}
		delete(edges, id)
	}
	for _, id := range d.NodesRemoved {
		if _, ok := nodes[id]; !ok {
			return nil, ErrNotFound
		}
		delete(nodes, id)
	}
	for _, n := range d.NodesAdded {
		nodes[n.ID] = n
	}
	for _, e := range d.EdgesAdded {
		e.ID = EdgeID(e)
		if _, ok := edges[e.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate added edge", ErrInvalid)
		}
		edges[e.ID] = e
	}
	data := Data{Nodes: make([]Node, 0, len(nodes)), Edges: make([]Edge, 0, len(edges))}
	for _, n := range nodes {
		data.Nodes = append(data.Nodes, n)
	}
	for _, e := range edges {
		data.Edges = append(data.Edges, e)
	}
	return Build(version, data)
}
