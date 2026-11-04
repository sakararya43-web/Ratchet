package graph

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

type Revocation struct {
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	Access    string `json:"access"`
	Cost      int64  `json:"cost"`
	Protected bool   `json:"protected"`
}

func (a Revocation) key() string { return a.Kind + "\x00" + a.Target + "\x00" + a.Access }

// RevocationDelta maps a real target operation to its complete graph effect.
// Role removal covers all matching bindings; service permissions need original
// grant provenance. A derived reachability edge is never an executable grant.
func (s *Snapshot) RevocationDelta(a Revocation) (Delta, error) {
	if a.Protected || len(a.Target) > 256 || len(a.Access) > 256 || strings.ContainsRune(a.Target, 0) || strings.ContainsRune(a.Access, 0) {
		return Delta{}, ErrInvalid
	}
	n, err := s.Node(a.Target)
	if err != nil {
		return Delta{}, err
	}
	if n.Properties["protected"] == "true" || n.Properties["removable"] == "false" {
		return Delta{}, ErrInvalid
	}
	switch a.Kind {
	case "ROLE_REVOKE":
		d, err := s.Draft("ROLE_REVOKE", a.Target, a.Access)
		if err != nil {
			return Delta{}, err
		}
		for _, e := range s.edges {
			if slices.Contains(d.EdgesRemoved, e.ID) && (e.Properties["protected"] == "true" || e.Properties["removable"] == "false") {
				return Delta{}, ErrInvalid
			}
		}
		return d, nil
	case "REMOVE_SERVICE_PERMISSION":
		if n.Type != "ServiceAccount" || a.Access == "" {
			return Delta{}, ErrInvalid
		}
		d := Delta{}
		for _, e := range s.edges {
			if e.Source == a.Target && e.Kind == "GRANTS" && e.Properties["grant_id"] == a.Access {
				if e.Properties["protected"] == "true" || e.Properties["removable"] == "false" {
					return Delta{}, ErrInvalid
				}
				d.EdgesRemoved = append(d.EdgesRemoved, e.ID)
			}
		}
		if len(d.EdgesRemoved) == 0 {
			return Delta{}, fmt.Errorf("%w: original service grant provenance required", ErrNotFound)
		}
		return d, nil
	case "TERMINATE_SESSION", "RESTRICT_ACCOUNT":
		if a.Access != "" || (a.Kind == "TERMINATE_SESSION" && n.Type != "Session") || (a.Kind == "RESTRICT_ACCOUNT" && !Identity(n.Type)) {
			return Delta{}, ErrInvalid
		}
		if n.Properties["disabled"] == "true" {
			return Delta{}, ErrNotFound
		}
		if n.Properties == nil {
			n.Properties = map[string]string{}
		}
		n.Properties["disabled"] = "true"
		return Delta{NodesAdded: []Node{n}}, nil
	default:
		return Delta{}, fmt.Errorf("%w: unsupported revocation", ErrInvalid)
	}
}

func (s *Snapshot) ApplyRevocations(actions []Revocation) (*Snapshot, Delta, error) {
	if len(actions) > 1000 {
		return nil, Delta{}, ErrAnalysisLimit
	}
	after := s
	seen := map[string]bool{}
	for _, action := range actions {
		if seen[action.key()] {
			return nil, Delta{}, ErrInvalid
		}
		seen[action.key()] = true
		d, err := after.RevocationDelta(action)
		if err != nil {
			return nil, Delta{}, err
		}
		after, err = after.Overlay(s.version, d)
		if err != nil {
			return nil, Delta{}, err
		}
	}
	final := Delta{}
	for _, node := range after.nodes {
		old := s.nodes[s.index[node.ID]]
		if !maps.Equal(old.Properties, node.Properties) {
			final.NodesAdded = append(final.NodesAdded, cloneNode(node))
		}
	}
	present := map[string]bool{}
	for _, edge := range after.edges {
		present[edge.ID] = true
	}
	for _, edge := range s.edges {
		if !present[edge.ID] {
			final.EdgesRemoved = append(final.EdgesRemoved, edge.ID)
		}
	}
	slices.Sort(final.EdgesRemoved)
	safe, err := s.IsMonotonicReduction(final)
	if err != nil {
		return nil, Delta{}, err
	}
	if !safe {
		return nil, Delta{}, fmt.Errorf("%w: revocation set weakens protection or creates authority", ErrInvalid)
	}
	return after, final, nil
}
