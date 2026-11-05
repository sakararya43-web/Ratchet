// Package evaluation runs reproducible core-only workloads and reports their scope.
package evaluation

import (
	"encoding/json"
	"errors"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"strings"
)

// CompileDemo expresses the reviewed core semantics of exchange-v1. Logical
// permissions and broad iam:all expansion are explicit benchmark assumptions;
// this fixture compiler is never used by production ingestion or APIs.
func CompileDemo(raw []byte) (*graph.Snapshot, error) {
	var seed struct {
		Identities []struct {
			ID, Type string
			Disabled bool `json:"is_disabled"`
		} `json:"identities"`
		Roles []struct {
			ID          string
			Permissions []string
		} `json:"roles"`
		Resources []struct {
			ID   string
			Tier int
		} `json:"resources"`
		Safeguards []struct {
			ID         string
			Tier       int
			Resources  []string          `json:"protected_resources"`
			Parameters map[string]string `json:"parameters"`
		} `json:"safeguards"`
		Grants []struct {
			ID         string
			IdentityID string `json:"identity_id"`
			RoleID     string `json:"role_id"`
			By         string `json:"granted_by"`
		} `json:"grants"`
		Control []struct {
			Source string `json:"controller_id"`
			Target string `json:"controlled_id"`
			Kind   string `json:"kind"`
		} `json:"control_relations"`
		Sessions []struct {
			ID       string `json:"session_id"`
			Identity string `json:"identity_id"`
			Revoked  bool   `json:"is_revoked"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &seed); err != nil {
		return nil, err
	}
	d := graph.Data{}
	known := map[string]bool{}
	add := func(n graph.Node) { known[n.ID] = true; d.Nodes = append(d.Nodes, n) }
	for _, n := range seed.Identities {
		p := map[string]string{}
		if n.Disabled {
			p["disabled"] = "true"
		}
		add(graph.Node{ID: n.ID, Type: n.Type, Properties: p})
	}
	for _, r := range seed.Roles {
		add(graph.Node{ID: r.ID, Type: "Role"})
	}
	for _, r := range seed.Resources {
		add(graph.Node{ID: r.ID, Type: "Resource", Tier: r.Tier})
	}
	for _, s := range seed.Safeguards {
		properties := s.Parameters
		if s.ID == "safeguard:withdrawal-rule" {
			properties["guard_kind"] = "withdrawal_threshold_v1"
		}
		add(graph.Node{ID: s.ID, Type: "Safeguard", Tier: s.Tier, Properties: properties})
		for _, resource := range s.Resources {
			d.Edges = append(d.Edges, graph.Edge{Source: resource, Target: s.ID, Kind: "PROTECTED_BY"})
		}
	}
	for _, r := range seed.Roles {
		for _, permission := range r.Permissions {
			at := strings.LastIndex(permission, ":")
			if at < 0 {
				return nil, errors.New("malformed seed permission")
			}
			target, action := permission[:at], permission[at+1:]
			if !known[target] {
				target = "permission:" + permission
				if !known[target] {
					add(graph.Node{ID: target, Type: "Permission"})
				}
				action = "exercise"
			}
			d.Edges = append(d.Edges, graph.Edge{Source: r.ID, Target: target, Kind: "GRANTS", Action: action})
			if permission == "iam:all" {
				for _, role := range seed.Roles {
					d.Edges = append(d.Edges, graph.Edge{Source: target, Target: role.ID, Kind: "CAN_MODIFY"})
				}
				for _, identity := range seed.Identities {
					d.Edges = append(d.Edges, graph.Edge{Source: target, Target: identity.ID, Kind: "CAN_ADMINISTER"})
				}
				for _, resource := range seed.Resources {
					d.Edges = append(d.Edges, graph.Edge{Source: target, Target: resource.ID, Kind: "GRANTS", Action: "*"})
				}
			}
		}
	}
	for _, g := range seed.Grants {
		d.Edges = append(d.Edges, graph.Edge{ID: g.ID, Source: g.IdentityID, Target: g.RoleID, Kind: "ASSIGNED", Properties: map[string]string{"granted_by": g.By}})
	}
	for _, c := range seed.Control {
		d.Edges = append(d.Edges, graph.Edge{Source: c.Source, Target: c.Target, Kind: c.Kind})
	}
	for _, s := range seed.Sessions {
		props := map[string]string{}
		if s.Revoked {
			props["disabled"] = "true"
		}
		add(graph.Node{ID: s.ID, Type: "Session", Properties: props})
		if !s.Revoked {
			d.Edges = append(d.Edges, graph.Edge{Source: s.ID, Target: s.Identity, Kind: "CAN_ASSUME"})
		}
	}
	s, err := graph.Build(1000, d)
	if err != nil {
		return nil, err
	}
	return s, nil
}
