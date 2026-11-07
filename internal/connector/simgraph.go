package connector

import (
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
)

// buildSimulatorGraph encodes the simulator's explicit permission/control
// semantics. It preserves target identities, revocation state and grant IDs.
func buildSimulatorGraph(org *domain.OrgState) ([]GraphNode, []GraphEdge) {
	nodes := []GraphNode{}
	edges := []GraphEdge{}
	known := map[string]bool{}
	addNode := func(n GraphNode) {
		if !known[n.ID] {
			nodes = append(nodes, n)
			known[n.ID] = true
		}
	}
	for _, identity := range org.Identities {
		p := maps.Clone(identity.Properties)
		if p == nil {
			p = map[string]string{}
		}
		p["disabled"] = strconv.FormatBool(identity.IsDisabled)
		addNode(GraphNode{ID: identity.ID, Type: string(identity.Type), DisplayName: identity.DisplayName, Properties: p})
	}
	for _, role := range org.Roles {
		addNode(GraphNode{ID: role.ID, Type: "Role", DisplayName: role.DisplayName, Properties: maps.Clone(role.Properties)})
	}
	for _, resource := range org.Resources {
		addNode(GraphNode{ID: resource.ID, Type: "Resource", Tier: resource.Tier, DisplayName: resource.DisplayName, Properties: maps.Clone(resource.Properties)})
	}
	for _, guard := range org.Safeguards {
		addNode(GraphNode{ID: guard.ID, Type: "Safeguard", Tier: guard.Tier, DisplayName: guard.DisplayName, Properties: maps.Clone(guard.Parameters)})
		for _, resource := range guard.ProtectedResources {
			edges = append(edges, GraphEdge{Source: guard.ID, Target: resource, Kind: "PROTECTED_BY"})
		}
	}
	for _, grant := range org.Grants {
		properties := map[string]string{"grant_id": grant.ID, "granted_by": grant.GrantedBy, "granted_at": grant.GrantedAt.UTC().Format(time.RFC3339Nano)}
		if grant.ExpiresAt != nil {
			properties["expires_at"] = grant.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		edges = append(edges, GraphEdge{Source: grant.IdentityID, Target: grant.RoleID, Kind: "ASSIGNED", Properties: properties})
	}
	for _, role := range org.Roles {
		for _, permission := range role.Permissions {
			separator := strings.LastIndexByte(permission, ':')
			if separator < 1 {
				continue
			}
			resource, action := permission[:separator], permission[separator+1:]
			// Logical policy/audit permissions are Permission nodes, not fabricated
			// resources. iam:all explicitly denotes control of the whole target IAM.
			if resource == "iam" && action == "all" {
				for _, identity := range org.Identities {
					edges = append(edges, GraphEdge{Source: role.ID, Target: identity.ID, Kind: "CAN_ADMINISTER"})
				}
				for _, r := range org.Roles {
					edges = append(edges, GraphEdge{Source: role.ID, Target: r.ID, Kind: "CAN_MODIFY"})
				}
				for _, g := range org.Safeguards {
					edges = append(edges, GraphEdge{Source: role.ID, Target: g.ID, Kind: "CAN_MODIFY"})
				}
				for _, r := range org.Resources {
					edges = append(edges, GraphEdge{Source: role.ID, Target: r.ID, Kind: "GRANTS", Action: "*"})
				}
				continue
			}
			if !known[resource] {
				resource = "permission:" + permission
				addNode(GraphNode{ID: resource, Type: "Permission", DisplayName: permission})
			}
			if action == "all" {
				action = "*"
			}
			edges = append(edges, GraphEdge{Source: role.ID, Target: resource, Kind: "GRANTS", Action: action})
		}
	}
	for _, relation := range org.ControlRelations {
		edges = append(edges, GraphEdge{Source: relation.ControllerID, Target: relation.ControlledID, Kind: relation.Kind})
	}
	for _, session := range org.Sessions {
		addNode(GraphNode{ID: session.SessionID, Type: "Session", Properties: map[string]string{"disabled": strconv.FormatBool(session.IsRevoked), "owner": session.IdentityID}})
		edges = append(edges, GraphEdge{Source: session.IdentityID, Target: session.SessionID, Kind: "GRANTS", Action: "use"}, GraphEdge{Source: session.SessionID, Target: session.IdentityID, Kind: "CAN_ASSUME"})
	}
	return nodes, edges
}
