package k8s

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/connector"
)

// K8sClusterState holds stateful representations of Kubernetes RBAC objects in a target cluster.
type K8sClusterState struct {
	Revision            int64                 `json:"revision"`
	ServiceAccounts     []string              `json:"service_accounts"`
	Roles               []Role                `json:"roles"`
	ClusterRoles        []ClusterRole         `json:"cluster_roles"`
	RoleBindings        []RoleBinding         `json:"role_bindings"`
	ClusterRoleBindings []RoleBinding         `json:"cluster_role_bindings"`
}

// K8sAdapter implements connector.TargetAdapter for Kubernetes clusters.
type K8sAdapter struct {
	mu          sync.RWMutex
	tenantID    string
	connectorID string
	state       K8sClusterState
}

// NewK8sAdapter initializes a new K8sAdapter with deterministic baseline cluster RBAC state.
func NewK8sAdapter(tenantID, connectorID string) *K8sAdapter {
	if tenantID == "" {
		tenantID = "tenant-k8s-demo"
	}
	if connectorID == "" {
		connectorID = "connector-k8s-01"
	}

	// Deterministic baseline RBAC seed
	state := K8sClusterState{
		Revision: 100,
		ServiceAccounts: []string{
			"default:default",
			"kube-system:coredns",
			"default:deploy-worker",
		},
		ClusterRoles: []ClusterRole{
			{
				Name: "cluster-admin",
				Rules: []PolicyRule{
					{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				},
			},
			{
				Name: "view",
				Rules: []PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list", "watch"}},
				},
			},
		},
		Roles: []Role{
			{
				Name:      "pod-reader",
				Namespace: "default",
				Rules: []PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
				},
			},
		},
		RoleBindings: []RoleBinding{
			{
				Name:      "read-pods-binding",
				Namespace: "default",
				RoleRef:   RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "pod-reader"},
				Subjects:  []Subject{{Kind: "ServiceAccount", Name: "deploy-worker", Namespace: "default"}},
			},
		},
		ClusterRoleBindings: []RoleBinding{
			{
				Name:      "cluster-admin-binding",
				Namespace: "",
				RoleRef:   RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:  []Subject{{Kind: "User", Name: "admin"}},
			},
		},
	}

	return &K8sAdapter{
		tenantID:    tenantID,
		connectorID: connectorID,
		state:       state,
	}
}

func (a *K8sAdapter) Name() string {
	return "ratchet-k8s-adapter"
}

// FetchSnapshot maps Kubernetes RBAC resources into a full RATCHET GraphSnapshot.
func (a *K8sAdapter) FetchSnapshot(ctx context.Context) (*connector.GraphSnapshot, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var nodes []connector.GraphNode
	var edges []connector.GraphEdge

	// 1. ServiceAccounts & Users as Identity Nodes
	for _, sa := range a.state.ServiceAccounts {
		nodes = append(nodes, connector.GraphNode{
			ID:          "sa:" + sa,
			Type:        "ServiceAccount",
			Tier:        2,
			DisplayName: "K8s ServiceAccount " + sa,
		})
	}
	nodes = append(nodes, connector.GraphNode{
		ID:          "user:admin",
		Type:        "Human",
		Tier:        0,
		DisplayName: "Kubernetes Cluster Administrator",
	})

	// 2. Roles & ClusterRoles
	for _, cr := range a.state.ClusterRoles {
		findings := DetectEscalationPrimitives(cr.Rules)
		tier := 2
		if len(findings) > 0 || cr.Name == "cluster-admin" {
			tier = 0 // Criticality tier 0
		}
		roleNodeID := "clusterrole:" + cr.Name
		nodes = append(nodes, connector.GraphNode{
			ID:          roleNodeID,
			Type:        "Role",
			Tier:        tier,
			DisplayName: "ClusterRole " + cr.Name,
		})
	}

	for _, r := range a.state.Roles {
		findings := DetectEscalationPrimitives(r.Rules)
		tier := 2
		if len(findings) > 0 {
			tier = 1
		}
		roleNodeID := fmt.Sprintf("role:%s:%s", r.Namespace, r.Name)
		nodes = append(nodes, connector.GraphNode{
			ID:          roleNodeID,
			Type:        "Role",
			Tier:        tier,
			DisplayName: fmt.Sprintf("Role %s/%s", r.Namespace, r.Name),
		})
	}

	// 3. RoleBindings & ClusterRoleBindings as ASSIGNED Edges
	for _, b := range a.state.ClusterRoleBindings {
		targetRole := "clusterrole:" + b.RoleRef.Name
		for _, s := range b.Subjects {
			subjectID := "user:" + s.Name
			if s.Kind == "ServiceAccount" {
				subjectID = fmt.Sprintf("sa:%s:%s", s.Namespace, s.Name)
			}
			edges = append(edges, connector.GraphEdge{
				Source: subjectID,
				Target: targetRole,
				Kind:   "ASSIGNED",
				Action: "bind",
			})
		}
	}

	for _, b := range a.state.RoleBindings {
		targetRole := fmt.Sprintf("role:%s:%s", b.Namespace, b.RoleRef.Name)
		for _, s := range b.Subjects {
			subjectID := "user:" + s.Name
			if s.Kind == "ServiceAccount" {
				subjectID = fmt.Sprintf("sa:%s:%s", s.Namespace, s.Name)
			}
			edges = append(edges, connector.GraphEdge{
				Source: subjectID,
				Target: targetRole,
				Kind:   "ASSIGNED",
				Action: "bind",
			})
		}
	}

	return &connector.GraphSnapshot{
		TenantID:       a.tenantID,
		ConnectorID:    a.connectorID,
		SourceRevision: a.state.Revision,
		Nodes:          nodes,
		Edges:          edges,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// FetchDelta returns an incremental delta since fromRevision.
func (a *K8sAdapter) FetchDelta(ctx context.Context, fromRevision int64) (*connector.GraphDelta, error) {
	snap, err := a.FetchSnapshot(ctx)
	if err != nil {
		return nil, err
	}

	return &connector.GraphDelta{
		TenantID:     a.tenantID,
		ConnectorID:  a.connectorID,
		FromRevision: fromRevision,
		ToRevision:   snap.SourceRevision,
		NodesAdded:   snap.Nodes,
		EdgesAdded:   snap.Edges,
		Timestamp:    snap.Timestamp,
	}, nil
}

// Execute applies an authorized IAM change (RoleBinding creation or deletion) on Kubernetes.
func (a *K8sAdapter) Execute(ctx context.Context, cmd *connector.ExecCommand) (*connector.ExecResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch cmd.Action {
	case "ASSIGN_ROLE":
		// Create or update RoleBinding
		newBinding := RoleBinding{
			Name:      fmt.Sprintf("binding-%s-%s", cmd.TargetIdentity, cmd.ResourceOrRole),
			Namespace: "default",
			RoleRef:   RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: cmd.ResourceOrRole},
			Subjects:  []Subject{{Kind: "ServiceAccount", Name: cmd.TargetIdentity, Namespace: "default"}},
		}
		a.state.RoleBindings = append(a.state.RoleBindings, newBinding)
		a.state.Revision++

	case "REVOKE_ROLE":
		// Remove matching RoleBindings
		var remaining []RoleBinding
		for _, b := range a.state.RoleBindings {
			match := false
			if b.RoleRef.Name == cmd.ResourceOrRole {
				for _, s := range b.Subjects {
					if s.Name == cmd.TargetIdentity {
						match = true
						break
					}
				}
			}
			if !match {
				remaining = append(remaining, b)
			}
		}
		a.state.RoleBindings = remaining
		a.state.Revision++

	default:
		return nil, fmt.Errorf("unsupported Kubernetes operation: %s", cmd.Action)
	}

	obs, err := a.verifyLocked(cmd)
	if err != nil {
		return nil, err
	}

	return &connector.ExecResult{
		CommandID:           cmd.CommandID,
		Success:             true,
		AppliedAt:           time.Now().UTC().Format(time.RFC3339),
		TargetRevisionAfter: a.state.Revision,
		ObservedState:       *obs,
	}, nil
}

// Verify independently reads back the target state to confirm the expected role status.
func (a *K8sAdapter) Verify(ctx context.Context, cmd *connector.ExecCommand) (*connector.ObservedState, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.verifyLocked(cmd)
}

func (a *K8sAdapter) verifyLocked(cmd *connector.ExecCommand) (*connector.ObservedState, error) {
	var currentRoles []string
	for _, b := range a.state.RoleBindings {
		for _, s := range b.Subjects {
			if s.Name == cmd.TargetIdentity {
				currentRoles = append(currentRoles, b.RoleRef.Name)
			}
		}
	}

	if cmd.Action == "ASSIGN_ROLE" {
		found := false
		for _, r := range currentRoles {
			if r == cmd.ResourceOrRole {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("read-back mismatch: assigned role %q not found in RoleBindings for %q", cmd.ResourceOrRole, cmd.TargetIdentity)
		}
	} else if cmd.Action == "REVOKE_ROLE" {
		for _, r := range currentRoles {
			if r == cmd.ResourceOrRole {
				return nil, fmt.Errorf("read-back mismatch: revoked role %q still present in RoleBindings for %q", cmd.ResourceOrRole, cmd.TargetIdentity)
			}
		}
	}

	return &connector.ObservedState{
		TenantID:         cmd.TenantID,
		TargetIdentity:   cmd.TargetIdentity,
		CurrentRoles:     currentRoles,
		ObservedRevision: a.state.Revision,
	}, nil
}
