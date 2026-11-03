package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
)

// GraphNode mirrors the protobuf GraphNode for serialization across transports.
type GraphNode struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // Human, ServiceAccount, Group, Role, Permission, Resource, Safeguard, Session
	Tier        int               `json:"tier"` // Criticality tier 0-3
	DisplayName string            `json:"display_name"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// GraphEdge mirrors the protobuf GraphEdge.
type GraphEdge struct {
	Source     string            `json:"source"`
	Target     string            `json:"target"`
	Kind       string            `json:"kind"`   // MEMBER_OF, ASSIGNED, GRANTS, CAN_ASSUME, CAN_ADMINISTER, CAN_MODIFY, CAN_APPROVE, PROTECTED_BY
	Action     string            `json:"action"` // e.g. read, admin, sign
	Properties map[string]string `json:"properties,omitempty"`
}

// GraphSnapshot represents the full graph state ingested from a target.
type GraphSnapshot struct {
	TenantID       string      `json:"tenant_id"`
	ConnectorID    string      `json:"connector_id"`
	SourceRevision int64       `json:"source_revision"`
	Nodes          []GraphNode `json:"nodes"`
	Edges          []GraphEdge `json:"edges"`
	Timestamp      string      `json:"timestamp"`
}

// GraphDelta represents an incremental update from a known revision.
type GraphDelta struct {
	TenantID       string      `json:"tenant_id"`
	ConnectorID    string      `json:"connector_id"`
	FromRevision   int64       `json:"from_revision"`
	ToRevision     int64       `json:"to_revision"`
	NodesAdded     []GraphNode `json:"nodes_added,omitempty"`
	NodesRemoved   []string    `json:"nodes_removed,omitempty"`
	EdgesAdded     []GraphEdge `json:"edges_added,omitempty"`
	EdgesRemoved   []GraphEdge `json:"edges_removed,omitempty"`
	Timestamp      string      `json:"timestamp"`
}

// TargetAdapter defines the capability required to integrate any external IAM/infrastructure target.
type TargetAdapter interface {
	Name() string
	FetchSnapshot(ctx context.Context) (*GraphSnapshot, error)
	FetchDelta(ctx context.Context, fromRevision int64) (*GraphDelta, error)
}

// Publisher is an abstraction for publishing messages to the message backbone (NATS JetStream).
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// MemoryPublisher is an in-memory publisher useful for tests and standalone mode.
type MemoryPublisher struct {
	mu       sync.Mutex
	Messages map[string][][]byte
}

func NewMemoryPublisher() *MemoryPublisher {
	return &MemoryPublisher{
		Messages: make(map[string][][]byte),
	}
}

func (m *MemoryPublisher) Publish(ctx context.Context, subject string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Messages[subject] = append(m.Messages[subject], data)
	return nil
}

func (m *MemoryPublisher) GetMessages(subject string) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Messages[subject]
}

// CursorStore persists the latest acknowledged target revision cursor.
type CursorStore struct {
	mu       sync.Mutex
	filePath string
	cursor   int64
}

func NewCursorStore(filePath string) (*CursorStore, error) {
	cs := &CursorStore{filePath: filePath}
	if filePath != "" {
		if _, err := os.Stat(filePath); err == nil {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}
			var cur struct {
				Cursor int64 `json:"cursor"`
			}
			if err := json.Unmarshal(data, &cur); err == nil {
				cs.cursor = cur.Cursor
			}
		}
	}
	return cs, nil
}

func (cs *CursorStore) Get() int64 {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.cursor
}

func (cs *CursorStore) Set(cursor int64) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.cursor = cursor

	if cs.filePath != "" {
		dir := filepath.Dir(cs.filePath)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		data, _ := json.Marshal(map[string]int64{"cursor": cursor})
		return os.WriteFile(cs.filePath, data, 0644)
	}
	return nil
}

// BuildGraphElements converts simulator domain OrgState into generic GraphNodes and GraphEdges.
func BuildGraphElements(org *domain.OrgState) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	// 1. Identities
	for _, id := range org.Identities {
		nodes = append(nodes, GraphNode{
			ID:          id.ID,
			Type:        string(id.Type),
			DisplayName: id.DisplayName,
			Properties:  id.Properties,
		})
	}

	// 2. Roles
	for _, r := range org.Roles {
		nodes = append(nodes, GraphNode{
			ID:          r.ID,
			Type:        string(domain.NodeRole),
			DisplayName: r.DisplayName,
			Properties:  r.Properties,
		})
	}

	// 3. Resources
	for _, res := range org.Resources {
		nodes = append(nodes, GraphNode{
			ID:          res.ID,
			Type:        string(domain.NodeResource),
			Tier:        res.Tier,
			DisplayName: res.DisplayName,
			Properties:  res.Properties,
		})
	}

	// 4. Safeguards
	for _, sg := range org.Safeguards {
		nodes = append(nodes, GraphNode{
			ID:          sg.ID,
			Type:        string(domain.NodeSafeguard),
			Tier:        sg.Tier,
			DisplayName: sg.DisplayName,
			Properties:  sg.Parameters,
		})
		for _, pr := range sg.ProtectedResources {
			edges = append(edges, GraphEdge{
				Source: sg.ID,
				Target: pr,
				Kind:   "PROTECTED_BY",
			})
		}
	}

	// 5. Grants (Identity -> Role)
	for _, g := range org.Grants {
		edges = append(edges, GraphEdge{
			Source: g.IdentityID,
			Target: g.RoleID,
			Kind:   "ASSIGNED",
		})
	}

	// 6. Role Permissions (Role -> Resource)
	for _, r := range org.Roles {
		for _, perm := range r.Permissions {
			// Format: "resource_id:action"
			var resID, action string
			for i := len(perm) - 1; i >= 0; i-- {
				if perm[i] == ':' {
					resID = perm[:i]
					action = perm[i+1:]
					break
				}
			}
			if resID != "" {
				edges = append(edges, GraphEdge{
					Source: r.ID,
					Target: resID,
					Kind:   "GRANTS",
					Action: action,
				})
			}
		}
	}

	// 7. Control Relations (Takeover: Identity -> Identity)
	for _, cr := range org.ControlRelations {
		edges = append(edges, GraphEdge{
			Source: cr.ControllerID,
			Target: cr.ControlledID,
			Kind:   cr.Kind,
		})
	}

	return nodes, edges
}
