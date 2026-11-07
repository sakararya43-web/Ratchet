package connector

import (
	"context"
	"encoding/json"
	"fmt"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"os"
	"sync"
	"time"

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
	TenantID       string                `json:"tenant_id"`
	ConnectorID    string                `json:"connector_id"`
	SourceRevision int64                 `json:"source_revision"`
	Nodes          []GraphNode           `json:"nodes"`
	Edges          []GraphEdge           `json:"edges"`
	Timestamp      string                `json:"timestamp"`
	Complete       bool                  `json:"complete"`
	Envelope       *v1.ConnectorEnvelope `json:"envelope,omitempty"`
}

// GraphDelta represents an incremental update from a known revision.
type GraphDelta struct {
	TenantID     string      `json:"tenant_id"`
	ConnectorID  string      `json:"connector_id"`
	FromRevision int64       `json:"from_revision"`
	ToRevision   int64       `json:"to_revision"`
	NodesAdded   []GraphNode `json:"nodes_added,omitempty"`
	NodesRemoved []string    `json:"nodes_removed,omitempty"`
	EdgesAdded   []GraphEdge `json:"edges_added,omitempty"`
	EdgesRemoved []GraphEdge `json:"edges_removed,omitempty"`
	Timestamp    string      `json:"timestamp"`
}

// ExecCommand represents an authorized IAM modification to apply on the target.
type ExecCommand struct {
	Deadline               time.Time `json:"deadline,omitempty"`
	CommandID              string    `json:"command_id"`
	TenantID               string    `json:"tenant_id"`
	RequestID              string    `json:"request_id"`
	Action                 string    `json:"action"` // ASSIGN_ROLE, REVOKE_ROLE, TERMINATE_SESSION, RESTRICT_ACCOUNT
	TargetIdentity         string    `json:"target_identity"`
	ResourceOrRole         string    `json:"resource_or_role"`
	ExpectedTargetRevision int64     `json:"expected_target_revision"`
	IsReduction            bool      `json:"is_reduction"`
}

// ObservedState represents the independently verified target IAM state.
type ObservedState struct {
	TenantID         string   `json:"tenant_id"`
	TargetIdentity   string   `json:"target_identity"`
	CurrentRoles     []string `json:"current_roles"`
	ActiveSessions   []string `json:"active_sessions"`
	IsRestricted     bool     `json:"is_restricted"`
	ObservedRevision int64    `json:"observed_revision"`
}

// ExecResult captures the execution and read-back verification evidence.
type ExecResult struct {
	CommandID           string        `json:"command_id"`
	Success             bool          `json:"success"`
	ErrorMessage        string        `json:"error_message,omitempty"`
	AppliedAt           string        `json:"applied_at"`
	TargetRevisionAfter int64         `json:"target_revision_after"`
	ObservedState       ObservedState `json:"observed_state"`
}

// TargetAdapter defines the capability required to integrate any external IAM/infrastructure target.
type TargetAdapter interface {
	Name() string
	FetchSnapshot(ctx context.Context) (*GraphSnapshot, error)
	FetchDelta(ctx context.Context, fromRevision int64) (*GraphDelta, error)
	Execute(ctx context.Context, cmd *ExecCommand) (*ExecResult, error)
	Verify(ctx context.Context, cmd *ExecCommand) (*ObservedState, error)
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
			if err := json.Unmarshal(data, &cur); err != nil || cur.Cursor < 0 {
				return nil, fmt.Errorf("invalid persistent source cursor")
			}
			cs.cursor = cur.Cursor
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
	if cursor < 0 {
		return fmt.Errorf("negative source cursor")
	}
	if cs.filePath != "" {
		if err := WritePrivateJSON(cs.filePath, map[string]int64{"cursor": cursor}); err != nil {
			return err
		}
	}
	cs.cursor = cursor
	return nil
}

// BuildGraphElements converts simulator domain OrgState into generic GraphNodes and GraphEdges.
func BuildGraphElements(org *domain.OrgState) ([]GraphNode, []GraphEdge) {
	return buildSimulatorGraph(org)
}
