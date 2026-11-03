package sim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/internal/connector"
)

// Adapter implements connector.TargetAdapter for the simulated crypto exchange.
type Adapter struct {
	baseURL     string
	brokerToken string
	tenantID    string
	connectorID string
	client      *http.Client
}

// NewAdapter creates a new simulator adapter.
func NewAdapter(baseURL, brokerToken, tenantID, connectorID string) *Adapter {
	if tenantID == "" {
		tenantID = "tenant-exchange-demo"
	}
	if connectorID == "" {
		connectorID = "connector-sim-01"
	}
	return &Adapter{
		baseURL:     baseURL,
		brokerToken: brokerToken,
		tenantID:    tenantID,
		connectorID: connectorID,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (a *Adapter) Name() string {
	return "ratchet-sim-adapter"
}

// FetchSnapshot fetches the complete OrgState from the simulator and builds a GraphSnapshot.
func (a *Adapter) FetchSnapshot(ctx context.Context) (*connector.GraphSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/api/v1/org", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach simulator at %s: %w", a.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simulator returned non-200: %d", resp.StatusCode)
	}

	var org domain.OrgState
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil, fmt.Errorf("failed to decode org state: %w", err)
	}

	nodes, edges := connector.BuildGraphElements(&org)
	return &connector.GraphSnapshot{
		TenantID:       a.tenantID,
		ConnectorID:    a.connectorID,
		SourceRevision: org.Revision,
		Nodes:          nodes,
		Edges:          edges,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// FetchDelta fetches recent audit entries since fromRevision and builds an incremental GraphDelta.
func (a *Adapter) FetchDelta(ctx context.Context, fromRevision int64) (*connector.GraphDelta, error) {
	url := fmt.Sprintf("%s/api/v1/audit?since_revision=%d", a.baseURL, fromRevision)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simulator audit returned %d", resp.StatusCode)
	}

	var auditEntries []domain.TargetAuditEntry
	if err := json.NewDecoder(resp.Body).Decode(&auditEntries); err != nil {
		return nil, err
	}

	// Fetch current snapshot to resolve latest entities
	currentSnapshot, err := a.FetchSnapshot(ctx)
	if err != nil {
		return nil, err
	}

	delta := &connector.GraphDelta{
		TenantID:     a.tenantID,
		ConnectorID:  a.connectorID,
		FromRevision: fromRevision,
		ToRevision:   currentSnapshot.SourceRevision,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	// Translate audit events to added/removed graph edges and nodes
	for _, entry := range auditEntries {
		switch entry.Action {
		case "ASSIGN_ROLE":
			roleID := entry.Details["role_id"]
			delta.EdgesAdded = append(delta.EdgesAdded, connector.GraphEdge{
				Source: entry.Target,
				Target: roleID,
				Kind:   "ASSIGNED",
			})
		case "REVOKE_ROLE":
			roleID := entry.Details["role_id"]
			delta.EdgesRemoved = append(delta.EdgesRemoved, connector.GraphEdge{
				Source: entry.Target,
				Target: roleID,
				Kind:   "ASSIGNED",
			})
		case "RESTRICT_ACCOUNT":
			delta.NodesRemoved = append(delta.NodesRemoved, entry.Target)
		}
	}

	return delta, nil
}

