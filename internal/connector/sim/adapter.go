package sim

import (
	"bytes"
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

// Execute applies an authorized IAM command to the simulator via broker authentication.
func (a *Adapter) Execute(ctx context.Context, cmd *connector.ExecCommand) (*connector.ExecResult, error) {
	payload, err := json.Marshal(map[string]any{
		"command_id":               cmd.CommandID,
		"tenant_id":                cmd.TenantID,
		"expected_target_revision": cmd.ExpectedTargetRevision,
		"action":                   cmd.Action,
		"target_identity":          cmd.TargetIdentity,
		"resource_or_role":         cmd.ResourceOrRole,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/api/v1/execute", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.brokerToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach target: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return &connector.ExecResult{
			CommandID:    cmd.CommandID,
			Success:      false,
			ErrorMessage: fmt.Sprintf("target returned HTTP %d: %v", resp.StatusCode, errResp),
			AppliedAt:    time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	var simResult struct {
		CommandID     string `json:"command_id"`
		Success       bool   `json:"success"`
		Revision      int64  `json:"revision"`
		ObservedState struct {
			TargetIdentity string   `json:"target_identity"`
			CurrentRoles   []string `json:"current_roles"`
			ActiveSessions []string `json:"active_sessions"`
			IsRestricted   bool     `json:"is_restricted"`
		} `json:"observed_state"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&simResult); err != nil {
		return nil, fmt.Errorf("failed to decode execution result: %w", err)
	}

	return &connector.ExecResult{
		CommandID:           cmd.CommandID,
		Success:             simResult.Success,
		AppliedAt:           time.Now().UTC().Format(time.RFC3339),
		TargetRevisionAfter: simResult.Revision,
		ObservedState: connector.ObservedState{
			TenantID:         cmd.TenantID,
			TargetIdentity:   simResult.ObservedState.TargetIdentity,
			CurrentRoles:     simResult.ObservedState.CurrentRoles,
			ActiveSessions:   simResult.ObservedState.ActiveSessions,
			IsRestricted:     simResult.ObservedState.IsRestricted,
			ObservedRevision: simResult.Revision,
		},
	}, nil
}

// Verify independently reads back the target's actual IAM state to prove the change took effect.
func (a *Adapter) Verify(ctx context.Context, cmd *connector.ExecCommand) (*connector.ObservedState, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+"/api/v1/org", nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach simulator for verification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read-back failed with HTTP %d", resp.StatusCode)
	}

	var org domain.OrgState
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil, fmt.Errorf("failed to decode verification state: %w", err)
	}

	var currentRoles []string
	for _, g := range org.Grants {
		if g.IdentityID == cmd.TargetIdentity {
			currentRoles = append(currentRoles, g.RoleID)
		}
	}

	var activeSessions []string
	for _, s := range org.Sessions {
		if s.IdentityID == cmd.TargetIdentity && !s.IsRevoked {
			activeSessions = append(activeSessions, s.SessionID)
		}
	}

	isRestricted := false
	for _, id := range org.Identities {
		if id.ID == cmd.TargetIdentity {
			isRestricted = id.IsDisabled
			break
		}
	}

	// Verify expected state matches actual state
	switch cmd.Action {
	case "ASSIGN_ROLE":
		found := false
		for _, r := range currentRoles {
			if r == cmd.ResourceOrRole {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("read-back mismatch: assigned role %q not observed in target", cmd.ResourceOrRole)
		}
	case "REVOKE_ROLE", "REMOVE_SERVICE_PERMISSION":
		for _, r := range currentRoles {
			if r == cmd.ResourceOrRole {
				return nil, fmt.Errorf("read-back mismatch: revoked role %q still observed in target", cmd.ResourceOrRole)
			}
		}
	case "RESTRICT_ACCOUNT":
		if !isRestricted {
			return nil, fmt.Errorf("read-back mismatch: target account %q is not marked restricted", cmd.TargetIdentity)
		}
	case "TERMINATE_SESSION":
		for _, s := range activeSessions {
			if s == cmd.ResourceOrRole {
				return nil, fmt.Errorf("read-back mismatch: terminated session %q still active in target", cmd.ResourceOrRole)
			}
		}
	}

	return &connector.ObservedState{
		TenantID:         cmd.TenantID,
		TargetIdentity:   cmd.TargetIdentity,
		CurrentRoles:     currentRoles,
		ActiveSessions:   activeSessions,
		IsRestricted:     isRestricted,
		ObservedRevision: org.Revision,
	}, nil
}

func (a *Adapter) isSessionActive(sessions []domain.Session, sessionID string) bool {
	for _, s := range sessions {
		if s.SessionID == sessionID && !s.IsRevoked {
			return true
		}
	}
	return false
}
