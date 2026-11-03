package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// Allowed priority reduction actions
const (
	ActionTerminateSession        = "TERMINATE_SESSION"
	ActionRevokeRole              = "REVOKE_ROLE"
	ActionRestrictAccount         = "RESTRICT_ACCOUNT"
	ActionRemoveServicePermission = "REMOVE_SERVICE_PERMISSION"
)

// ContainmentAction specifies one single reduction operation in a cut plan.
type ContainmentAction struct {
	ActionID                string `json:"action_id"`
	ActionType              string `json:"action_type"` // TERMINATE_SESSION, REVOKE_ROLE, RESTRICT_ACCOUNT, REMOVE_SERVICE_PERMISSION
	TargetIdentity          string `json:"target_identity"`
	TargetResourceOrSession string `json:"target_resource_or_session"`
	CorrelationID           string `json:"correlation_id"`
}

// ContainmentPlan is a signed, server-computed minimum cut plan.
type ContainmentPlan struct {
	PlanID                string              `json:"plan_id"`
	TenantID              string              `json:"tenant_id"`
	IncidentID            string              `json:"incident_id"`
	TargetIdentity        string              `json:"target_identity"`
	Actions               []ContainmentAction `json:"actions"`
	PlanDigest            ports.Digest        `json:"plan_digest"`
	ConfirmationSignature []byte              `json:"confirmation_signature"`
	ConfirmedBy           string              `json:"confirmed_by"`
	CreatedAt             time.Time           `json:"created_at"`
}

// ContainmentActionResult records execution and verification for a single action.
type ContainmentActionResult struct {
	ActionID       string        `json:"action_id"`
	ActionType     string        `json:"action_type"`
	TargetIdentity string        `json:"target_identity"`
	Success        bool          `json:"success"`
	ErrorMessage   string        `json:"error_message,omitempty"`
	ObservedState  ObservedState `json:"observed_state"`
	ExecutedAt     time.Time     `json:"executed_at"`
	LatencyMs      int64         `json:"latency_ms"`
}

// ContainmentPlanResult aggregates the outcomes of an entire executed plan.
type ContainmentPlanResult struct {
	PlanID              string                    `json:"plan_id"`
	IncidentID          string                    `json:"incident_id"`
	TotalActions        int                       `json:"total_actions"`
	SucceededActions    int                       `json:"succeeded_actions"`
	FailedActions       int                       `json:"failed_actions"`
	ActionResults       []ContainmentActionResult `json:"action_results"`
	CompletedAt         time.Time                 `json:"completed_at"`
	TotalLatencyMs      int64                     `json:"total_latency_ms"`
	TargetRevisionAfter int64                     `json:"target_revision_after"`
}

// PriorityContainmentEngine executes reduction commands on a dedicated high-priority queue.
type PriorityContainmentEngine struct {
	mu        sync.RWMutex
	adapter   TargetAdapter
	statePath string
	history   map[string]*ContainmentPlanResult // key: plan_id
}

func NewPriorityContainmentEngine(adapter TargetAdapter, statePath string) (*PriorityContainmentEngine, error) {
	pce := &PriorityContainmentEngine{
		adapter:   adapter,
		statePath: statePath,
		history:   make(map[string]*ContainmentPlanResult),
	}

	if statePath != "" {
		if _, err := os.Stat(statePath); err == nil {
			if err := pce.loadFromFile(); err != nil {
				return nil, fmt.Errorf("failed to load containment engine history: %w", err)
			}
		}
	}

	return pce, nil
}

// ExecutePlan runs each action in the containment plan through the adapter with dedicated worker capacity.
func (pce *PriorityContainmentEngine) ExecutePlan(ctx context.Context, plan *ContainmentPlan) (*ContainmentPlanResult, error) {
	pce.mu.Lock()
	defer pce.mu.Unlock()

	if len(plan.Actions) == 0 {
		return nil, fmt.Errorf("cannot execute empty containment plan")
	}

	startTime := time.Now().UTC()
	var actionResults []ContainmentActionResult
	succeeded := 0
	failed := 0
	var lastRevision int64

	for _, action := range plan.Actions {
		actionStart := time.Now().UTC()

		// Validate reduction action allowlist: never trust non-reduction commands on priority subject
		if !isReductionAction(action.ActionType) {
			result := ContainmentActionResult{
				ActionID:       action.ActionID,
				ActionType:     action.ActionType,
				TargetIdentity: action.TargetIdentity,
				Success:        false,
				ErrorMessage:   fmt.Sprintf("action %q is not a permitted reduction operation", action.ActionType),
				ExecutedAt:     actionStart,
				LatencyMs:      time.Since(actionStart).Milliseconds(),
			}
			actionResults = append(actionResults, result)
			failed++
			continue
		}

		// Map to connector ExecCommand
		execCmd := &ExecCommand{
			CommandID:      action.ActionID,
			TenantID:       plan.TenantID,
			RequestID:      plan.PlanID,
			Action:         action.ActionType,
			TargetIdentity: action.TargetIdentity,
			ResourceOrRole: action.TargetResourceOrSession,
			IsReduction:    true,
		}

		// Execute on target adapter
		execRes, err := pce.adapter.Execute(ctx, execCmd)
		if err != nil || !execRes.Success {
			errMsg := "execution failed"
			if err != nil {
				errMsg = err.Error()
			} else if execRes != nil && execRes.ErrorMessage != "" {
				errMsg = execRes.ErrorMessage
			}
			result := ContainmentActionResult{
				ActionID:       action.ActionID,
				ActionType:     action.ActionType,
				TargetIdentity: action.TargetIdentity,
				Success:        false,
				ErrorMessage:   errMsg,
				ExecutedAt:     actionStart,
				LatencyMs:      time.Since(actionStart).Milliseconds(),
			}
			actionResults = append(actionResults, result)
			failed++
			continue
		}

		lastRevision = execRes.TargetRevisionAfter

		// Independently verify read-back
		observed, err := pce.adapter.Verify(ctx, execCmd)
		if err != nil {
			result := ContainmentActionResult{
				ActionID:       action.ActionID,
				ActionType:     action.ActionType,
				TargetIdentity: action.TargetIdentity,
				Success:        false,
				ErrorMessage:   fmt.Sprintf("read-back verification failed: %v", err),
				ExecutedAt:     actionStart,
				LatencyMs:      time.Since(actionStart).Milliseconds(),
			}
			actionResults = append(actionResults, result)
			failed++
			continue
		}

		result := ContainmentActionResult{
			ActionID:       action.ActionID,
			ActionType:     action.ActionType,
			TargetIdentity: action.TargetIdentity,
			Success:        true,
			ObservedState:  *observed,
			ExecutedAt:     actionStart,
			LatencyMs:      time.Since(actionStart).Milliseconds(),
		}
		actionResults = append(actionResults, result)
		succeeded++
	}

	totalDuration := time.Since(startTime).Milliseconds()
	planResult := &ContainmentPlanResult{
		PlanID:              plan.PlanID,
		IncidentID:          plan.IncidentID,
		TotalActions:        len(plan.Actions),
		SucceededActions:    succeeded,
		FailedActions:       failed,
		ActionResults:       actionResults,
		CompletedAt:         time.Now().UTC(),
		TotalLatencyMs:      totalDuration,
		TargetRevisionAfter: lastRevision,
	}

	pce.history[plan.PlanID] = planResult
	if pce.statePath != "" {
		_ = pce.saveToFile()
	}

	return planResult, nil
}

// GetPlanResult retrieves a previously executed containment plan result.
func (pce *PriorityContainmentEngine) GetPlanResult(planID string) (*ContainmentPlanResult, error) {
	pce.mu.RLock()
	defer pce.mu.RUnlock()

	res, ok := pce.history[planID]
	if !ok {
		return nil, fmt.Errorf("containment plan %q not found", planID)
	}
	return res, nil
}

func isReductionAction(action string) bool {
	switch action {
	case ActionTerminateSession, ActionRevokeRole, ActionRestrictAccount, ActionRemoveServicePermission:
		return true
	default:
		return false
	}
}

func (pce *PriorityContainmentEngine) loadFromFile() error {
	data, err := os.ReadFile(pce.statePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &pce.history)
}

func (pce *PriorityContainmentEngine) saveToFile() error {
	data, err := json.MarshalIndent(pce.history, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(pce.statePath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	tmp := pce.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, pce.statePath)
}
