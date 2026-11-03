package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AdmissionWebhookHandler implements the RATCHET Validating Admission Webhook logic.
// Enforces fail-closed evaluation on unapproved privilege escalations while preserving legitimate reductions.
type AdmissionWebhookHandler struct {
	mu              sync.RWMutex
	approvedIntents map[string]*ApprovedIntent // key: intent_id
	failClosedMode  bool
}

// NewAdmissionWebhookHandler creates a new admission webhook handler.
func NewAdmissionWebhookHandler() *AdmissionWebhookHandler {
	return &AdmissionWebhookHandler{
		approvedIntents: make(map[string]*ApprovedIntent),
		failClosedMode:  true, // Always fail-closed on unapproved sensitive mutations
	}
}

// RegisterIntent registers a one-time approved RATCHET decision for admission.
func (h *AdmissionWebhookHandler) RegisterIntent(intent *ApprovedIntent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.approvedIntents[intent.IntentID] = intent
}

// HandleAdmission processes an incoming Kubernetes AdmissionRequest and returns the AdmissionResponse.
func (h *AdmissionWebhookHandler) HandleAdmission(req *AdmissionRequest) *AdmissionResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	uid := req.UID

	// 1. Legitimate Reduction: DELETE is always allowed even during degraded control-plane availability
	if req.Operation == "DELETE" {
		return &AdmissionResponse{
			UID:     uid,
			Allowed: true,
			Status: &AdmissionStatus{
				Code:    http.StatusOK,
				Message: "RATCHET: reduction operation (DELETE) permitted",
			},
		}
	}

	// 2. Sensitive Privilege Escalation Detection on Role / ClusterRole
	kind := req.Kind["kind"]
	if kind == "Role" || kind == "ClusterRole" {
		rulesJSON, _ := json.Marshal(req.Object["rules"])
		var rules []PolicyRule
		_ = json.Unmarshal(rulesJSON, &rules)

		findings := DetectEscalationPrimitives(rules)
		if len(findings) > 0 {
			// Found escalation primitive(s) - check for approved intent
			intent := h.matchIntentLocked(req.Operation, kind, req.Object["metadata"])
			if intent == nil {
				// FAIL-CLOSED: Refuse unapproved escalation
				detail := findings[0].Details
				return &AdmissionResponse{
					UID:     uid,
					Allowed: false,
					Status: &AdmissionStatus{
						Code:    http.StatusForbidden,
						Reason:  "PrivilegeEscalationForbidden",
						Message: fmt.Sprintf("RATCHET: admission refused: unapproved escalation primitive detected (%s)", detail),
					},
				}
			}

			// Consume approved intent
			intent.Consumed = true
			return &AdmissionResponse{
				UID:     uid,
				Allowed: true,
				Status: &AdmissionStatus{
					Code:    http.StatusOK,
					Message: fmt.Sprintf("RATCHET: approved escalation admitted via intent %s (approved by %s)", intent.IntentID, intent.ApprovedBy),
				},
			}
		}
	}

	// 3. Sensitive Privilege Escalation Detection on RoleBinding / ClusterRoleBinding
	if kind == "RoleBinding" || kind == "ClusterRoleBinding" {
		roleRefJSON, _ := json.Marshal(req.Object["roleRef"])
		var roleRef RoleRef
		_ = json.Unmarshal(roleRefJSON, &roleRef)

		// High-privilege role binding (e.g. cluster-admin or admin)
		isHighPrivilege := roleRef.Name == "cluster-admin" || roleRef.Name == "admin"
		if isHighPrivilege {
			intent := h.matchIntentLocked(req.Operation, kind, req.Object["metadata"])
			if intent == nil {
				return &AdmissionResponse{
					UID:     uid,
					Allowed: false,
					Status: &AdmissionStatus{
						Code:    http.StatusForbidden,
						Reason:  "UnauthorizedRoleBinding",
						Message: fmt.Sprintf("RATCHET: admission refused: binding to %q requires verified RATCHET quorum approval", roleRef.Name),
					},
				}
			}

			intent.Consumed = true
			return &AdmissionResponse{
				UID:     uid,
				Allowed: true,
				Status: &AdmissionStatus{
					Code:    http.StatusOK,
					Message: fmt.Sprintf("RATCHET: approved binding to %q admitted via intent %s", roleRef.Name, intent.IntentID),
				},
			}
		}
	}

	// Normal non-escalating object permitted
	return &AdmissionResponse{
		UID:     uid,
		Allowed: true,
		Status: &AdmissionStatus{
			Code:    http.StatusOK,
			Message: "RATCHET: non-escalating RBAC update admitted",
		},
	}
}

func (h *AdmissionWebhookHandler) matchIntentLocked(op, kind string, metadata any) *ApprovedIntent {
	now := time.Now().UTC()

	metaMap, ok := metadata.(map[string]any)
	if !ok {
		return nil
	}
	objName, _ := metaMap["name"].(string)

	for _, intent := range h.approvedIntents {
		if !intent.Consumed && intent.ExpiresAt.After(now) {
			if intent.Operation == op && intent.TargetResource == objName {
				return intent
			}
		}
	}
	return nil
}
