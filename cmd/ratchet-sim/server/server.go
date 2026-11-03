package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
)

type Server struct {
	store       *domain.Store
	brokerToken string
}

func NewServer(store *domain.Store, brokerToken string) *Server {
	if brokerToken == "" {
		brokerToken = "sim-broker-secret"
	}
	return &Server{
		store:       store,
		brokerToken: brokerToken,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/org", s.handleGetOrg)
	mux.HandleFunc("GET /api/v1/identities", s.handleGetIdentities)
	mux.HandleFunc("GET /api/v1/roles", s.handleGetRoles)
	mux.HandleFunc("GET /api/v1/resources", s.handleGetResources)
	mux.HandleFunc("GET /api/v1/safeguards", s.handleGetSafeguards)
	mux.HandleFunc("GET /api/v1/audit", s.handleGetAudit)
	mux.HandleFunc("POST /api/v1/reset", s.handleReset)
	mux.HandleFunc("POST /api/v1/execute", s.handleExecute)
	mux.HandleFunc("POST /api/v1/probe", s.handleProbe)
	mux.HandleFunc("POST /api/v1/business/finance-report/read", s.handleBusinessFinanceReport)
	mux.HandleFunc("POST /api/v1/business/wallet/sign", s.handleBusinessWalletSign)

	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"tenant":   state.TenantID,
		"revision": state.Revision,
	})
}

func (s *Server) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleGetIdentities(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, state.Identities)
}

func (s *Server) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, state.Roles)
}

func (s *Server) handleGetResources(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, state.Resources)
}

func (s *Server) handleGetSafeguards(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, state.Safeguards)
}

func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	state := s.store.GetState()
	sinceStr := r.URL.Query().Get("since_revision")

	if sinceStr == "" {
		writeJSON(w, http.StatusOK, state.AuditLog)
		return
	}

	sinceRev, err := strconv.ParseInt(sinceStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid since_revision", http.StatusBadRequest)
		return
	}

	var filtered []domain.TargetAuditEntry
	for _, entry := range state.AuditLog {
		if entry.Revision > sinceRev {
			filtered = append(filtered, entry)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ResetToSeed(); err != nil {
		http.Error(w, fmt.Sprintf("reset error: %v", err), http.StatusInternalServerError)
		return
	}
	state := s.store.GetState()
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "simulator state reset to deterministic seed",
		"revision": state.Revision,
	})
}

type ExecuteRequest struct {
	CommandID      string `json:"command_id"`
	Action         string `json:"action"` // ASSIGN_ROLE, REVOKE_ROLE, TERMINATE_SESSION, RESTRICT_ACCOUNT
	TargetIdentity string `json:"target_identity"`
	ResourceOrRole string `json:"resource_or_role"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	expected := "Bearer " + s.brokerToken
	if authHeader != expected {
		http.Error(w, "unauthorized: broker credentials required", http.StatusUnauthorized)
		return
	}

	var req ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	actorID := "broker:ratchet-connector"
	var err error

	switch req.Action {
	case "ASSIGN_ROLE":
		err = s.store.AssignRole(actorID, req.TargetIdentity, req.ResourceOrRole)
	case "REVOKE_ROLE":
		err = s.store.RevokeRole(actorID, req.TargetIdentity, req.ResourceOrRole)
	case "TERMINATE_SESSION":
		err = s.store.TerminateSession(actorID, req.ResourceOrRole)
	case "RESTRICT_ACCOUNT":
		err = s.store.RestrictAccount(actorID, req.TargetIdentity)
	default:
		http.Error(w, fmt.Sprintf("unsupported action %q", req.Action), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("execution failed: %v", err), http.StatusUnprocessableEntity)
		return
	}

	state := s.store.GetState()
	var currentRoles []string
	for _, g := range state.Grants {
		if g.IdentityID == req.TargetIdentity {
			currentRoles = append(currentRoles, g.RoleID)
		}
	}

	var activeSessions []string
	for _, sess := range state.Sessions {
		if sess.IdentityID == req.TargetIdentity && !sess.IsRevoked {
			activeSessions = append(activeSessions, sess.SessionID)
		}
	}

	isDisabled := false
	for _, id := range state.Identities {
		if id.ID == req.TargetIdentity {
			isDisabled = id.IsDisabled
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"command_id": req.CommandID,
		"success":    true,
		"revision":   state.Revision,
		"observed_state": map[string]any{
			"target_identity": req.TargetIdentity,
			"current_roles":   currentRoles,
			"active_sessions": activeSessions,
			"is_restricted":   isDisabled,
		},
	})
}

type ProbeRequest struct {
	IdentityID string `json:"identity_id"`
	ResourceID string `json:"resource_id"`
	Action     string `json:"action"`
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req ProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid probe request", http.StatusBadRequest)
		return
	}

	result := s.store.CheckAccess(req.IdentityID, req.ResourceID, req.Action)
	writeJSON(w, http.StatusOK, result)
}

type BusinessReportRequest struct {
	SessionID string `json:"session_id"`
}

func (s *Server) handleBusinessFinanceReport(w http.ResponseWriter, r *http.Request) {
	var req BusinessReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result, actor := s.store.CheckSessionAccess(req.SessionID, "res:finance-reports", "read")
	if !result.Allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "forbidden",
			"reason": result.Reason,
			"actor":  actor,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"actor":       actor,
		"report_name": "Q3-2026-Trading-Volume-Summary",
		"data": map[string]any{
			"total_matched_volume_usd": 4200000000,
			"cleared_settlements":      145020,
			"generated_at":             "2026-11-03T00:00:00Z",
		},
	})
}

type BusinessSignRequest struct {
	SessionID string  `json:"session_id"`
	AmountUSD float64 `json:"amount_usd"`
}

func (s *Server) handleBusinessWalletSign(w http.ResponseWriter, r *http.Request) {
	var req BusinessSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result, actor := s.store.CheckSessionAccess(req.SessionID, "svc:wallet-signer", "sign")
	if !result.Allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "forbidden",
			"reason": result.Reason,
			"actor":  actor,
		})
		return
	}

	if req.AmountUSD > 10000 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "safeguard_violation",
			"safeguard": "safeguard:withdrawal-rule",
			"reason":    "dual approval required for withdrawals exceeding $10,000",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "signed",
		"actor":  actor,
		"tx_id":  "0x89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

