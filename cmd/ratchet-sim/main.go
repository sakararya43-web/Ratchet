package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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
	// Broker mode enforcement (PRD §5.9 & FR-K3): only connector holds credentials to change IAM
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	port := flag.Int("port", 8085, "Simulator HTTP listen port")
	stateFile := flag.String("state", "sim_data.json", "Path to simulator state persistence file")
	brokerToken := flag.String("token", os.Getenv("SIM_BROKER_TOKEN"), "Broker authorization token")
	flag.Parse()

	store, err := domain.NewStore(*stateFile)
	if err != nil {
		log.Fatalf("failed to initialize simulator store: %v", err)
	}

	server := NewServer(store, *brokerToken)
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting ratchet-sim on %s (state file: %s)", addr, *stateFile)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		log.Fatalf("simulator server failed: %v", err)
	}
}
