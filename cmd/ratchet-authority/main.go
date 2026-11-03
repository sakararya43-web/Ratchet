package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/sakararya43-web/Ratchet/internal/trust"
)

type Server struct {
	store *trust.Store
}

func NewServer(store *trust.Store) *Server {
	return &Server{store: store}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/authority/registry", s.handleGetRegistry)
	mux.HandleFunc("GET /api/v1/authority/bundle/active", s.handleGetActiveBundle)
	mux.HandleFunc("POST /api/v1/authority/genesis", s.handleGenesis)
	mux.HandleFunc("POST /api/v1/authority/bundle/propose", s.handleProposeBundle)
	mux.HandleFunc("POST /api/v1/authority/bundle/sign", s.handleSignBundle)
	mux.HandleFunc("POST /api/v1/authority/bundle/activate", s.handleActivateBundle)

	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "ratchet-authority"})
}

func (s *Server) handleGetRegistry(w http.ResponseWriter, r *http.Request) {
	gen, err := s.store.GetGenesis()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, gen)
}

func (s *Server) handleGetActiveBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := s.store.GetActiveBundle()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

type GenesisRequest struct {
	TenantID   string `json:"tenant_id"`
	ThresholdM int    `json:"threshold_m"`
	TotalN     int    `json:"total_n"`
	Members    []struct {
		ActorID     string `json:"actor_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"` // hex encoded PKIX bytes
	} `json:"members"`
}

func (s *Server) handleGenesis(w http.ResponseWriter, r *http.Request) {
	var req GenesisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var members []trust.AuthorityMember
	for _, m := range req.Members {
		pkBytes, err := hex.DecodeString(m.PublicKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid hex public key for %s", m.ActorID), http.StatusBadRequest)
			return
		}
		members = append(members, trust.AuthorityMember{
			ActorID:     m.ActorID,
			DisplayName: m.DisplayName,
			PublicKey:   pkBytes,
			IsActive:    true,
		})
	}

	gen, err := s.store.InitGenesis(req.TenantID, req.ThresholdM, req.TotalN, members)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusCreated, gen)
}

type ProposeRequest struct {
	TenantID      string            `json:"tenant_id"`
	BundleVersion string            `json:"bundle_version"`
	Description   string            `json:"description"`
	Modules       map[string]string `json:"modules"`
	Data          map[string]any    `json:"data"`
}

func (s *Server) handleProposeBundle(w http.ResponseWriter, r *http.Request) {
	var req ProposeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	bundle, err := s.store.ProposeBundle(req.TenantID, req.BundleVersion, req.Description, req.Modules, req.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusCreated, bundle)
}

type SignRequest struct {
	ProposalID string `json:"proposal_id"`
	ActorID    string `json:"actor_id"`
	Signature  string `json:"signature"` // hex encoded signature bytes
}

func (s *Server) handleSignBundle(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature hex", http.StatusBadRequest)
		return
	}

	err = s.store.SignProposal(req.ProposalID, trust.MemberSignature{
		ActorID:   req.ActorID,
		Signature: sigBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

type ActivateRequest struct {
	ProposalID string `json:"proposal_id"`
}

func (s *Server) handleActivateBundle(w http.ResponseWriter, r *http.Request) {
	var req ActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	bundle, err := s.store.ActivateBundle(req.ProposalID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
		return
	}

	writeJSON(w, http.StatusOK, bundle)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	port := flag.Int("port", 8086, "Authority HTTP listen port")
	stateFile := flag.String("state", "authority_state.json", "Authority storage file")
	flag.Parse()

	store, err := trust.NewStore(*stateFile)
	if err != nil {
		log.Fatalf("failed to initialize authority store: %v", err)
	}

	srv := NewServer(store)
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting ratchet-authority on %s", addr)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatalf("authority server failed: %v", err)
	}
}
