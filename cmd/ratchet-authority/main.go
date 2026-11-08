package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/sakararya43-web/Ratchet/internal/ports"
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
	mux.HandleFunc("GET /api/v1/authority/registry/history", s.handleGetRegistryHistory)
	mux.HandleFunc("POST /api/v1/authority/registry/propose", s.handleProposeRegistry)
	mux.HandleFunc("POST /api/v1/authority/registry/sign", s.handleSignRegistry)
	mux.HandleFunc("POST /api/v1/authority/registry/activate", s.handleActivateRegistry)
	mux.HandleFunc("GET /api/v1/authority/registry/proposals", s.handleListRegistryProposals)

	mux.HandleFunc("GET /api/v1/authority/bundle/active", s.handleGetActiveBundle)
	mux.HandleFunc("GET /api/v1/authority/bundle/proposals", s.handleListProposals)
	mux.HandleFunc("GET /api/v1/authority/bundle/history", s.handleGetBundleHistory)
	mux.HandleFunc("POST /api/v1/authority/genesis", s.handleGenesis)
	mux.HandleFunc("POST /api/v1/authority/bundle/propose", s.handleProposeBundle)
	mux.HandleFunc("POST /api/v1/authority/bundle/sign", s.handleSignBundle)
	mux.HandleFunc("POST /api/v1/authority/bundle/activate", s.handleActivateBundle)

	mux.HandleFunc("POST /api/v1/authority/checkpoint/create", s.handleCreateCheckpoint)
	mux.HandleFunc("POST /api/v1/authority/checkpoint/sign", s.handleSignCheckpoint)
	mux.HandleFunc("GET /api/v1/authority/checkpoint/latest", s.handleGetLatestCheckpoint)
	mux.HandleFunc("GET /api/v1/authority/checkpoint/list", s.handleListCheckpoints)

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

func (s *Server) handleGetRegistryHistory(w http.ResponseWriter, r *http.Request) {
	history := s.store.GetRegistryHistory()
	writeJSON(w, http.StatusOK, history)
}

func (s *Server) handleGetActiveBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := s.store.GetActiveBundle()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
	proposals := s.store.ListProposals()
	writeJSON(w, http.StatusOK, proposals)
}

func (s *Server) handleGetBundleHistory(w http.ResponseWriter, r *http.Request) {
	history := s.store.GetHistory()
	writeJSON(w, http.StatusOK, history)
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

type ProposeRegistryRequest struct {
	TenantID  string `json:"tenant_id"`
	ProposedM int    `json:"proposed_m"`
	ProposedN int    `json:"proposed_n"`
	Members   []struct {
		ActorID     string `json:"actor_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
		IsActive    bool   `json:"is_active"`
	} `json:"members"`
}

func (s *Server) handleProposeRegistry(w http.ResponseWriter, r *http.Request) {
	var req ProposeRegistryRequest
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
			IsActive:    m.IsActive,
		})
	}

	prop, err := s.store.ProposeRegistryChange(req.TenantID, req.ProposedM, req.ProposedN, members)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusCreated, prop)
}

func (s *Server) handleSignRegistry(w http.ResponseWriter, r *http.Request) {
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

	err = s.store.SignRegistryProposal(req.ProposalID, trust.MemberSignature{
		ActorID:   req.ActorID,
		Signature: sigBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleActivateRegistry(w http.ResponseWriter, r *http.Request) {
	var req ActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	gen, err := s.store.ActivateRegistryProposal(req.ProposalID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
		return
	}

	writeJSON(w, http.StatusOK, gen)
}

func (s *Server) handleListRegistryProposals(w http.ResponseWriter, r *http.Request) {
	proposals := s.store.ListRegistryProposals()
	writeJSON(w, http.StatusOK, proposals)
}

type CreateCheckpointRequest struct {
	TenantID              string   `json:"tenant_id"`
	FromSequence          int64    `json:"from_sequence"`
	ToSequence            int64    `json:"to_sequence"`
	EventDigests          []string `json:"event_digests"`
	PriorCheckpointDigest string   `json:"prior_checkpoint_digest"`
}

func (s *Server) handleCreateCheckpoint(w http.ResponseWriter, r *http.Request) {
	var req CreateCheckpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var leaves []ports.Digest
	for _, dStr := range req.EventDigests {
		d, err := ports.DigestFromHex(dStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid event digest %q: %v", dStr, err), http.StatusBadRequest)
			return
		}
		leaves = append(leaves, d)
	}

	var priorDigest ports.Digest
	if req.PriorCheckpointDigest != "" {
		pd, err := ports.DigestFromHex(req.PriorCheckpointDigest)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid prior checkpoint digest %q: %v", req.PriorCheckpointDigest, err), http.StatusBadRequest)
			return
		}
		priorDigest = pd
	}

	chk, err := s.store.CreateCheckpoint(req.TenantID, req.FromSequence, req.ToSequence, leaves, priorDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.store.SaveCheckpoint(chk); err != nil {
		http.Error(w, fmt.Sprintf("failed to save checkpoint: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, chk)
}

type SignCheckpointRequest struct {
	CheckpointID string `json:"checkpoint_id"`
	ActorID      string `json:"actor_id"`
	Signature    string `json:"signature"` // hex encoded ASN.1 signature
}

func (s *Server) handleSignCheckpoint(w http.ResponseWriter, r *http.Request) {
	var req SignCheckpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	chk, err := s.store.GetCheckpoint(req.CheckpointID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid hex signature: %v", err), http.StatusBadRequest)
		return
	}

	sig := trust.MemberSignature{
		ActorID:   req.ActorID,
		Signature: sigBytes,
	}

	if err := s.store.SignCheckpoint(chk, sig); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := s.store.SaveCheckpoint(chk); err != nil {
		http.Error(w, fmt.Sprintf("failed to update checkpoint: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, chk)
}

func (s *Server) handleGetLatestCheckpoint(w http.ResponseWriter, r *http.Request) {
	chk, err := s.store.GetLatestCheckpoint()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, chk)
}

func (s *Server) handleListCheckpoints(w http.ResponseWriter, r *http.Request) {
	list := s.store.ListCheckpoints()
	writeJSON(w, http.StatusOK, list)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "secure" {
		if err := runSecure(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	port := flag.Int("port", 8086, "Authority HTTP listen port")
	listen := flag.String("listen", "", "Authority HTTP listen address (e.g. 0.0.0.0:8086)")
	stateFile := flag.String("state", "authority_state.json", "Authority storage file")
	flag.Parse()

	store, err := trust.NewStore(*stateFile)
	if err != nil {
		log.Fatalf("failed to initialize authority store: %v", err)
	}

	srv := NewServer(store)
	addr := fmt.Sprintf(":%d", *port)
	if *listen != "" {
		addr = *listen
	}
	log.Printf("Starting ratchet-authority on %s", addr)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatalf("authority server failed: %v", err)
	}
}
