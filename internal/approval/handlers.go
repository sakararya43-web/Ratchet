package approval

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// Handler provides HTTP endpoints for WebAuthn passkey registration, management, and assertions.
type Handler struct {
	verifier *ApprovalVerifier
	store    *CredentialStore
}

func NewHandler(verifier *ApprovalVerifier, store *CredentialStore) *Handler {
	return &Handler{
		verifier: verifier,
		store:    store,
	}
}

// Routes returns an http.Handler implementing all passkey ceremonies.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register/begin", h.handleRegisterBegin)
	mux.HandleFunc("POST /register/finish", h.handleRegisterFinish)
	mux.HandleFunc("GET /list", h.handleList)
	mux.HandleFunc("POST /revoke", h.handleRevoke)
	mux.HandleFunc("POST /assert/begin", h.handleAssertBegin)
	mux.HandleFunc("POST /assert/finish", h.handleAssertFinish)
	mux.HandleFunc("POST /assert/simulate", h.handleAssertSimulate)

	return mux
}

// MakePasskeyHandlerFactory returns a ports.PasskeyHandlerFactory implementation.
func MakePasskeyHandlerFactory(store *CredentialStore, rpID string, rpOrigins []string) ports.PasskeyHandlerFactory {
	return func(deps ports.PasskeyDeps) http.Handler {
		effectiveRPID := rpID
		if deps.RPID != "" {
			effectiveRPID = deps.RPID
		}
		effectiveOrigins := rpOrigins
		if len(deps.RPOrigins) > 0 {
			effectiveOrigins = deps.RPOrigins
		}

		verifier, err := NewApprovalVerifier(store, effectiveRPID, effectiveOrigins)
		if err != nil {
			panic(fmt.Sprintf("failed to create ApprovalVerifier: %v", err))
		}
		return NewHandler(verifier, store).Routes()
	}
}

type RegisterBeginRequest struct {
	TenantID    string `json:"tenant_id"`
	ActorID     string `json:"actor_id"`
	DisplayName string `json:"display_name"`
}

func (h *Handler) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req RegisterBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.TenantID == "" || req.ActorID == "" {
		http.Error(w, "tenant_id and actor_id are required", http.StatusBadRequest)
		return
	}

	user := h.store.GetUser(req.TenantID, req.ActorID, req.DisplayName)
	options, sessionData, err := h.verifier.webauthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to begin registration: %v", err), http.StatusInternalServerError)
		return
	}

	sessionID := h.store.SaveSession(req.TenantID, req.ActorID, "", nil, sessionData)

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"options":    options,
	})
}

func (h *Handler) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	label := r.URL.Query().Get("label")

	if sessionID == "" {
		http.Error(w, "missing session_id parameter", http.StatusBadRequest)
		return
	}

	sess, err := h.store.ConsumeSession(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := h.store.GetUser(sess.TenantID, sess.ActorID, sess.ActorID)
	cred, err := h.verifier.webauthn.FinishRegistration(user, *sess.Data, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to finish registration: %v", err), http.StatusBadRequest)
		return
	}

	if label == "" {
		label = "Primary Passkey"
	}

	if err := h.store.SaveCredential(sess.TenantID, sess.ActorID, label, cred); err != nil {
		http.Error(w, fmt.Sprintf("failed to save credential: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"credential_id": hex.EncodeToString(cred.ID),
		"label":         label,
	})
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	actorID := r.URL.Query().Get("actor_id")

	if tenantID == "" || actorID == "" {
		http.Error(w, "tenant_id and actor_id required", http.StatusBadRequest)
		return
	}

	creds := h.store.ListCredentials(tenantID, actorID)
	writeJSON(w, http.StatusOK, creds)
}

type RevokeRequest struct {
	TenantID     string `json:"tenant_id"`
	ActorID      string `json:"actor_id"`
	CredentialID string `json:"credential_id"`
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	credBytes, err := hex.DecodeString(req.CredentialID)
	if err != nil {
		http.Error(w, "invalid hex credential_id", http.StatusBadRequest)
		return
	}

	if err := h.store.RevokeCredential(req.TenantID, req.ActorID, credBytes); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

type AssertBeginRequest struct {
	TenantID     string `json:"tenant_id"`
	ActorID      string `json:"actor_id"`
	ChangeDigest string `json:"change_digest"` // 64-char hex string
}

func (h *Handler) handleAssertBegin(w http.ResponseWriter, r *http.Request) {
	var req AssertBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	digestBytes, err := ports.DigestFromHex(req.ChangeDigest)
	if err != nil {
		http.Error(w, "invalid change_digest hex", http.StatusBadRequest)
		return
	}

	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	boundChallenge := ComputeApprovalChallenge(req.TenantID, req.ActorID, digestBytes, nonce)

	user := h.store.GetUser(req.TenantID, req.ActorID, req.ActorID)
	if len(user.Credentials) == 0 {
		http.Error(w, "no active passkeys enrolled for this actor", http.StatusPreconditionFailed)
		return
	}

	options, sessionData, err := h.verifier.webauthn.BeginLogin(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to begin assertion: %v", err), http.StatusInternalServerError)
		return
	}

	// Override the challenge with the domain-separated change-bound challenge
	options.Response.Challenge = boundChallenge
	sessionData.Challenge = base64.RawURLEncoding.EncodeToString(boundChallenge)

	sessionID := h.store.SaveSession(req.TenantID, req.ActorID, req.ChangeDigest, nonce, sessionData)

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":      sessionID,
		"options":         options,
		"bound_challenge": hex.EncodeToString(boundChallenge),
		"challenge_nonce": hex.EncodeToString(nonce),
	})
}

type AssertFinishRequest struct {
	SessionID         string `json:"session_id"`
	CredentialID      string `json:"credential_id"`       // hex
	ClientDataJSON    string `json:"client_data_json"`    // base64
	AuthenticatorData string `json:"authenticator_data"` // base64
	Signature         string `json:"signature"`          // base64
}

func (h *Handler) handleAssertFinish(w http.ResponseWriter, r *http.Request) {
	var req AssertFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	sess, err := h.store.ConsumeSession(req.SessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	credBytes, err := hex.DecodeString(req.CredentialID)
	if err != nil {
		http.Error(w, "invalid credential_id hex", http.StatusBadRequest)
		return
	}

	clientData, err := base64.StdEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		http.Error(w, "invalid client_data_json base64", http.StatusBadRequest)
		return
	}

	authData, err := base64.StdEncoding.DecodeString(req.AuthenticatorData)
	if err != nil {
		http.Error(w, "invalid authenticator_data base64", http.StatusBadRequest)
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature base64", http.StatusBadRequest)
		return
	}

	changeDigest, err := ports.DigestFromHex(sess.ChangeDigest)
	if err != nil {
		http.Error(w, "invalid session change digest", http.StatusInternalServerError)
		return
	}

	submission := ports.ApprovalSubmission{
		TenantID:          sess.TenantID,
		ActorID:           sess.ActorID,
		CredentialID:      credBytes,
		ClientDataJSON:    clientData,
		AuthenticatorData: authData,
		Signature:         sigBytes,
		ChallengeNonce:    sess.ChallengeNonce,
	}

	verified, err := h.verifier.Verify(r.Context(), submission, changeDigest)
	if err != nil {
		http.Error(w, fmt.Sprintf("passkey verification failed: %v", err), http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"verified":      true,
		"verified_at":   verified.VerifiedAt,
		"actor_id":      verified.ActorID,
		"credential_id": hex.EncodeToString(verified.CredentialID),
		"user_verified": verified.UserVerified,
		"change_digest": verified.ChangeDigest.String(),
	})
}

type AssertSimulateRequest struct {
	TenantID     string `json:"tenant_id"`
	ActorID      string `json:"actor_id"`
	ChangeDigest string `json:"change_digest"`
}

func (h *Handler) handleAssertSimulate(w http.ResponseWriter, r *http.Request) {
	var req AssertSimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	changeDigest, err := ports.DigestFromHex(req.ChangeDigest)
	if err != nil {
		http.Error(w, "invalid change_digest hex", http.StatusBadRequest)
		return
	}

	submission, err := GenerateSimulatedAssertion(req.TenantID, req.ActorID, changeDigest, "localhost", "http://localhost:3000")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate assertion: %v", err), http.StatusBadRequest)
		return
	}

	verified, err := h.verifier.Verify(r.Context(), submission, changeDigest)
	if err != nil {
		http.Error(w, fmt.Sprintf("passkey verification failed: %v", err), http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"verified":      true,
		"verified_at":   verified.VerifiedAt,
		"actor_id":      verified.ActorID,
		"credential_id": hex.EncodeToString(verified.CredentialID),
		"user_verified": verified.UserVerified,
		"change_digest": verified.ChangeDigest.String(),
		"submission": map[string]any{
			"credential_id":      hex.EncodeToString(submission.CredentialID),
			"client_data_json":   base64.StdEncoding.EncodeToString(submission.ClientDataJSON),
			"authenticator_data": base64.StdEncoding.EncodeToString(submission.AuthenticatorData),
			"signature":          base64.StdEncoding.EncodeToString(submission.Signature),
			"challenge_nonce":    hex.EncodeToString(submission.ChallengeNonce),
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
