package approval

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type SessionIdentity interface {
	PasskeyPrincipal(*http.Request) (string, string, error)
}
type Handler struct {
	verifier *ApprovalVerifier
	store    *CredentialStore
	identity SessionIdentity
}

func NewHandler(v *ApprovalVerifier, s *CredentialStore) *Handler {
	return &Handler{verifier: v, store: s}
}
func MakePasskeyHandlerFactory(store *CredentialStore, rp string, origins []string) ports.PasskeyHandlerFactory {
	return func(deps ports.PasskeyDeps) http.Handler {
		effectiveRP, effectiveOrigins := rp, slices.Clone(origins)
		if deps.RPID != "" {
			effectiveRP = deps.RPID
		}
		if len(deps.RPOrigins) > 0 {
			effectiveOrigins = slices.Clone(deps.RPOrigins)
		}
		v, err := NewApprovalVerifier(store, effectiveRP, effectiveOrigins)
		identity, ok := deps.SessionAPI.(SessionIdentity)
		if err != nil || !ok {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "authenticated passkey session required", http.StatusUnauthorized)
			})
		}
		return (&Handler{verifier: v, store: store, identity: identity}).Routes()
	}
}
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/begin", h.registerBegin)
	mux.HandleFunc("POST /register/finish", h.registerFinish)
	mux.HandleFunc("GET /list", h.list)
	mux.HandleFunc("POST /revoke", h.revoke)
	mux.HandleFunc("POST /assert/begin", h.assertBegin)
	mux.HandleFunc("POST /assert/finish", h.assertFinish)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.identity == nil || r.TLS == nil {
			http.Error(w, "authenticated HTTPS session required", http.StatusUnauthorized)
			return
		}
		if _, _, err := h.identity.PasskeyPrincipal(r); err != nil {
			http.Error(w, "authenticated session required", http.StatusUnauthorized)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !slices.Contains(h.verifier.webauthn.Config.RPOrigins, r.Header.Get("Origin")) {
			http.Error(w, "origin refused", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}
func passkeyDecode(r *http.Request, out any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("single ceremony object required")
	}
	return nil
}
func (h *Handler) owner(w http.ResponseWriter, r *http.Request, tenant, actor string) (string, string, bool) {
	t, a, err := h.identity.PasskeyPrincipal(r)
	if err != nil || tenant != "" && tenant != t || actor != "" && actor != a {
		http.Error(w, "ceremony owner mismatch", http.StatusForbidden)
		return "", "", false
	}
	return t, a, true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type RegisterBeginRequest struct {
	TenantID    string `json:"tenant_id"`
	ActorID     string `json:"actor_id"`
	DisplayName string `json:"display_name"`
}

func (h *Handler) registerBegin(w http.ResponseWriter, r *http.Request) {
	var in RegisterBeginRequest
	if passkeyDecode(r, &in) != nil {
		http.Error(w, "invalid registration", http.StatusBadRequest)
		return
	}
	t, a, ok := h.owner(w, r, in.TenantID, in.ActorID)
	if !ok {
		return
	}
	user, err := h.store.User(r.Context(), t, a)
	if err != nil {
		http.Error(w, "credentials unavailable", http.StatusServiceUnavailable)
		return
	}
	options, data, err := h.verifier.webauthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "registration refused", http.StatusBadRequest)
		return
	}
	id := h.store.SaveSession(t, a, "", nil, data)
	if id == "" {
		http.Error(w, "ceremony unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": id, "options": options})
}
func (h *Handler) registerFinish(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.owner(w, r, "", "")
	if !ok {
		return
	}
	s, err := h.store.ConsumeOwnedSession(r.Context(), r.URL.Query().Get("session_id"), t, a)
	if err != nil || s.ChangeDigest != "" || s.Data == nil {
		http.Error(w, "registration ceremony refused", http.StatusBadRequest)
		return
	}
	user, err := h.store.User(r.Context(), t, a)
	if err != nil {
		http.Error(w, "credentials unavailable", http.StatusServiceUnavailable)
		return
	}
	credential, err := h.verifier.webauthn.FinishRegistration(user, *s.Data, r)
	if err != nil {
		http.Error(w, "registration assertion refused", http.StatusBadRequest)
		return
	}
	label := r.URL.Query().Get("label")
	if label == "" {
		label = "Passkey"
	}
	if err := h.store.SaveCredential(t, a, label, credential); err != nil {
		http.Error(w, "credential persistence refused", http.StatusConflict)
		return
	}
	writeJSON(w, 200, map[string]any{"credential_id": hex.EncodeToString(credential.ID), "label": label})
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.owner(w, r, r.URL.Query().Get("tenant_id"), r.URL.Query().Get("actor_id"))
	if !ok {
		return
	}
	var list []*StoredCredential
	if h.store.pool != nil {
		var err error
		list, err = h.store.listPersistent(r.Context(), t, a)
		if err != nil {
			http.Error(w, "credentials unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		list = h.store.ListCredentials(t, a)
	}
	result := []map[string]any{}
	for _, c := range list {
		result = append(result, map[string]any{"credential_id": hex.EncodeToString(c.Credential.ID), "label": c.Label, "enrolled_at": c.CreatedAt, "revoked": c.IsRevoked})
	}
	writeJSON(w, 200, result)
}

type RevokeRequest struct {
	TenantID     string `json:"tenant_id"`
	ActorID      string `json:"actor_id"`
	CredentialID string `json:"credential_id"`
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	var in RevokeRequest
	if passkeyDecode(r, &in) != nil {
		http.Error(w, "invalid revocation", http.StatusBadRequest)
		return
	}
	t, a, ok := h.owner(w, r, in.TenantID, in.ActorID)
	if !ok {
		return
	}
	id, err := hex.DecodeString(in.CredentialID)
	if err != nil {
		http.Error(w, "invalid credential", http.StatusBadRequest)
		return
	}
	if err := h.store.RevokeCredential(t, a, id); err != nil {
		http.Error(w, "active credential absent", http.StatusNotFound)
		return
	}
	writeJSON(w, 200, map[string]bool{"revoked": true})
}

type AssertBeginRequest struct {
	TenantID     string `json:"tenant_id"`
	ActorID      string `json:"actor_id"`
	ChangeDigest string `json:"change_digest"`
}

func (h *Handler) assertBegin(w http.ResponseWriter, r *http.Request) {
	var in AssertBeginRequest
	if passkeyDecode(r, &in) != nil {
		http.Error(w, "invalid assertion", http.StatusBadRequest)
		return
	}
	t, a, ok := h.owner(w, r, in.TenantID, in.ActorID)
	if !ok {
		return
	}
	digest, err := ports.DigestFromHex(in.ChangeDigest)
	if err != nil || digest.IsZero() {
		http.Error(w, "exact change digest required", http.StatusBadRequest)
		return
	}
	user, err := h.store.User(r.Context(), t, a)
	if err != nil {
		http.Error(w, "credentials unavailable", http.StatusServiceUnavailable)
		return
	}
	options, data, err := h.verifier.webauthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		http.Error(w, "active passkey required", http.StatusPreconditionFailed)
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	challenge := ComputeApprovalChallenge(t, a, digest, nonce)
	options.Response.Challenge = challenge
	data.Challenge = base64.RawURLEncoding.EncodeToString(challenge)
	id := h.store.SaveSession(t, a, digest.String(), nonce, data)
	if id == "" {
		http.Error(w, "ceremony unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": id, "options": options, "challenge_nonce": hex.EncodeToString(nonce)})
}

type AssertFinishRequest struct {
	SessionID         string `json:"session_id"`
	CredentialID      string `json:"credential_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

func decodeAssertionBytes(raw string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(raw)
	if err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(raw)
}
func (h *Handler) assertFinish(w http.ResponseWriter, r *http.Request) {
	var in AssertFinishRequest
	if passkeyDecode(r, &in) != nil {
		http.Error(w, "invalid assertion", http.StatusBadRequest)
		return
	}
	t, a, ok := h.owner(w, r, "", "")
	if !ok {
		return
	}
	s, err := h.store.ConsumeOwnedSession(r.Context(), in.SessionID, t, a)
	if err != nil || s.ChangeDigest == "" {
		http.Error(w, "assertion ceremony refused", http.StatusBadRequest)
		return
	}
	id, e1 := hex.DecodeString(in.CredentialID)
	client, e2 := decodeAssertionBytes(in.ClientDataJSON)
	auth, e3 := decodeAssertionBytes(in.AuthenticatorData)
	signature, e4 := decodeAssertionBytes(in.Signature)
	digest, e5 := ports.DigestFromHex(s.ChangeDigest)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		http.Error(w, "invalid assertion encoding", http.StatusBadRequest)
		return
	}
	sub := ports.ApprovalSubmission{TenantID: t, ActorID: a, CredentialID: id, ClientDataJSON: client, AuthenticatorData: auth, Signature: signature, ChallengeNonce: s.ChallengeNonce}
	verified, err := h.verifier.Verify(r.Context(), sub, digest)
	if err != nil {
		http.Error(w, "assertion refused", http.StatusUnauthorized)
		return
	}
	writeJSON(w, 200, map[string]any{"verified": true, "user_verified": verified.UserVerified, "change_digest": digest.String(), "submission": sub})
}
