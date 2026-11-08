package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"

	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/authority"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// AuthorityGateway derives identity from the authenticated core session. The
// separate Authority independently checks the signed transport, pinned member
// key, exact artifact purpose, current epoch, quorum and native assertion.
func AuthorityGateway(clients map[string]*authority.Client, credentials *approval.CredentialStore, verifier ports.ApprovalVerifier, authorize func(context.Context, Principal) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := SessionPrincipal(r.Context())
		if !ok {
			http.Error(w, "session required", 401)
			return
		}
		client := clients[principal.TenantID]
		if client == nil || credentials == nil || verifier == nil || authorize == nil || authorize(r.Context(), principal) != nil {
			http.Error(w, "Authority access refused", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == "GET" && r.URL.Path == "/state" {
			var state authority.State
			if client.Do(r.Context(), principal.ActorID, "/v1/state", nil, &state) != nil {
				http.Error(w, "Authority unavailable or access refused", 503)
				return
			}
			writeJSON(w, 200, state)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/credentials" {
			user, err := credentials.User(r.Context(), principal.TenantID, principal.ActorID)
			if err != nil {
				http.Error(w, "credentials unavailable", 503)
				return
			}
			list := []map[string]any{}
			for _, credential := range user.Credentials {
				list = append(list, map[string]any{"credential_id": credential.ID, "public_key": credential.PublicKey})
			}
			writeJSON(w, 200, list)
			return
		}
		if r.Method != "POST" || (r.URL.Path != "/prepare" && r.URL.Path != "/apply") {
			http.NotFound(w, r)
			return
		}
		var input authority.Input
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "exact Authority input required", 400)
			return
		}
		var preview authority.Preview
		if client.Do(r.Context(), principal.ActorID, "/v1/prepare", &input, &preview) != nil {
			http.Error(w, "Authority context changed or refused", 409)
			return
		}
		if r.URL.Path == "/prepare" {
			writeJSON(w, 200, preview)
			return
		}
		if input.Proof.TenantID != principal.TenantID || input.Proof.ActorID != principal.ActorID {
			http.Error(w, "assertion actor mismatch", 403)
			return
		}
		if _, err := verifier.Verify(r.Context(), input.Proof, preview.Digest); err != nil {
			http.Error(w, "current enrolled passkey required", 403)
			return
		}
		if input.Operation == "enroll" {
			user, err := credentials.User(r.Context(), principal.TenantID, principal.ActorID)
			if err != nil || input.Member == nil {
				http.Error(w, "enrollment unavailable", 409)
				return
			}
			matched := false
			for _, credential := range user.Credentials {
				if slices.Equal(credential.ID, input.Proof.CredentialID) && slices.Equal(credential.ID, input.Member.CredentialID) && slices.Equal(credential.PublicKey, input.Member.PublicKey) {
					matched = true
				}
			}
			if !matched {
				http.Error(w, "exact enrolled public key required", 403)
				return
			}
		}
		var state authority.State
		if client.Do(r.Context(), principal.ActorID, "/v1/apply", &input, &state) != nil {
			http.Error(w, "Authority action refused; refresh current state", 409)
			return
		}
		writeJSON(w, 200, state)
	})
}
