//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

func TestRealPasswordSessionsCSRFRevocationAndTenantBinding(t *testing.T) {
	ctx := context.Background()
	if os.Getenv("RATCHET_MIGRATION_DSN") == "" {
		t.Fatal("real database required")
	}
	if err := eventstore.Migrate(ctx, os.Getenv("RATCHET_MIGRATION_DSN")); err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.New(ctx, os.Getenv("RATCHET_MIGRATION_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	runtime, err := pgxpool.New(ctx, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	p := api.Principal{TenantID: "session_" + uuid.NewString(), ActorID: "user:finance-lead"}
	password := "test-only-real-password-" + uuid.NewString()
	if err := api.ProvisionUser(ctx, admin, p, password); err != nil {
		t.Fatal(err)
	}
	origin := "https://console.local"
	sessions, err := api.NewSessions(runtime, origin, bytes.Repeat([]byte{7}, 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", sessions.Routes()))
	mux.Handle("/identity", sessions.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := api.SessionPrincipal(r.Context())
		_ = json.NewEncoder(w).Encode(principal)
	})))
	mux.HandleFunc("/identified-only", func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := sessions.PasskeyPrincipal(r); err == nil {
			t.Error("rate-limit identification bypassed route/CSRF authentication")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(api.NewRequestLimits().WrapSessions(sessions, mux))
	defer server.Close()
	client := server.Client()
	post := func(path, body, csrf string, cookie *http.Cookie, requestOrigin string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", requestOrigin)
		req.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}
	body, _ := json.Marshal(map[string]string{"tenant_id": p.TenantID, "actor_id": p.ActorID, "password": password})
	if res := post("/auth/login", string(body), "", nil, "https://evil.local"); res.StatusCode != 403 {
		t.Fatal("cross-origin login")
	}
	res := post("/auth/login", string(body), "", nil, origin)
	if res.StatusCode != 200 {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("login %d %s", res.StatusCode, raw)
	}
	cookies := res.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/identity", nil)
	request.AddCookie(cookies[0])
	request.Header.Set("X-Actor-ID", "forged")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var identity api.Principal
	_ = json.NewDecoder(response.Body).Decode(&identity)
	if identity != p {
		t.Fatal(identity)
	}
	if res := post("/auth/logout", "{}", "", cookies[0], origin); res.StatusCode != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if res := post("/auth/logout", "{}", login.CSRF, cookies[0], origin); res.StatusCode != 204 {
		t.Fatal(res.StatusCode)
	}
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("logged-out session accepted")
	}
	res = post("/auth/login", string(body), "", nil, origin)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	expiredCookie := res.Cookies()[0]
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('ratchet.tenant_id',$1,true)`, p.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE ratchet.console_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1`, p.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/identity", nil)
	request.AddCookie(expiredCookie)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("expired session accepted")
	}

	// Exercise the actual session/outer-limit chain with two real tenants behind
	// one TLS peer. Exhausting one verified actor must not exhaust another actor
	// or cause an anonymous request to inherit that actor's identity.
	first := post("/auth/login", string(body), "", nil, origin)
	if first.StatusCode != http.StatusOK {
		t.Fatal("fresh first session", first.StatusCode)
	}
	firstCookie := first.Cookies()[0]
	other := api.Principal{TenantID: "session_" + uuid.NewString(), ActorID: p.ActorID}
	if err := api.ProvisionUser(ctx, admin, other, password); err != nil {
		t.Fatal(err)
	}
	otherBody, err := json.Marshal(map[string]string{"tenant_id": other.TenantID, "actor_id": other.ActorID, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	second := post("/auth/login", string(otherBody), "", nil, origin)
	if second.StatusCode != http.StatusOK {
		t.Fatal("second tenant session", second.StatusCode)
	}
	get := func(path string, cookie *http.Cookie) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		req.Header.Set("X-Actor-ID", p.ActorID)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if status := get("/identified-only", firstCookie); status != http.StatusNoContent {
		t.Fatal("identification promoted into passkey authorization", status)
	}
	exhausted := false
	for range 200 {
		status := get("/identity", firstCookie)
		if status == http.StatusTooManyRequests {
			exhausted = true
			break
		}
		if status != http.StatusOK {
			t.Fatal("unexpected actor response", status)
		}
	}
	if !exhausted {
		t.Fatal("verified actor burst was unbounded")
	}
	if status := get("/identity", second.Cookies()[0]); status != http.StatusOK {
		t.Fatal("verified actor limit crossed tenant/peer boundary", status)
	}
	if status := get("/identity", nil); status != http.StatusUnauthorized {
		t.Fatal("anonymous request inherited an authenticated actor budget", status)
	}
}
