package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoLoginDelegatesOnlyFixedRequesterToNormalLogin(t *testing.T) {
	const origin = "https://localhost:8444"
	const password = "demo-test-password-not-a-real-credential"
	calls := 0
	h, err := newDemoLogin(origin, password, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["tenant_id"] != "tenant-exchange-demo" || body["actor_id"] != "user:rahul-assistant" || body["password"] != password {
			t.Error("demo did not delegate the fixed provisioned requester")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, origin, body string
		tls                  bool
		status               int
	}{
		{http.MethodPost, origin, "{}", true, http.StatusNoContent},
		{http.MethodGet, origin, "{}", true, http.StatusMethodNotAllowed},
		{http.MethodPost, "https://other.example", "{}", true, http.StatusForbidden},
		{http.MethodPost, origin, "{}", false, http.StatusForbidden},
		{http.MethodPost, origin, `{"actor_id":"user:sec-lead-1"}`, true, http.StatusBadRequest},
	} {
		r := httptest.NewRequest(tc.method, origin+"/api/auth/demo", strings.NewReader(tc.body))
		r.Header.Set("Origin", tc.origin)
		r.TLS = nil
		if tc.tls {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), password) {
			t.Fatalf("demo request returned status %d, expected %d", w.Code, tc.status)
		}
	}
	if calls != 1 {
		t.Fatal("a refused demo request reached password authentication")
	}
	for _, location := range []string{"https://example.com", "http://localhost:8444"} {
		if _, err := newDemoLogin(location, password, http.NotFoundHandler()); err == nil {
			t.Fatal("demo enabled on a non-local or non-HTTPS origin")
		}
	}
}
