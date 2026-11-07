package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/api"
)

func TestMissingDecisionDependenciesNeverReportReady(t *testing.T) {
	ok := func(context.Context) error { return nil }
	h := api.Health{Database: ok, Migrations: ok, RuntimeRole: ok}.Handler()
	for _, tc := range []struct {
		path string
		code int
	}{{"/livez", 200}, {"/readyz/storage", 200}, {"/readyz", 503}, {"/api/changes", 404}} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if r.Code != tc.code {
			t.Fatalf("%s got %d: %s", tc.path, r.Code, r.Body.String())
		}
	}
}

func TestReadinessDoesNotLeakDependencyErrors(t *testing.T) {
	h := api.Health{Database: func(context.Context) error { return errors.New("secret database credentials") }}.Handler()
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if r.Code != 503 || strings.Contains(r.Body.String(), "secret") {
		t.Fatal(r.Body.String())
	}
}

func TestBrokerAndAuthorityDegradeDecisionReadinessIndependently(t *testing.T) {
	ok := func(context.Context) error { return nil }
	failed := func(context.Context) error { return errors.New("private dependency address") }
	for _, dependency := range []string{"broker", "authority_source"} {
		h := api.Health{Database: ok, Migrations: ok, RuntimeRole: ok, Graph: ok, PolicyBundle: ok, Workflow: ok, Broker: ok, Authority: ok}
		if dependency == "broker" { h.Broker = failed } else { h.Authority = failed }
		for _, path := range []string{"/livez", "/readyz/storage", "/readyz"} {
			r := httptest.NewRecorder()
			h.Handler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, path, nil))
			want := 200; if path == "/readyz" { want = 503 }
			if r.Code != want || strings.Contains(r.Body.String(), "private") { t.Fatal(dependency, path, r.Code, r.Body.String()) }
		}
	}
}
