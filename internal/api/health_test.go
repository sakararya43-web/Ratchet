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
