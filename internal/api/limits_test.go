package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func limitedRequest(actor, tenant string) *http.Request {
	r := httptest.NewRequest("POST", "https://console.test/api/test", strings.NewReader("{}"))
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, Principal{TenantID: tenant, ActorID: actor}))
}
func TestRequestRateIsBoundedAndTenantScoped(t *testing.T) {
	h := NewRequestLimits().Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for range 60 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, limitedRequest("actor", "a"))
		if w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, limitedRequest("actor", "a"))
	if w.Code != 429 {
		t.Fatal("unbounded actor burst", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, limitedRequest("actor", "b"))
	if w.Code != 204 {
		t.Fatal("rate bucket crossed tenant boundary", w.Code)
	}
}
func TestRequestConcurrencyAndSizeAreBounded(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var workers sync.WaitGroup
	h := NewRequestLimits().Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { entered <- struct{}{}; <-release; w.WriteHeader(204) }))
	for range 8 {
		workers.Go(func() { h.ServeHTTP(httptest.NewRecorder(), limitedRequest("actor", "a")) })
	}
	for range 8 {
		<-entered
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, limitedRequest("actor", "a"))
	close(release)
	workers.Wait()
	if w.Code != 429 {
		t.Fatal("unbounded expensive concurrent actor work", w.Code)
	}
	reader := NewRequestLimits().Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(413)
			return
		}
		w.WriteHeader(204)
	}))
	for _, length := range []int64{-1, RequestBodyLimit + 1} {
		r := httptest.NewRequest("POST", "https://console.test/api/test", strings.NewReader(strings.Repeat("x", int(RequestBodyLimit+1))))
		r.ContentLength = length
		w := httptest.NewRecorder()
		reader.ServeHTTP(w, r)
		if w.Code != 413 {
			t.Fatal("oversized fixed or streamed payload accepted", length, w.Code)
		}
	}
}

func TestTransportCapacityBoundsWorkAcrossDistinctActors(t *testing.T) {
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	var workers sync.WaitGroup
	h := NewRequestLimits().Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := range 64 {
		workers.Go(func() {
			h.ServeHTTP(httptest.NewRecorder(), limitedRequest(fmt.Sprint(i), "tenant"))
		})
	}
	for range 64 {
		<-entered
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, limitedRequest("another-actor", "tenant"))
	close(release)
	workers.Wait()
	if w.Code != http.StatusTooManyRequests {
		t.Fatal("global capacity was split across actor buckets", w.Code)
	}
}
func FuzzAuthenticationDecoder(f *testing.F) {
	for _, raw := range []string{`{}`, `{"tenant_id":"a","actor_id":"b"}`, `{} {}`, strings.Repeat(" ", 16385)} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "https://console.test", strings.NewReader(raw))
		var out struct {
			Tenant string `json:"tenant_id"`
			Actor  string `json:"actor_id"`
		}
		err := decodeBody(r, &out)
		if len(raw) > 16384 && err == nil {
			t.Fatal("oversize decode accepted")
		}
	})
}
