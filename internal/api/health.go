// Package api contains HTTP surfaces implemented by the core.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type Probe func(context.Context) error

type Health struct {
	Database     Probe
	Migrations   Probe
	RuntimeRole  Probe
	Graph        Probe
	PolicyBundle Probe
	Workflow     Probe
}

type DependencyStatus struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

func (h Health) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"alive": true})
	})
	mux.HandleFunc("GET /readyz", h.ready(false))
	mux.HandleFunc("GET /readyz/storage", h.ready(true))
	return mux
}

func (h Health) ready(storageOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		probes := map[string]Probe{"database": h.Database, "migrations": h.Migrations, "runtime_role": h.RuntimeRole}
		if !storageOnly {
			probes["graph"] = h.Graph
			probes["policy_bundle"] = h.PolicyBundle
			if h.Workflow != nil {
				probes["workflow"] = h.Workflow
			}
		}
		status := make(map[string]DependencyStatus, len(probes))
		ready := true
		for name, probe := range probes {
			state := DependencyStatus{Ready: true}
			if probe == nil {
				state = DependencyStatus{Reason: "not_initialized"}
			} else if err := probe(ctx); err != nil {
				state = DependencyStatus{Reason: "unavailable"}
			}
			status[name] = state
			ready = ready && state.Ready
		}
		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, struct {
			Ready        bool                        `json:"ready"`
			Dependencies map[string]DependencyStatus `json:"dependencies"`
		}{ready, status})
	}
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
