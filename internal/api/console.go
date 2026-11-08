package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"

	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func ConsoleApprovalReview(service *workflow.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		principal, ok := SessionPrincipal(r.Context())
		if !ok {
			http.Error(w, "session required", http.StatusUnauthorized)
			return
		}
		request := r.URL.Query().Get("request_id")
		if id, err := uuid.Parse(request); err != nil || id == uuid.Nil {
			http.Error(w, "request required", http.StatusBadRequest)
			return
		}
		review, err := service.ApprovalReview(r.Context(), workflow.Actor{TenantID: principal.TenantID, ID: principal.ActorID}, request)
		if err != nil {
			code := http.StatusServiceUnavailable
			switch {
			case errors.Is(err, workflow.ErrPermission):
				code = http.StatusForbidden
			case errors.Is(err, pgx.ErrNoRows):
				code = http.StatusNotFound
			case errors.Is(err, domain.ErrContextChanged):
				code = http.StatusConflict
			}
			http.Error(w, "authorized current request review unavailable; refresh or reassess", code)
			return
		}
		writeJSON(w, http.StatusOK, review)
	})
}

// ConsoleBootstrap is an authenticated display projection, never an alternate
// authorization/decision API. Ordinary users receive an explicitly self-only cut.
func ConsoleBootstrap(service *workflow.Service, key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		p, ok := SessionPrincipal(r.Context())
		if !ok {
			http.Error(w, "session required", http.StatusUnauthorized)
			return
		}
		actor := workflow.Actor{TenantID: p.TenantID, ID: p.ActorID}
		if err := service.Authorize(r.Context(), actor, "view"); err != nil {
			http.Error(w, "view unavailable", http.StatusForbidden)
			return
		}
		snapshot, err := service.Store.CurrentGraph(r.Context(), p.TenantID, key)
		if err != nil {
			http.Error(w, "graph unavailable", http.StatusServiceUnavailable)
			return
		}
		scope := "SELF"
		nodes := []map[string]any{{"id": p.ActorID, "type": "Human", "display_name": p.ActorID}}
		edges := []map[string]string{}
		if service.Authorize(r.Context(), actor, "investigate") == nil {
			scope = "ORGANIZATION"
			nodes = nil
			data := snapshot.Data()
			for _, node := range data.Nodes {
				nodes = append(nodes, map[string]any{"id": node.ID, "type": node.Type, "display_name": node.DisplayName, "tier": node.Tier})
			}
			for _, edge := range data.Edges {
				edges = append(edges, map[string]string{"id": edge.ID, "source": edge.Source, "target": edge.Target, "kind": edge.Kind, "action": edge.Action})
			}
		}
		raw, err := json.Marshal(map[string]any{"principal": p, "graph_version": snapshot.Version(), "scope": scope, "nodes": nodes, "edges": edges})
		if err != nil {
			http.Error(w, "projection unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(raw) > 32<<20 {
			http.Error(w, "use paginated graph endpoints for this source", http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})
}
