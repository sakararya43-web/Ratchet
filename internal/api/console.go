package api

import (
	"encoding/json"
	"net/http"

	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

// ConsoleBootstrap is an authenticated display projection, never an alternate
// authorization/decision API. Ordinary users receive an explicitly self-only cut.
func ConsoleBootstrap(service *workflow.Service, key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		p, ok := SessionPrincipal(r.Context())
		if !ok {
			http.Error(w, "session required", 401)
			return
		}
		actor := workflow.Actor{TenantID: p.TenantID, ID: p.ActorID}
		if err := service.Authorize(r.Context(), actor, "view"); err != nil {
			http.Error(w, "view unavailable", 403)
			return
		}
		snapshot, err := service.Store.CurrentGraph(r.Context(), p.TenantID, key)
		if err != nil {
			http.Error(w, "graph unavailable", 503)
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
			http.Error(w, "projection unavailable", 503)
			return
		}
		if len(raw) > 32<<20 {
			http.Error(w, "use paginated graph endpoints for this source", 413)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})
}
