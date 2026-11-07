package api

import (
	"encoding/json"
	"net/http"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func NewMetricsHandler(service *workflow.Service) (http.Handler, error) {
	if service == nil {
		return nil, domain.ErrInvalid
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		p, ok := SessionPrincipal(r.Context())
		if !ok {
			http.Error(w, "session required", http.StatusUnauthorized)
			return
		}
		d, err := service.InvestigatorDiagnostics(r.Context(), workflow.Actor{TenantID: p.TenantID, ID: p.ActorID})
		if err != nil {
			http.Error(w, "investigator diagnostics unavailable", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	}), nil
}
