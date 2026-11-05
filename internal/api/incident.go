package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type incidentAPI struct {
	service *workflow.Service
	key     []byte
}

func NewIncidentHandler(service *workflow.Service, key []byte) (http.Handler, error) {
	if service == nil || len(key) != 32 {
		return nil, domain.ErrInvalid
	}
	a := &incidentAPI{service, append([]byte(nil), key...)}
	mux := http.NewServeMux()
	opts := []connect.HandlerOption{connect.WithReadMaxBytes(1 << 20), connect.WithSendMaxBytes(8 << 20)}
	mux.Handle(ratchetv1connect.IncidentServiceOpenIncidentProcedure, connect.NewUnaryHandler(ratchetv1connect.IncidentServiceOpenIncidentProcedure, a.OpenIncident, opts...))
	mux.Handle(ratchetv1connect.IncidentServiceGetIncidentProcedure, connect.NewUnaryHandler(ratchetv1connect.IncidentServiceGetIncidentProcedure, a.GetIncident, opts...))
	mux.Handle(ratchetv1connect.IncidentServiceListIncidentsProcedure, connect.NewUnaryHandler(ratchetv1connect.IncidentServiceListIncidentsProcedure, a.ListIncidents, opts...))
	return mux, nil
}

func incidentView(view workflow.IncidentView) (*v1.Incident, error) {
	plan, err := containmentView(view.Proposal)
	if err != nil {
		return nil, err
	}
	severity := "LOW"
	if len(view.Observed.Routes) > 0 {
		severity = "CRITICAL"
	}
	result := &v1.Incident{IncidentId: view.Incident.ID, TenantId: view.Incident.Tenant, Title: "Manual containment investigation", Severity: severity, Status: view.Incident.Status, AffectedIdentity: view.Incident.Identity, RootCauseType: "MANUAL_CONTAINMENT", ContainmentPlan: plan, OpenedAt: view.Incident.OpenedAt.Format(time.RFC3339Nano), CorrelationId: view.Incident.CorrelationID, ResidualRoutesComplete: !view.Observed.Truncated, ObservedGraphVersion: view.Observed.Version, ObservedAt: view.ObservedAt.Format(time.RFC3339Nano), Revision: view.Incident.Revision, RestorationPrerequisites: []string{"Review the current incident and observed target state.", "Request a new access increase linked to this incident.", "Collect fresh independent approvals and target verification."}}
	for _, r := range view.Observed.Routes {
		result.ResidualRoutes = append(result.ResidualRoutes, route(r))
	}
	return result, nil
}

func (a *incidentAPI) OpenIncident(ctx context.Context, r *connect.Request[v1.OpenIncidentRequest]) (*connect.Response[v1.OpenIncidentResponse], error) {
	actor, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	id, revision, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	if revision != 0 {
		return nil, changeError(domain.ErrInvalid)
	}
	digest, err := ports.DigestFromHex(r.Msg.PlanDigest)
	if err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	opened, err := a.service.OpenIncident(ctx, actor, workflow.OpenIncidentInput{CommandID: id, CorrelationID: r.Msg.Mutation.CorrelationId, PlanID: r.Msg.PlanId, PlanDigest: digest, MinGraphVersion: r.Msg.Mutation.MinGraphVersion})
	if err != nil {
		return nil, changeError(err)
	}
	view, err := incidentView(opened)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.OpenIncidentResponse{Incident: view}), nil
}
func (a *incidentAPI) GetIncident(ctx context.Context, r *connect.Request[v1.GetIncidentRequest]) (*connect.Response[v1.GetIncidentResponse], error) {
	actor, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	incident, err := a.service.GetIncident(ctx, actor, r.Msg.IncidentId)
	if err != nil {
		return nil, changeError(err)
	}
	view, err := incidentView(incident)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.GetIncidentResponse{Incident: view}), nil
}

type incidentCursor struct {
	Tenant, Status string
	After, End     int64
}

func (a *incidentAPI) mac(raw []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte("RATCHET_INCIDENT_CURSOR_V1:"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}
func (a *incidentAPI) ListIncidents(ctx context.Context, r *connect.Request[v1.ListIncidentsRequest]) (*connect.Response[v1.ListIncidentsResponse], error) {
	actor, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	size := int(r.Msg.PageSize)
	if size == 0 {
		size = 10
	}
	if size < 1 || size > 20 {
		return nil, changeError(domain.ErrInvalid)
	}
	c := incidentCursor{Tenant: actor.TenantID, Status: r.Msg.StatusFilter}
	if token := r.Msg.PageToken; token != "" {
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			return nil, changeError(domain.ErrInvalid)
		}
		raw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
		signature, e2 := base64.RawURLEncoding.DecodeString(parts[1])
		if e1 != nil || e2 != nil || !hmac.Equal(signature, a.mac(raw)) || json.Unmarshal(raw, &c) != nil || c.Tenant != actor.TenantID || c.Status != r.Msg.StatusFilter || c.After < 0 || c.End < c.After || c.End > ledger.MaxSafeInteger {
			return nil, changeError(domain.ErrInvalid)
		}
	}
	page, err := a.service.ListIncidents(ctx, actor, c.Status, c.After, c.End, size)
	if err != nil {
		return nil, changeError(err)
	}
	result := &v1.ListIncidentsResponse{SnapshotEndSequence: page.End}
	for _, incident := range page.Incidents {
		view, err := incidentView(incident)
		if err != nil {
			return nil, changeError(err)
		}
		result.Incidents = append(result.Incidents, view)
	}
	if page.More {
		c.After, c.End = page.After, page.End
		raw, _ := json.Marshal(c)
		result.NextPageToken = base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(a.mac(raw))
	}
	return connect.NewResponse(result), nil
}
