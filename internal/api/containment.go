package api

import (
	"context"
	"maps"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type containmentAPI struct {
	service *workflow.Service
	costs   map[string]int64
}

func NewContainmentHandler(service *workflow.Service, costs map[string]int64) (http.Handler, error) {
	if service == nil {
		return nil, domain.ErrInvalid
	}
	if err := graph.ValidateRevocationCosts(costs); err != nil {
		return nil, err
	}
	a := &containmentAPI{service, maps.Clone(costs)}
	mux := http.NewServeMux()
	mux.Handle(ratchetv1connect.ContainmentServicePlanContainmentProcedure, connect.NewUnaryHandler(ratchetv1connect.ContainmentServicePlanContainmentProcedure, a.PlanContainment, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(8<<20)))
	return mux, nil
}
func (a *containmentAPI) PlanContainment(ctx context.Context, r *connect.Request[v1.PlanContainmentRequest]) (*connect.Response[v1.PlanContainmentResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	id, revision, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	if revision != 0 || r.Msg.MinGraphVersion < 0 {
		return nil, changeError(domain.ErrInvalid)
	}
	proposal, err := a.service.PlanContainment(ctx, p, workflow.PlanInput{CommandID: id, CorrelationID: r.Msg.Mutation.CorrelationId, Identity: r.Msg.CompromisedIdentity, MinGraphVersion: max(r.Msg.MinGraphVersion, r.Msg.Mutation.MinGraphVersion), Costs: a.costs})
	if err != nil {
		return nil, changeError(err)
	}
	body := proposal.Body
	plan := body.Plan
	raw, err := canon.New().Canonicalize(body)
	if err != nil {
		return nil, changeError(err)
	}
	view := &v1.ContainmentPlan{PlanId: body.ID, TenantId: body.Tenant, CompromisedIdentity: r.Msg.CompromisedIdentity, PlanDigest: proposal.Digest.String(), GraphVersion: plan.GraphVersion, CreatedAt: body.CreatedAt.Format(time.RFC3339Nano), MinimumProved: plan.MinimumProved, OptimalityScope: plan.OptimalityScope, ProposedZeroTier0Proved: true, DisruptionCost: plan.Cost, CanonicalPlanJson: raw, PolicyBundleHash: body.PolicyDigest.String(), ExpiresAt: body.ExpiresAt.Format(time.RFC3339Nano), Algorithm: plan.Algorithm, RouteCountComplete: body.RoutesComplete, SeveredTier0RoutesCount: int32(body.RoutesCount)}
	planID, err := uuid.Parse(body.ID)
	if err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	for _, action := range plan.Actions {
		digest, err := canon.New().Digest(action)
		if err != nil {
			return nil, changeError(err)
		}
		kind := action.Kind
		reason := "Remove this service permission to cut access to critical assets."
		if kind == "ROLE_REVOKE" {
			kind = "REVOKE_ROLE"
			reason = "Remove this role to cut access to critical assets."
		}
		if kind == "TERMINATE_SESSION" {
			reason = "End this session to cut access to critical assets."
		}
		if kind == "RESTRICT_ACCOUNT" {
			reason = "Restrict this account to cut access to critical assets."
		}
		view.RecommendedRevocations = append(view.RecommendedRevocations, &v1.RevocationAction{ActionId: uuid.NewSHA1(planID, digest.Bytes()).String(), ActionType: kind, TargetIdentity: action.Target, ResourceOrRole: action.Access, Reason: reason})
	}
	convert := func(activity graph.Activity) *v1.PreservedActivity {
		return &v1.PreservedActivity{ResourceId: activity.Resource, PermittedAction: activity.Action, Tier: int32(activity.Tier), IdentityId: activity.Identity}
	}
	for _, activity := range plan.Preserved {
		view.PreservedActivities = append(view.PreservedActivities, convert(activity))
	}
	for _, activity := range plan.Removed {
		view.DisruptedActivities = append(view.DisruptedActivities, convert(activity))
	}
	return connect.NewResponse(&v1.PlanContainmentResponse{Plan: view}), nil
}
