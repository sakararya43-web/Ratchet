package api

import (
	"context"
	"maps"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
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
	mux.Handle(ratchetv1connect.ContainmentServiceExecuteContainmentProcedure, connect.NewUnaryHandler(ratchetv1connect.ContainmentServiceExecuteContainmentProcedure, a.ExecuteContainment, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(8<<20)))
	mux.Handle(ratchetv1connect.ContainmentServiceRestoreAccessProcedure, connect.NewUnaryHandler(ratchetv1connect.ContainmentServiceRestoreAccessProcedure, a.RestoreAccess, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20)))
	return mux, nil
}

func (a *containmentAPI) RestoreAccess(ctx context.Context, r *connect.Request[v1.RestoreAccessRequest]) (*connect.Response[v1.RestoreAccessResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, r.Msg.RequestedBy)
	if err != nil {
		return nil, err
	}
	id, revision, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	if revision != 0 || r.Msg.IncidentId == "" {
		return nil, changeError(domain.ErrInvalid)
	}
	kind := "ROLE_ASSIGN"
	if r.Msg.AccessToRestore == "" {
		kind = "ENABLE_ACCOUNT"
	} else if strings.HasPrefix(r.Msg.AccessToRestore, "perm:") || strings.HasPrefix(r.Msg.AccessToRestore, "grant:") {
		kind = "RESTORE_SERVICE_PERMISSION"
	} else if strings.HasPrefix(r.Msg.AccessToRestore, "session:") {
		kind = "ISSUE_SESSION"
	}
	change, err := a.service.Submit(ctx, p, workflow.Submit{
		CommandID:       id,
		CorrelationID:   r.Msg.Mutation.CorrelationId,
		MinGraphVersion: r.Msg.Mutation.MinGraphVersion,
		Justification:   r.Msg.Justification,
		Intent: domain.Intent{
			Kind:       kind,
			Target:     r.Msg.TargetIdentity,
			Access:     r.Msg.AccessToRestore,
			IncidentID: r.Msg.IncidentId,
		},
	})
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.RestoreAccessResponse{ChangeRequestId: change.ID}), nil
}

func (a *containmentAPI) ExecuteContainment(ctx context.Context, r *connect.Request[v1.ExecuteContainmentRequest]) (*connect.Response[v1.ExecuteContainmentResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, r.Msg.ResponderId)
	if err != nil {
		return nil, err
	}
	id, revision, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	if revision != 0 || r.Msg.PlanId == "" || r.Msg.ApprovedPlanDigest == "" {
		return nil, changeError(domain.ErrInvalid)
	}
	planDigest, err := ports.DigestFromHex(r.Msg.ApprovedPlanDigest)
	if err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	res, err := a.service.ExecuteContainment(ctx, p, workflow.ExecuteContainmentInput{
		CommandID:       id,
		CorrelationID:   r.Msg.Mutation.CorrelationId,
		PlanID:          r.Msg.PlanId,
		PlanDigest:      planDigest,
		AssertionJSON:   r.Msg.AssertionResponseJson,
		ResponderID:     r.Msg.ResponderId,
		MinGraphVersion: r.Msg.Mutation.MinGraphVersion,
	})
	if err != nil {
		return nil, changeError(err)
	}
	var results []*v1.ExecResult
	for _, er := range res.ExecutionResults {
		results = append(results, &v1.ExecResult{
			CommandId:           er.ActionID,
			TenantId:            r.Msg.TenantId,
			RequestId:           r.Msg.PlanId,
			Success:             er.Success,
			ErrorMessage:        er.ErrorMessage,
			AppliedAt:           er.AppliedAt.Format(time.RFC3339Nano),
			TargetRevisionAfter: er.TargetRevisionAfter,
			ReadBackVerified:    er.ReadBackVerified,
		})
	}
	return connect.NewResponse(&v1.ExecuteContainmentResponse{
		Executed:          res.Executed,
		IncidentId:        res.IncidentID,
		ExecutionResults:  results,
		VerifiedLatencyMs: res.VerifiedLatencyMs,
	}), nil
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
	view, err := containmentView(proposal)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.PlanContainmentResponse{Plan: view}), nil
}

func containmentView(proposal workflow.ContainmentProposal) (*v1.ContainmentPlan, error) {
	body := proposal.Body
	plan := body.Plan
	if len(plan.Origins) != 1 {
		return nil, domain.ErrInvalid
	}
	raw, err := canon.New().Canonicalize(body)
	if err != nil {
		return nil, changeError(err)
	}
	view := &v1.ContainmentPlan{PlanId: body.ID, TenantId: body.Tenant, CompromisedIdentity: plan.Origins[0], PlanDigest: proposal.Digest.String(), GraphVersion: plan.GraphVersion, CreatedAt: body.CreatedAt.Format(time.RFC3339Nano), MinimumProved: plan.MinimumProved, OptimalityScope: plan.OptimalityScope, ProposedZeroTier0Proved: true, DisruptionCost: plan.Cost, CanonicalPlanJson: raw, PolicyBundleHash: body.PolicyDigest.String(), ExpiresAt: body.ExpiresAt.Format(time.RFC3339Nano), Algorithm: plan.Algorithm, RouteCountComplete: body.RoutesComplete, SeveredTier0RoutesCount: int32(body.RoutesCount)}
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
	return view, nil
}
