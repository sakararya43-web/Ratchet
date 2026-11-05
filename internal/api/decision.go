package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type decisionAPI struct{ service *workflow.Service }

func NewDecisionHandler(service *workflow.Service) (http.Handler, error) {
	if service == nil {
		return nil, domain.ErrInvalid
	}
	a := &decisionAPI{service}
	return connect.NewUnaryHandler(ratchetv1connect.DecisionServiceDecideProcedure, a.Decide, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20)), nil
}

func (a *decisionAPI) Decide(ctx context.Context, r *connect.Request[v1.DecisionRequest]) (*connect.Response[v1.DecisionResponse], error) {
	i := r.Msg.Intent
	if i == nil || len(i.Context) != 0 {
		return nil, changeError(domain.ErrInvalid)
	}
	p, err := actor(ctx, i.TenantId, i.RequestedBy)
	if err != nil {
		return nil, err
	}
	kind := strings.TrimPrefix(i.Kind, "SIM_")
	intent, err := typedIntent(&v1.SubmitChangeRequest{Kind: kind, TargetIdentity: i.TargetIdentity, RequestedAccess: i.RequestedAccess, Intent: i.ExactIntent})
	if err != nil {
		return nil, changeError(err)
	}
	digest, err := ports.DigestFromHex(r.Msg.ExactObjectDigest)
	if err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	decision, err := a.service.DecideInline(ctx, p, workflow.InlineInput{Intent: intent, AdmissionID: r.Msg.AdmissionRequestId, ObjectDigest: digest, TargetRevision: r.Msg.TargetRevision, ApprovedRequest: r.Msg.ApprovedRequestId, MinGraphVersion: r.Msg.MinGraphVersion})
	if err != nil {
		return nil, changeError(err)
	}
	out := &v1.DecisionResponse{Outcome: decision.Decision.Outcome, Reasons: decision.Decision.Reasons, RequiredApproverGroups: decision.Decision.Groups, RequiredQuorum: int32(decision.Decision.Quorum), PolicyBundleHash: decision.PolicyDigest.String(), GraphVersion: decision.GraphVersion, DecisionId: decision.ID, ExactObjectDigest: decision.ObjectDigest.String(), ExecutionAuthorized: decision.ExecutionAuthorized, AdmissionRequestId: r.Msg.AdmissionRequestId, TargetRevision: r.Msg.TargetRevision, PolicyOutcome: decision.PolicyOutcome}
	out.TypedOutcome = v1.DecisionOutcome(v1.DecisionOutcome_value["DECISION_OUTCOME_"+out.Outcome])
	if !decision.ExpiresAt.IsZero() {
		out.ExpiresAt = decision.ExpiresAt.Format(time.RFC3339Nano)
	}
	if a.service.Authorize(ctx, p, "investigate") != nil {
		out.Reasons = []string{"Decision: " + out.Outcome}
		out.RequiredApproverGroups, out.PolicyBundleHash = nil, ""
	}
	return connect.NewResponse(out), nil
}
