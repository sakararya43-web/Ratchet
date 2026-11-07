package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type decisionAPI struct{ service *workflow.Service }

// Connector evidence uses its own pinned signature, independent of browser
// cookies. Only this exact procedure is mounted outside session/CSRF middleware.
func NewKubernetesDecisionHandler(service *workflow.Service) (http.Handler, error) {
	if service == nil {
		return nil, domain.ErrInvalid
	}
	a := &decisionAPI{service}
	handler := connect.NewUnaryHandler(ratchetv1connect.DecisionServiceDecideKubernetesProcedure, a.DecideKubernetes, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusUpgradeRequired)
			return
		}
		handler.ServeHTTP(w, r)
	}), nil
}

func (a *decisionAPI) DecideKubernetes(ctx context.Context, r *connect.Request[v1.KubernetesDecisionRequest]) (*connect.Response[v1.DecisionResponse], error) {
	if len(r.Msg.SignedAdmissionJson) == 0 || len(r.Msg.SignedAdmissionJson) > 1<<20 {
		return nil, changeError(domain.ErrInvalid)
	}
	var message kube.SignedKubernetesAdmission
	decoder := json.NewDecoder(bytes.NewReader(r.Msg.SignedAdmissionJson))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&message) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, changeError(domain.ErrInvalid)
	}
	decision, err := a.service.DecideKubernetes(ctx, message)
	if errors.Is(err, kube.ErrAuthentication) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("connector authentication failed"))
	}
	if err != nil {
		return nil, changeError(err)
	}
	out := &v1.DecisionResponse{Outcome: decision.Decision.Outcome, Reasons: decision.Decision.Reasons, RequiredApproverGroups: decision.Decision.Groups, RequiredQuorum: int32(decision.Decision.Quorum), PolicyBundleHash: decision.PolicyDigest.String(), GraphVersion: decision.GraphVersion, DecisionId: decision.ID, ExactObjectDigest: decision.ObjectDigest.String(), ExecutionAuthorized: decision.ExecutionAuthorized, AdmissionRequestId: decision.AdmissionUID, TargetRevision: message.Admission.SourceResourceVersion, PolicyOutcome: decision.PolicyOutcome, AdmissionContextDigest: decision.ContextDigest.String()}
	out.TypedOutcome = v1.DecisionOutcome(v1.DecisionOutcome_value["DECISION_OUTCOME_"+out.Outcome])
	if decision.ExecutionAuthorized {
		out.ExpiresAt = decision.ExpiresAt.Format(time.RFC3339Nano)
		out.SignedNativeDecisionJson, err = json.Marshal(decision)
		if err != nil {
			return nil, changeError(err)
		}
	}
	return connect.NewResponse(out), nil
}

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
