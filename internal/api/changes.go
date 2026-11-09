package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type ChangeAPI struct {
	service *workflow.Service
	key     []byte
}

func NewChangeHandler(service *workflow.Service, key []byte) (http.Handler, error) {
	if service == nil || len(key) != 32 {
		return nil, domain.ErrInvalid
	}
	a := &ChangeAPI{service, append([]byte(nil), key...)}
	mux := http.NewServeMux()
	opts := []connect.HandlerOption{connect.WithReadMaxBytes(1 << 20), connect.WithSendMaxBytes(8 << 20)}
	mux.Handle(ratchetv1connect.ChangeServiceSubmitChangeProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceSubmitChangeProcedure, a.SubmitChange, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceGetChangeProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceGetChangeProcedure, a.GetChange, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceListChangesProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceListChangesProcedure, a.ListChanges, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceApproveChangeProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceApproveChangeProcedure, a.ApproveChange, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceRejectChangeProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceRejectChangeProcedure, a.RejectChange, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceHoldChangeProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceHoldChangeProcedure, a.HoldChange, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceRequestMoreInfoProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceRequestMoreInfoProcedure, a.RequestMoreInfo, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceProvideContextProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceProvideContextProcedure, a.ProvideContext, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceGetDecisionEvidenceProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceGetDecisionEvidenceProcedure, a.GetDecisionEvidence, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceListPolicyHistoryProcedure, connect.NewUnaryHandler(ratchetv1connect.ChangeServiceListPolicyHistoryProcedure, a.ListPolicyHistory, opts...))
	mux.Handle(ratchetv1connect.OverviewServiceGetAttentionItemsProcedure, connect.NewUnaryHandler(ratchetv1connect.OverviewServiceGetAttentionItemsProcedure, a.GetAttentionItems, opts...))
	mux.Handle(ratchetv1connect.ChangeServiceWatchChangesProcedure, connect.NewServerStreamHandler(ratchetv1connect.ChangeServiceWatchChangesProcedure, a.WatchChanges, opts...))
	return mux, nil
}
func changeError(err error) error {
	if err == nil {
		return nil
	}
	var code connect.Code
	switch {
	case errors.Is(err, domain.ErrInvalid), errors.Is(err, eventstore.ErrInvalid), errors.Is(err, kube.ErrInvalid):
		code = connect.CodeInvalidArgument
	case errors.Is(err, domain.ErrTransition), errors.Is(err, domain.ErrContextChanged):
		code = connect.CodeFailedPrecondition
	case errors.Is(err, kube.ErrUnsupported):
		code = connect.CodeFailedPrecondition
	case errors.Is(err, graph.ErrNoContainment):
		code = connect.CodeFailedPrecondition
	case errors.Is(err, eventstore.ErrVersionConflict):
		code = connect.CodeAborted
	case errors.Is(err, eventstore.ErrIdempotencyConflict):
		code = connect.CodeAlreadyExists
	case errors.Is(err, workflow.ErrPermission):
		code = connect.CodePermissionDenied
	case errors.Is(err, workflow.ErrDependency), errors.Is(err, eventstore.ErrResyncRequired):
		code = connect.CodeUnavailable
	case errors.Is(err, pgx.ErrNoRows):
		code = connect.CodeNotFound
	default:
		return rpcError(err)
	}
	return connect.NewError(code, err)
}
func actor(ctx context.Context, tenant, claimed string) (workflow.Actor, error) {
	p, ok := SessionPrincipal(ctx)
	if !ok {
		return workflow.Actor{}, connect.NewError(connect.CodeUnauthenticated, errors.New("session required"))
	}
	if p.TenantID != tenant || (claimed != "" && claimed != p.ActorID) {
		return workflow.Actor{}, connect.NewError(connect.CodePermissionDenied, errors.New("identity mismatch"))
	}
	return workflow.Actor{TenantID: p.TenantID, ID: p.ActorID}, nil
}
func mutation(m *v1.MutationContext) (uuid.UUID, int64, error) {
	if m == nil || m.ExpectedRevision < 0 || m.MinGraphVersion < 0 {
		return uuid.Nil, 0, changeError(domain.ErrInvalid)
	}
	id, err := uuid.Parse(m.IdempotencyKey)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, 0, changeError(domain.ErrInvalid)
	}
	if _, err := uuid.Parse(m.CorrelationId); err != nil {
		return uuid.Nil, 0, changeError(domain.ErrInvalid)
	}
	return id, m.ExpectedRevision, nil
}
func typedIntent(r *v1.SubmitChangeRequest) (domain.Intent, error) {
	i := domain.Intent{Kind: r.Kind, Target: r.TargetIdentity, Access: r.RequestedAccess, Emergency: r.Emergency, DurationSeconds: r.TimeLimitSeconds}
	if exact := r.Intent; exact != nil {
		if exact.Kubernetes != nil {
			return i, domain.ErrInvalid
		}
		kind := strings.TrimPrefix(exact.Kind.String(), "CHANGE_KIND_")
		if (r.Kind != "" && r.Kind != kind) || (r.TargetIdentity != "" && r.TargetIdentity != exact.TargetIdentity) || (r.RequestedAccess != "" && r.RequestedAccess != exact.RequestedAccess) {
			return i, domain.ErrInvalid
		}
		i = domain.Intent{Kind: kind, Target: exact.TargetIdentity, Access: exact.RequestedAccess, Resources: exact.RequestedResources, Permissions: exact.RequestedPermissions, Emergency: exact.Emergency, DurationSeconds: exact.TimeLimitSeconds, IncidentID: exact.IncidentId, Parameters: exact.SafeguardParameters}
	}
	return i, i.Validate()
}
func (a *ChangeAPI) request(ctx context.Context, c domain.Change) (*v1.ChangeRequest, error) {
	p, err := actor(ctx, c.TenantID, "")
	if err != nil {
		return nil, err
	}
	detail, err := a.service.ResponseDetail(ctx, p, c)
	if err != nil {
		return nil, err
	}
	return a.view(ctx, p, c, detail)
}

// view builds the response for a change whose visibility was already decided.
func (a *ChangeAPI) view(ctx context.Context, p workflow.Actor, c domain.Change, detail bool) (*v1.ChangeRequest, error) {
	text, err := a.service.PrivateContext(ctx, c)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		text = "Private context removed by retention."
	}
	r := &v1.ChangeRequest{RequestId: c.ID, TenantId: c.TenantID, Kind: c.Intent.Kind, TargetIdentity: c.Intent.Target, RequestedAccess: c.Intent.Access, Justification: text, RequestedBy: c.Requester, Emergency: c.Intent.Emergency, TimeLimitSeconds: c.Intent.DurationSeconds, Status: string(c.State), ChangeDigest: c.Digest.String(), Revision: c.Revision, RequiredApproverGroups: c.Decision.Groups, RequiredQuorum: int32(c.Decision.Quorum), DecisionReasons: c.Decision.Reasons, CreatedAt: c.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), UpdatedAt: c.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00")}
	r.TypedKind = v1.ChangeKind(v1.ChangeKind_value["CHANGE_KIND_"+c.Intent.Kind])
	if detail && c.Intent.Kubernetes != nil {
		value, err := a.service.KubernetesContext(ctx, p, c)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			raw, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			r.KubernetesContext = &v1.NormalizedKubernetesMutation{NormalizedMutationJson: raw}
		}
	}
	r.RequestedResources, r.RequestedPermissions = c.Intent.Resources, c.Intent.Permissions
	r.ExpiryStatus = c.ExpiryStatus
	if !c.GrantExpiresAt.IsZero() {
		r.GrantExpiresAt = c.GrantExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	if c.Scope != nil {
		r.ScopeOverBroad = c.Scope.OverBroad
		if detail {
			r.ScopeExtraResources, r.ScopeExtraPermissions = c.Scope.Resources, c.Scope.Permissions
		}
	}
	var requesterQuestion string
	if (detail || c.ReviewKind == "MORE_INFO") && c.ReviewReference != "" {
		review := c
		review.PrivateReference = c.ReviewReference
		note, err := a.service.PrivateContext(ctx, review)
		if err == nil {
			if detail {
				r.DecisionReasons = append(append([]string(nil), r.DecisionReasons...), note)
			} else {
				requesterQuestion = note
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	r.State = v1.ChangeState(v1.ChangeState_value["CHANGE_STATE_"+string(c.State)])
	if detail && c.Envelope != nil {
		r.GraphVersion = c.Envelope.GraphVersion
		r.PolicyBundleHash = c.Envelope.PolicyDigest.String()
		raw, err := canon.New().Canonicalize(c.Envelope)
		if err != nil {
			return nil, err
		}
		r.CanonicalApprovalEnvelopeJson = raw
	}
	if !detail {
		r.ChangeDigest = ""
		r.RequiredApproverGroups = nil
		r.DecisionReasons = []string{"Request status: " + string(c.State)}
		if requesterQuestion != "" {
			r.DecisionReasons = append(r.DecisionReasons, requesterQuestion)
		}
	}
	return r, nil
}
func (a *ChangeAPI) SubmitChange(ctx context.Context, r *connect.Request[v1.SubmitChangeRequest]) (*connect.Response[v1.SubmitChangeResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, r.Msg.RequestedBy)
	if err != nil {
		return nil, err
	}
	id, rev, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	if rev != 0 {
		return nil, changeError(domain.ErrInvalid)
	}
	var c domain.Change
	if native := r.Msg.Kubernetes; native != nil {
		if r.Msg.Intent != nil || r.Msg.Emergency || r.Msg.TimeLimitSeconds != 0 || (r.Msg.Kind != "" && r.Msg.Kind != "K8S_RBAC_CHANGE") {
			return nil, changeError(domain.ErrInvalid)
		}
		var value kube.Mutation
		decoder := json.NewDecoder(bytes.NewReader(native.NormalizedMutationJson))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || value.Validate() != nil {
			return nil, changeError(domain.ErrInvalid)
		}
		if (r.Msg.TargetIdentity != "" && r.Msg.TargetIdentity != workflow.NativeObjectKey(value)) || (r.Msg.RequestedAccess != "" && r.Msg.RequestedAccess != value.Operation) {
			return nil, changeError(domain.ErrInvalid)
		}
		c, err = a.service.SubmitKubernetes(ctx, p, workflow.KubernetesSubmit{Mutation: value, Justification: r.Msg.Justification, CommandID: id, MinGraphVersion: r.Msg.Mutation.MinGraphVersion, CorrelationID: r.Msg.Mutation.CorrelationId})
	} else {
		intent, e := typedIntent(r.Msg)
		if e != nil {
			return nil, changeError(e)
		}
		c, err = a.service.Submit(ctx, p, workflow.Submit{Intent: intent, Justification: r.Msg.Justification, CommandID: id, MinGraphVersion: r.Msg.Mutation.MinGraphVersion, CorrelationID: r.Msg.Mutation.CorrelationId})
	}
	if err != nil {
		return nil, changeError(err)
	}
	view, err := a.request(ctx, c)
	return connect.NewResponse(&v1.SubmitChangeResponse{Request: view}), changeError(err)
}
func (a *ChangeAPI) ProvideContext(ctx context.Context, r *connect.Request[v1.ProvideContextRequest]) (*connect.Response[v1.ProvideContextResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	id, revision, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	c, err := a.service.ProvideContext(ctx, p, r.Msg.RequestId, id, revision, r.Msg.Context)
	if err != nil {
		return nil, changeError(err)
	}
	view, err := a.request(ctx, c)
	return connect.NewResponse(&v1.ProvideContextResponse{Request: view}), changeError(err)
}
func (a *ChangeAPI) GetChange(ctx context.Context, r *connect.Request[v1.GetChangeRequest]) (*connect.Response[v1.GetChangeResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	c, err := a.service.View(ctx, p, r.Msg.RequestId)
	if err != nil {
		return nil, changeError(err)
	}
	view, err := a.request(ctx, c)
	return connect.NewResponse(&v1.GetChangeResponse{Request: view}), changeError(err)
}

type changeCursor struct {
	Tenant, Filter  string
	After, Position int64
	Temporary       bool
}

func (a *ChangeAPI) cursor(c changeCursor) string {
	raw, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (a *ChangeAPI) ListChanges(ctx context.Context, r *connect.Request[v1.ListChangesRequest]) (*connect.Response[v1.ListChangesResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	size := int(r.Msg.PageSize)
	if size == 0 {
		size = 50
	}
	if size < 1 || size > 200 {
		return nil, changeError(domain.ErrInvalid)
	}
	cursor := changeCursor{Tenant: p.TenantID, Filter: r.Msg.StatusFilter, Temporary: r.Msg.TemporaryGrantsOnly}
	if token := r.Msg.PageToken; token != "" {
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			return nil, changeError(domain.ErrInvalid)
		}
		raw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
		sig, e2 := base64.RawURLEncoding.DecodeString(parts[1])
		mac := hmac.New(sha256.New, a.key)
		_, _ = mac.Write(raw)
		if e1 != nil || e2 != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(raw, &cursor) != nil || cursor.Tenant != p.TenantID || cursor.Filter != r.Msg.StatusFilter || cursor.Temporary != r.Msg.TemporaryGrantsOnly || cursor.After < 0 || cursor.Position < 1 {
			return nil, changeError(domain.ErrInvalid)
		}
	}
	list := a.service.ListWindow
	if cursor.Temporary {
		list = a.service.ListTemporaryGrants
	}
	page, err := list(ctx, p, cursor.Filter, cursor.After, cursor.Position, size)
	if err != nil {
		return nil, changeError(err)
	}
	response := &v1.ListChangesResponse{SnapshotEndSequence: page.End, WatchCursor: watchToken(a.key, p, "changes", page.End)}
	if page.More {
		response.NextPageToken = a.cursor(changeCursor{Tenant: p.TenantID, Filter: cursor.Filter, After: page.After, Position: page.End, Temporary: cursor.Temporary})
	}
	for i, c := range page.Changes {
		// Reuse the window's own visibility decision: re-deciding per change reloaded the
		// whole graph context for every row and could disagree with the window snapshot.
		view, err := a.view(ctx, p, c, page.Details[i])
		if err != nil {
			return nil, changeError(err)
		}
		response.Requests = append(response.Requests, view)
	}
	return connect.NewResponse(response), nil
}
func (a *ChangeAPI) ApproveChange(ctx context.Context, r *connect.Request[v1.ApproveChangeRequest]) (*connect.Response[v1.ApproveChangeResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, r.Msg.ApproverId)
	if err != nil {
		return nil, err
	}
	id, rev, err := mutation(r.Msg.Mutation)
	if err != nil {
		return nil, err
	}
	expected, err := ports.DigestFromHex(r.Msg.ApprovedEnvelopeDigest)
	if err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	var submission ports.ApprovalSubmission
	// The raw fields use the agreed Go port's standard base64 byte encoding.
	if err := json.Unmarshal([]byte(r.Msg.AssertionResponseJson), &submission); err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	if (submission.ActorID != "" && submission.ActorID != p.ID) || (submission.TenantID != "" && submission.TenantID != p.TenantID) {
		return nil, changeError(workflow.ErrPermission)
	}
	c, err := a.service.Approve(ctx, p, r.Msg.RequestId, id, rev, expected, submission)
	if err != nil {
		return nil, changeError(err)
	}
	view, err := a.request(ctx, c)
	return connect.NewResponse(&v1.ApproveChangeResponse{Approved: c.State == domain.Approved, Request: view}), changeError(err)
}
func (a *ChangeAPI) review(ctx context.Context, tenant, claimed, request string, m *v1.MutationContext, kind, reason string) (*v1.ChangeRequest, error) {
	p, err := actor(ctx, tenant, claimed)
	if err != nil {
		return nil, err
	}
	id, rev, err := mutation(m)
	if err != nil {
		return nil, err
	}
	c, err := a.service.Review(ctx, p, request, id, rev, kind, reason)
	if err != nil {
		return nil, changeError(err)
	}
	view, err := a.request(ctx, c)
	return view, changeError(err)
}
func (a *ChangeAPI) RejectChange(ctx context.Context, r *connect.Request[v1.RejectChangeRequest]) (*connect.Response[v1.RejectChangeResponse], error) {
	c, err := a.review(ctx, r.Msg.TenantId, r.Msg.RejecterId, r.Msg.RequestId, r.Msg.Mutation, "REJECT", r.Msg.Reason)
	return connect.NewResponse(&v1.RejectChangeResponse{Rejected: err == nil, Request: c}), err
}
func (a *ChangeAPI) HoldChange(ctx context.Context, r *connect.Request[v1.HoldChangeRequest]) (*connect.Response[v1.HoldChangeResponse], error) {
	c, err := a.review(ctx, r.Msg.TenantId, r.Msg.ActorId, r.Msg.RequestId, r.Msg.Mutation, "HOLD", r.Msg.Reason)
	return connect.NewResponse(&v1.HoldChangeResponse{Request: c}), err
}
func (a *ChangeAPI) RequestMoreInfo(ctx context.Context, r *connect.Request[v1.RequestMoreInfoRequest]) (*connect.Response[v1.RequestMoreInfoResponse], error) {
	c, err := a.review(ctx, r.Msg.TenantId, r.Msg.ActorId, r.Msg.RequestId, r.Msg.Mutation, "MORE_INFO", r.Msg.Question)
	return connect.NewResponse(&v1.RequestMoreInfoResponse{Request: c}), err
}
func (a *ChangeAPI) GetAttentionItems(ctx context.Context, r *connect.Request[v1.GetAttentionItemsRequest]) (*connect.Response[v1.GetAttentionItemsResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	changes, truncated, err := a.service.Attention(ctx, p)
	if err != nil {
		return nil, changeError(err)
	}
	response := &v1.GetAttentionItemsResponse{}
	for _, c := range changes {
		if c.State == domain.Expired || c.State == domain.Revoked {
			continue
		}
		view, err := a.request(ctx, c)
		if err != nil {
			return nil, changeError(err)
		}
		response.PendingRequests = append(response.PendingRequests, view)
		itemType, title, severity := "PENDING_CHANGE", string(c.State)+": "+c.Intent.Kind, "review"
		if c.State == domain.Executed {
			itemType, title, severity = "TEMPORARY_GRANT_EXPIRY", "Temporary access requires verified revocation: "+c.ExpiryStatus, "high"
		}
		response.AttentionItems = append(response.AttentionItems, &v1.AttentionItem{ItemId: c.ID, ItemType: itemType, Title: title, Description: strings.Join(view.DecisionReasons, "; "), Severity: severity, EntityId: c.ID, CreatedAt: view.CreatedAt})
	}
	incidentPage, err := a.service.ListIncidents(ctx, p, "", 0, 0, 20)
	if err != nil && !errors.Is(err, workflow.ErrPermission) {
		return nil, changeError(err)
	}
	if err == nil {
		truncated = truncated || incidentPage.More
		for _, incident := range incidentPage.Incidents {
			view, err := incidentView(incident)
			if err != nil {
				return nil, changeError(err)
			}
			response.ActiveIncidents = append(response.ActiveIncidents, view)
			response.AttentionItems = append(response.AttentionItems, &v1.AttentionItem{ItemId: view.IncidentId, ItemType: "ACTIVE_INCIDENT", Title: view.Title, Severity: view.Severity, EntityId: view.IncidentId, CreatedAt: view.OpenedAt})
		}
	}
	res := connect.NewResponse(response)
	if truncated {
		res.Header().Set("X-Ratchet-Truncated", "true")
	}
	return res, nil
}
