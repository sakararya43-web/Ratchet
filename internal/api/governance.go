package api

import (
	"context"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

func (a *ChangeAPI) GetDecisionEvidence(ctx context.Context, r *connect.Request[v1.GetDecisionEvidenceRequest]) (*connect.Response[v1.GetDecisionEvidenceResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	e, err := a.service.DecisionEvidence(ctx, p, r.Msg.RequestId, r.Msg.AssessmentRevision)
	if err != nil {
		return nil, changeError(err)
	}
	raw, err := canon.New().Canonicalize(e)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.GetDecisionEvidenceResponse{CanonicalEvidenceJson: raw, AssessmentEventHash: e.EventHash.String(), GenesisDigest: e.Root.String()}), nil
}
func (a *ChangeAPI) ListPolicyHistory(ctx context.Context, r *connect.Request[v1.ListPolicyHistoryRequest]) (*connect.Response[v1.ListPolicyHistoryResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	limit := int(r.Msg.PageSize)
	if limit == 0 {
		limit = 50
	}
	records, more, err := a.service.PolicyHistory(ctx, p, r.Msg.AfterEventPosition, limit)
	if err != nil {
		return nil, changeError(err)
	}
	response := &v1.ListPolicyHistoryResponse{HasMore: more}
	for _, record := range records {
		response.Activations = append(response.Activations, &v1.PolicyActivationRecord{BundleVersion: record.Version, BundleDigest: record.Digest, RegistryEpoch: record.Epoch, RegistryDigest: record.RegistryDigest, EventPosition: record.Position})
		response.NextEventPosition = record.Position
	}
	return connect.NewResponse(response), nil
}
