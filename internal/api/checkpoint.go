package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

func (a *auditAPI) PrepareCheckpoint(ctx context.Context, r *connect.Request[v1.PrepareCheckpointRequest]) (*connect.Response[v1.PrepareCheckpointResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
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
	proposal, err := a.service.PrepareCheckpoint(ctx, p, workflow.PrepareCheckpointInput{CommandID: id, EndSequence: r.Msg.EndSequence})
	if err != nil {
		return nil, changeError(err)
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.PrepareCheckpointResponse{ProposalJson: raw, CheckpointDigest: proposal.Candidate.Checkpoint.CheckpointDigest.String()}), nil
}
func (a *auditAPI) SubmitCheckpoint(ctx context.Context, r *connect.Request[v1.SubmitCheckpointRequest]) (*connect.Response[v1.SubmitCheckpointResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	digest, err := ports.DigestFromHex(r.Msg.CheckpointDigest)
	if err != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	returned, err := a.service.SubmitCheckpoint(ctx, p, digest, a.authorities[p.TenantID])
	if err != nil {
		return nil, changeError(err)
	}
	raw, err := json.Marshal(returned)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.SubmitCheckpointResponse{AuthorityCheckpointJson: raw}), nil
}
func (a *auditAPI) AcceptCheckpoint(ctx context.Context, r *connect.Request[v1.AcceptCheckpointRequest]) (*connect.Response[v1.AcceptCheckpointResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	var signed trust.AuditCheckpoint
	if len(r.Msg.AuthorityCheckpointJson) > 64<<10 || json.Unmarshal(r.Msg.AuthorityCheckpointJson, &signed) != nil {
		return nil, changeError(domain.ErrInvalid)
	}
	record, err := a.service.AcceptCheckpoint(ctx, p, signed)
	if err != nil {
		return nil, changeError(err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, changeError(err)
	}
	return connect.NewResponse(&v1.AcceptCheckpointResponse{CheckpointRecordJson: raw, ReferenceSequence: record.ReferenceSequence}), nil
}

type checkpointCursor struct {
	Tenant                   string
	After, End, RequestedEnd int64
}

func (a *auditAPI) checkpointMAC(raw []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte("RATCHET_CHECKPOINT_CURSOR_V1:"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}
func (a *auditAPI) ListCheckpoints(ctx context.Context, r *connect.Request[v1.ListCheckpointsRequest]) (*connect.Response[v1.ListCheckpointsResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	size := int(r.Msg.PageSize)
	if size == 0 {
		size = 10
	}
	if size < 1 || size > 50 || r.Msg.SnapshotEndSequence < 0 || r.Msg.SnapshotEndSequence > ledger.MaxSafeInteger {
		return nil, changeError(domain.ErrInvalid)
	}
	c := checkpointCursor{Tenant: p.TenantID, End: r.Msg.SnapshotEndSequence, RequestedEnd: r.Msg.SnapshotEndSequence}
	if token := r.Msg.PageToken; token != "" {
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			return nil, changeError(domain.ErrInvalid)
		}
		raw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
		signature, e2 := base64.RawURLEncoding.DecodeString(parts[1])
		if e1 != nil || e2 != nil || !hmac.Equal(signature, a.checkpointMAC(raw)) || json.Unmarshal(raw, &c) != nil || c.Tenant != p.TenantID || c.RequestedEnd != r.Msg.SnapshotEndSequence || c.After < 0 || c.End < c.After || c.End > ledger.MaxSafeInteger {
			return nil, changeError(domain.ErrInvalid)
		}
	}
	records, end, err := a.service.Checkpoints(ctx, p, c.After, c.End, size+1)
	if err != nil {
		return nil, changeError(err)
	}
	more := len(records) > size
	if more {
		records = records[:size]
	}
	response := &v1.ListCheckpointsResponse{SnapshotEndSequence: end}
	bytes := 0
	for i, record := range records {
		raw, err := json.Marshal(record)
		if err != nil {
			return nil, changeError(err)
		}
		if bytes+len(raw) > 4<<20 && i > 0 {
			more = true
			break
		}
		response.CheckpointRecordsJson = append(response.CheckpointRecordsJson, raw)
		bytes += len(raw)
		c.After = record.ReferenceSequence
	}
	if more {
		c.End = end
		raw, _ := json.Marshal(c)
		response.NextPageToken = base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(a.checkpointMAC(raw))
	}
	return connect.NewResponse(response), nil
}
