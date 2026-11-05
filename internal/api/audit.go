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
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type auditAPI struct {
	service     *workflow.Service
	key         []byte
	authorities map[string]*workflow.CheckpointAuthority
}
type auditCursor struct {
	Tenant                          string
	Start, RequestedEnd, After, End int64
	Previous, Tip                   ports.Digest
}

func NewAuditHandler(service *workflow.Service, key []byte, configured ...map[string]*workflow.CheckpointAuthority) (http.Handler, error) {
	if service == nil || len(key) != 32 || len(configured) > 1 {
		return nil, domain.ErrInvalid
	}
	a := &auditAPI{service: service, key: append([]byte(nil), key...), authorities: map[string]*workflow.CheckpointAuthority{}}
	if len(configured) == 1 {
		for tenant, authority := range configured[0] {
			if tenant == "" || authority == nil {
				return nil, domain.ErrInvalid
			}
			a.authorities[tenant] = authority
		}
	}
	mux := http.NewServeMux()
	mux.Handle(ratchetv1connect.AuditServiceExportHashChainProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServiceExportHashChainProcedure, a.ExportHashChain, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(8<<20)))
	mux.Handle(ratchetv1connect.AuditServiceQueryAuditEventsProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServiceQueryAuditEventsProcedure, a.QueryAuditEvents, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(8<<20)))
	mux.Handle(ratchetv1connect.AuditServicePrepareCheckpointProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServicePrepareCheckpointProcedure, a.PrepareCheckpoint, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(4<<20)))
	if len(a.authorities) > 0 {
		mux.Handle(ratchetv1connect.AuditServiceSubmitCheckpointProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServiceSubmitCheckpointProcedure, a.SubmitCheckpoint, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20)))
	}
	mux.Handle(ratchetv1connect.AuditServiceAcceptCheckpointProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServiceAcceptCheckpointProcedure, a.AcceptCheckpoint, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(4<<20)))
	mux.Handle(ratchetv1connect.AuditServiceListCheckpointsProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServiceListCheckpointsProcedure, a.ListCheckpoints, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(8<<20)))
	return mux, nil
}

type auditQueryCursor struct {
	Tenant     string
	Filter     ports.Digest
	After, End int64
}

func (a *auditAPI) queryMAC(raw []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte("RATCHET_AUDIT_QUERY_CURSOR_V1:"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}
func (a *auditAPI) QueryAuditEvents(ctx context.Context, r *connect.Request[v1.QueryAuditEventsRequest]) (*connect.Response[v1.QueryAuditEventsResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	if len(r.Msg.ActorId) > 256 || len(r.Msg.ResourceId) > 256 {
		return nil, changeError(domain.ErrInvalid)
	}
	filter := eventstore.AuditFilter{Resource: r.Msg.ResourceId, Request: r.Msg.RequestId, Incident: r.Msg.IncidentId}
	if r.Msg.ActorId != "" {
		filter.Actor = uuid.NewSHA1(uuid.NameSpaceOID, []byte(p.TenantID+":"+r.Msg.ActorId)).String()
	}
	for _, id := range []*string{&filter.Request, &filter.Incident} {
		if *id != "" {
			if parsed, err := uuid.Parse(*id); err != nil || parsed == uuid.Nil {
				return nil, changeError(domain.ErrInvalid)
			} else {
				*id = parsed.String()
			}
		}
	}
	parse := func(raw string) (*time.Time, error) {
		if raw == "" {
			return nil, nil
		}
		stamp, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, domain.ErrInvalid
		}
		stamp = stamp.UTC()
		return &stamp, nil
	}
	filter.Start, err = parse(r.Msg.StartTime)
	if err != nil {
		return nil, changeError(err)
	}
	filter.End, err = parse(r.Msg.EndTime)
	if err != nil {
		return nil, changeError(err)
	}
	if filter.Start != nil && filter.End != nil && filter.Start.After(*filter.End) {
		return nil, changeError(domain.ErrInvalid)
	}
	size := int(r.Msg.PageSize)
	if size == 0 {
		size = 50
	}
	if size < 1 || size > 200 {
		return nil, changeError(domain.ErrInvalid)
	}
	digest, err := canon.New().Digest(filter)
	if err != nil {
		return nil, changeError(err)
	}
	c := auditQueryCursor{Tenant: p.TenantID, Filter: digest}
	if token := r.Msg.PageToken; token != "" {
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			return nil, changeError(domain.ErrInvalid)
		}
		raw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
		signature, e2 := base64.RawURLEncoding.DecodeString(parts[1])
		if e1 != nil || e2 != nil || !hmac.Equal(signature, a.queryMAC(raw)) || json.Unmarshal(raw, &c) != nil || c.Tenant != p.TenantID || c.Filter != digest || c.After < 0 || c.End < c.After || c.End > ledger.MaxSafeInteger {
			return nil, changeError(domain.ErrInvalid)
		}
	}
	views, end, err := a.service.QueryAudit(ctx, p, filter, c.After, c.End, size+1)
	if err != nil {
		return nil, changeError(err)
	}
	more := len(views) > size
	if more {
		views = views[:size]
	}
	response := &v1.QueryAuditEventsResponse{SnapshotEndSequence: end}
	for _, view := range views {
		event := view.Event
		response.Events = append(response.Events, &v1.LedgerEvent{SequenceNumber: event.Sequence, TenantId: p.TenantID, EventType: event.Type, EventPayloadJson: string(view.Display), PreviousEventHash: event.Entry.Previous.String(), EventHash: event.Entry.Hash.String(), RecordedAt: event.RecordedAt.Format(time.RFC3339Nano), FormatVersion: 1, StreamId: event.StreamID, StreamVersion: event.StreamVersion, EventId: event.ID.String()})
	}
	if more {
		c.After = views[len(views)-1].Event.Sequence
		c.End = end
		raw, _ := json.Marshal(c)
		response.NextPageToken = base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(a.queryMAC(raw))
	}
	return connect.NewResponse(response), nil
}
func (a *auditAPI) mac(raw []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte("RATCHET_AUDIT_EXPORT_CURSOR_V1:"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}
func (a *auditAPI) token(c auditCursor) string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(a.mac(raw))
}
func (a *auditAPI) ExportHashChain(ctx context.Context, r *connect.Request[v1.ExportHashChainRequest]) (*connect.Response[v1.ExportHashChainResponse], error) {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return nil, err
	}
	start := r.Msg.StartSequence
	if start == 0 {
		start = 1
	}
	if start < 1 || start > ledger.MaxSafeInteger || r.Msg.EndSequence < 0 || r.Msg.EndSequence > ledger.MaxSafeInteger || (r.Msg.EndSequence > 0 && r.Msg.EndSequence < start) {
		return nil, changeError(domain.ErrInvalid)
	}
	limit := int(r.Msg.PageSize)
	if limit == 0 {
		limit = 25
	}
	if limit < 1 || limit > 100 {
		return nil, changeError(domain.ErrInvalid)
	}
	c := auditCursor{Tenant: p.TenantID, Start: start, RequestedEnd: r.Msg.EndSequence, After: start - 1, End: r.Msg.EndSequence}
	var previous, tip *ports.Digest
	if token := r.Msg.PageToken; token != "" {
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			return nil, changeError(domain.ErrInvalid)
		}
		raw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
		signature, e2 := base64.RawURLEncoding.DecodeString(parts[1])
		if e1 != nil || e2 != nil || !hmac.Equal(signature, a.mac(raw)) || json.Unmarshal(raw, &c) != nil || c.Tenant != p.TenantID || c.Start != start || c.RequestedEnd != r.Msg.EndSequence || c.After < start-1 || c.End < c.After || c.End > ledger.MaxSafeInteger {
			return nil, changeError(domain.ErrInvalid)
		}
		previous = &c.Previous
		tip = &c.Tip
	}
	page, err := a.service.ExportAudit(ctx, p, c.After, c.End, limit, previous, tip)
	if err != nil {
		return nil, changeError(err)
	}
	response := &v1.ExportHashChainResponse{TenantId: p.TenantID, SnapshotEndSequence: page.End, SnapshotEndHash: page.EndHash.String(), ExportProfile: "RATCHET_LEDGER_CHAIN_V1", PagePreviousHash: page.Previous.String()}
	if !page.AcceptedCheckpointDigest.IsZero() {
		response.LatestCheckpointDigest = page.AcceptedCheckpointDigest.String()
	}
	for _, event := range page.Events {
		response.Chain = append(response.Chain, &v1.LedgerEvent{SequenceNumber: event.Sequence, TenantId: p.TenantID, EventType: event.Type, PreviousEventHash: event.Entry.Previous.String(), EventHash: event.Entry.Hash.String(), RecordedAt: event.RecordedAt.UTC().Format(time.RFC3339Nano), FormatVersion: 1, CanonicalContent: event.Entry.Canonical, StreamId: event.StreamID, StreamVersion: event.StreamVersion, EventId: event.ID.String()})
	}
	if page.After < page.End {
		c.After = page.After
		c.End = page.End
		c.Previous = page.LastHash
		c.Tip = page.EndHash
		response.NextPageToken = a.token(c)
	}
	return connect.NewResponse(response), nil
}
