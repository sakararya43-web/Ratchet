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

type auditAPI struct {
	service *workflow.Service
	key     []byte
}
type auditCursor struct {
	Tenant                          string
	Start, RequestedEnd, After, End int64
	Previous, Tip                   ports.Digest
}

func NewAuditHandler(service *workflow.Service, key []byte) (http.Handler, error) {
	if service == nil || len(key) != 32 {
		return nil, domain.ErrInvalid
	}
	a := &auditAPI{service, append([]byte(nil), key...)}
	mux := http.NewServeMux()
	mux.Handle(ratchetv1connect.AuditServiceExportHashChainProcedure, connect.NewUnaryHandler(ratchetv1connect.AuditServiceExportHashChainProcedure, a.ExportHashChain, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(8<<20)))
	return mux, nil
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
