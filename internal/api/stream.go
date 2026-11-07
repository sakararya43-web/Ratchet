package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

type watchCursor struct {
	Tenant, Actor, Kind string
	After               int64
}

func watchToken(key []byte, actor workflow.Actor, kind string, after int64) string {
	raw, _ := json.Marshal(watchCursor{actor.TenantID, actor.ID, kind, after})
	mac := watchMAC(key, raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac)
}
func watchMAC(key, raw []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("RATCHET_WATCH_CURSOR_V1:"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}
func watchAfter(key []byte, actor workflow.Actor, kind, token string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return 0, domain.ErrInvalid
	}
	raw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	var c watchCursor
	if e1 != nil || e2 != nil || !hmac.Equal(sig, watchMAC(key, raw)) || json.Unmarshal(raw, &c) != nil || c.Tenant != actor.TenantID || c.Actor != actor.ID || c.Kind != kind || c.After < 0 || c.After > ledger.MaxSafeInteger {
		return 0, domain.ErrInvalid
	}
	return c.After, nil
}

// Streams end cleanly after five seconds, within the HTTPS write timeout. Clients
// reconnect with the last received cursor; heartbeat-only frames advance safely.
func (a *ChangeAPI) WatchChanges(ctx context.Context, r *connect.Request[v1.WatchChangesRequest], stream *connect.ServerStream[v1.WatchChangesResponse]) error {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return err
	}
	after, err := watchAfter(a.key, p, "changes", r.Msg.GetCursor().GetAfterCursor())
	if err != nil {
		return changeError(err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		default:
		}
		page, err := a.service.StreamPage(ctx, p, "changes", after)
		if err != nil {
			return changeError(err)
		}
		for _, update := range page.Changes {
			view, err := a.request(ctx, update.Change)
			if err != nil {
				return changeError(err)
			}
			if err := stream.Send(&v1.WatchChangesResponse{Request: view, Cursor: watchToken(a.key, p, "changes", update.Sequence)}); err != nil {
				return err
			}
		}
		after = page.After
		if err := stream.Send(&v1.WatchChangesResponse{Cursor: watchToken(a.key, p, "changes", after), Heartbeat: true}); err != nil {
			return err
		}
		if after < page.End {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-ticker.C:
		}
	}
}
func (a *incidentAPI) WatchIncidents(ctx context.Context, r *connect.Request[v1.WatchIncidentsRequest], stream *connect.ServerStream[v1.WatchIncidentsResponse]) error {
	p, err := actor(ctx, r.Msg.TenantId, "")
	if err != nil {
		return err
	}
	after, err := watchAfter(a.key, p, "incidents", r.Msg.GetCursor().GetAfterCursor())
	if err != nil {
		return changeError(err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		default:
		}
		page, err := a.service.StreamPage(ctx, p, "incidents", after)
		if err != nil {
			return changeError(err)
		}
		for _, update := range page.Incidents {
			view, err := incidentView(update.Incident)
			if err != nil {
				return changeError(err)
			}
			if err := stream.Send(&v1.WatchIncidentsResponse{Incident: view, Cursor: watchToken(a.key, p, "incidents", update.Sequence)}); err != nil {
				return err
			}
		}
		after = page.After
		if err := stream.Send(&v1.WatchIncidentsResponse{Cursor: watchToken(a.key, p, "incidents", after), Heartbeat: true}); err != nil {
			return err
		}
		if after < page.End {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-ticker.C:
		}
	}
}
