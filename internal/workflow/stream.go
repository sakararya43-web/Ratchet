package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
)

type ChangeWindow struct {
	Changes    []domain.Change
	After, End int64
	More       bool
}

func (s *Service) ListWindow(ctx context.Context, actor Actor, status string, after, end int64, limit int) (ChangeWindow, error) {
	return s.listWindow(ctx, actor, status, after, end, limit, false)
}

func (s *Service) ListTemporaryGrants(ctx context.Context, actor Actor, status string, after, end int64, limit int) (ChangeWindow, error) {
	return s.listWindow(ctx, actor, status, after, end, limit, true)
}

func (s *Service) listWindow(ctx context.Context, actor Actor, status string, after, end int64, limit int, temporaryOnly bool) (ChangeWindow, error) {
	page := ChangeWindow{Changes: []domain.Change{}, After: after, End: end}
	if after < 0 || end < 0 || end > ledger.MaxSafeInteger || limit < 1 || limit > 201 {
		return page, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		var head int64
		if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, actor.TenantID).Scan(&head); err != nil {
			return err
		}
		if page.End == 0 {
			page.End = head
		}
		if after > page.End || page.End > head {
			return domain.ErrInvalid
		}
		rows, err := tx.Query(ctx, `SELECT stream_id,min(sequence) FROM ratchet.events WHERE tenant_id=$1 AND stream_id LIKE 'change:%' AND sequence<=$2 GROUP BY stream_id HAVING min(sequence)>$3 ORDER BY min(sequence) LIMIT 1001`, actor.TenantID, page.End, after)
		if err != nil {
			return err
		}
		type ref struct {
			stream   string
			position int64
		}
		refs := []ref{}
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.stream, &r.position); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i, r := range refs {
			if i == 1000 || len(page.Changes) == limit {
				page.More = true
				break
			}
			page.After = r.position
			c, err := s.Store.ChangeAtWithin(ctx, tx, actor.TenantID, r.stream[len("change:"):], page.End)
			if err != nil {
				return err
			}
			if status != "" && string(c.State) != status {
				continue
			}
			if temporaryOnly && c.Intent.DurationSeconds <= 0 {
				continue
			}
			if _, err := s.visibility(ctx, tx, actor, c, snapshot, active); errors.Is(err, ErrPermission) {
				continue
			} else if err != nil {
				return err
			}
			page.Changes = append(page.Changes, c)
		}
		return nil
	})
	return page, err
}

type ChangeUpdate struct {
	Change   domain.Change
	Sequence int64
}
type IncidentUpdate struct {
	Incident IncidentView
	Sequence int64
}
type StreamPage struct {
	Changes    []ChangeUpdate
	Incidents  []IncidentUpdate
	After, End int64
}

// StreamPage verifies the contiguous source chain, then filters display updates.
// Its consumed position includes hidden/nonmatching records without exposing them.
func (s *Service) StreamPage(ctx context.Context, actor Actor, kind string, after int64) (StreamPage, error) {
	page := StreamPage{}
	if kind != "changes" && kind != "incidents" {
		return page, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		operation := "view"
		if kind == "incidents" {
			operation = "incident_view"
		}
		snapshot, active, err := s.context(ctx, tx, actor, operation, nil)
		if err != nil {
			return err
		}
		chain, err := s.Store.ExportWithin(ctx, tx, actor.TenantID, after, 0, 100, nil, nil)
		if err != nil {
			return err
		}
		page.After, page.End = chain.After, chain.End
		for _, event := range chain.Events {
			if kind == "changes" && len(event.StreamID) > len("change:") && event.StreamID[:len("change:")] == "change:" {
				var content ledger.Content
				var payload struct {
					Facts domain.Event `json:"facts"`
				}
				if json.Unmarshal(event.Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil {
					return eventstore.ErrIntegrity
				}
				c := payload.Facts.Change
				if c.ID != event.StreamID[len("change:"):] || c.TenantID != actor.TenantID || c.Revision != event.StreamVersion || payload.Facts.Type != event.Type {
					return eventstore.ErrIntegrity
				}
				if _, err := s.visibility(ctx, tx, actor, c, snapshot, active); errors.Is(err, ErrPermission) {
					continue
				} else if err != nil {
					return err
				}
				page.Changes = append(page.Changes, ChangeUpdate{c, event.Sequence})
			}
			if kind == "incidents" && len(event.StreamID) > len("incident:") && event.StreamID[:len("incident:")] == "incident:" {
				incident, err := s.incidentWithin(ctx, tx, actor.TenantID, event.StreamID[len("incident:"):], event.Sequence)
				if err != nil {
					return err
				}
				view, err := s.incidentView(ctx, tx, incident, snapshot, now)
				if err != nil {
					return err
				}
				page.Incidents = append(page.Incidents, IncidentUpdate{view, event.Sequence})
			}
		}
		return nil
	})
	return page, err
}
