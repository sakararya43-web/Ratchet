package workflow

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func (s *Service) ExportAudit(ctx context.Context, actor Actor, after, end int64, limit int, previous, tip *ports.Digest) (eventstore.ChainPage, error) {
	var page eventstore.ChainPage
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		if _, _, err := s.context(ctx, tx, actor, "audit_export", nil); err != nil {
			return err
		}
		var err error
		page, err = s.Store.ExportWithin(ctx, tx, actor.TenantID, after, end, limit, previous, tip)
		return err
	})
	return page, err
}
func (s *Service) QueryAudit(ctx context.Context, actor Actor, filter eventstore.AuditFilter, after, end int64, limit int) ([]eventstore.AuditView, int64, error) {
	var views []eventstore.AuditView
	var position int64
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		if _, _, err := s.context(ctx, tx, actor, "audit_query", nil); err != nil {
			return err
		}
		var err error
		views, position, err = s.Store.AuditWithin(ctx, tx, actor.TenantID, filter, after, end, limit)
		return err
	})
	return views, position, err
}
