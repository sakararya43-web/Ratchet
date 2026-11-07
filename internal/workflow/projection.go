package workflow

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
)

func (s *Service) Position(ctx context.Context, actor Actor, request string) (int64, error) {
	var position int64
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		c, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, request)
		if err != nil {
			return err
		}
		if _, err := s.visibility(ctx, tx, actor, c, snapshot, active); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT event_position FROM ratchet.change_projection WHERE tenant_id=$1 AND request_id=$2::uuid`, actor.TenantID, request).Scan(&position)
	})
	return position, err
}

func (s *Service) Attention(ctx context.Context, actor Actor) ([]domain.Change, bool, error) {
	result := []domain.Change{}
	truncated := false
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		// Filter before the limit so historical executions cannot hide pending work.
		rows, err := tx.Query(ctx, `SELECT request_id::text FROM ratchet.change_projection WHERE tenant_id=$1 AND
 (state IN ('SUBMITTED','ASSESSED','ALLOWED','AWAITING_APPROVAL','HELD','APPROVED','EXECUTING','FAILED') OR (state='REJECTED' AND updated_at>clock_timestamp()-interval '7 days') OR
 (state='EXECUTED' AND document->>'expiry_status' IN ('FAILED','REVOKING','SCHEDULED') AND (document->>'grant_expires_at')::timestamptz<=clock_timestamp()))
 ORDER BY CASE state WHEN 'FAILED' THEN 0 WHEN 'HELD' THEN 1 WHEN 'EXECUTING' THEN 2 WHEN 'AWAITING_APPROVAL' THEN 3 WHEN 'REJECTED' THEN 5 ELSE 4 END,updated_at DESC,request_id LIMIT 201`, actor.TenantID)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(ids) > 200 {
			ids = ids[:200]
			truncated = true
		}
		for _, id := range ids {
			c, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, id)
			if err != nil {
				return err
			}
			if _, err := s.visibility(ctx, tx, actor, c, snapshot, active); errors.Is(err, ErrPermission) {
				continue
			} else if err != nil {
				return err
			}
			result = append(result, c)
		}
		return nil
	})
	return result, truncated, err
}

// Rebuild reconstructs the read model from verified immutable evidence, never
// accepting a projection row as authority for workflow execution.
func (s *Service) Rebuild(ctx context.Context, tenant string) error {
	return s.Store.RebuildChanges(ctx, tenant)
}
