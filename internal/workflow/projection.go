package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Service) Position(ctx context.Context, actor Actor, request string) (int64, error) {
	var position int64
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		if _, _, err := s.context(ctx, tx, actor, "view", nil); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT event_position FROM ratchet.change_projection WHERE tenant_id=$1 AND request_id=$2::uuid`, actor.TenantID, request).Scan(&position)
	})
	return position, err
}

// Rebuild reconstructs the read model from verified immutable evidence, never
// accepting a projection row as authority for workflow execution.
func (s *Service) Rebuild(ctx context.Context, tenant string) error {
	return s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		rows, err := tx.Query(ctx, `SELECT substring(stream_id from 8),max(sequence) FROM ratchet.events WHERE tenant_id=$1 AND stream_id LIKE 'change:%' GROUP BY stream_id ORDER BY max(sequence)`, tenant)
		if err != nil {
			return err
		}
		type ref struct {
			id       string
			position int64
		}
		refs := []ref{}
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.id, &r.position); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM ratchet.change_projection WHERE tenant_id=$1`, tenant); err != nil {
			return err
		}
		for _, r := range refs {
			c, err := s.Store.ChangeWithin(ctx, tx, tenant, r.id)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(c)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ratchet.change_projection(tenant_id,request_id,event_position,state,updated_at,document) VALUES($1,$2,$3,$4,$5,$6)`, tenant, r.id, r.position, string(c.State), c.UpdatedAt, raw); err != nil {
				return err
			}
		}
		return nil
	})
}
