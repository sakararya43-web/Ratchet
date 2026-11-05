package eventstore

import (
	"context"

	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
)

// TryCheckpointSubmission serializes Authority delivery across core instances
// without locking the tenant head or any ledger row. A busy delivery can be
// retried from its immutable candidate; process loss releases the advisory lock.
func (s *Store) TryCheckpointSubmission(ctx context.Context, tenant string, submit func() error) (bool, error) {
	if !token.MatchString(tenant) || submit == nil {
		return false, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := storedb.New(tx).SetTenant(ctx, tenant); err != nil {
		return false, err
	}
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,319736))`, "checkpoint:"+tenant).Scan(&locked); err != nil {
		return false, err
	}
	if !locked {
		return false, nil
	}
	if err := submit(); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}
