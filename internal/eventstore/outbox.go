package eventstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
)

type Backlog struct {
	Pending   int64
	OldestAge time.Duration
	Attempts  int64
}

// DeliverOne holds a per-tenant transaction lock until the broker acknowledges
// persistence. A crash after publish replays the same immutable event UUID.
func (s *Store) DeliverOne(ctx context.Context, tenant string, publish func(context.Context, string, string, []byte) error) (bool, error) {
	if !token.MatchString(tenant) || publish == nil {
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
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,319735))`, tenant).Scan(&locked); err != nil {
		return false, err
	}
	if !locked {
		return false, nil
	}
	var id, subject string
	var payload []byte
	var due bool
	var attempts int
	err = tx.QueryRow(ctx, `SELECT event_id::text,subject,payload,next_attempt_at<=clock_timestamp(),attempts FROM ratchet.outbox WHERE tenant_id=$1 AND delivered_at IS NULL ORDER BY sequence LIMIT 1 FOR UPDATE`, tenant).Scan(&id, &subject, &payload, &due, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !due {
		return false, nil
	}
	publication := publish(ctx, subject, id, payload)
	if publication == nil {
		_, err = tx.Exec(ctx, `UPDATE ratchet.outbox SET delivered_at=clock_timestamp(),attempts=attempts+1 WHERE tenant_id=$1 AND event_id=$2::uuid`, tenant, id)
	} else {
		backoff := time.Duration(1<<min(attempts, 8)) * 100 * time.Millisecond
		_, err = tx.Exec(ctx, `UPDATE ratchet.outbox SET attempts=attempts+1,next_attempt_at=clock_timestamp()+$3*interval '1 millisecond' WHERE tenant_id=$1 AND event_id=$2::uuid`, tenant, id, backoff.Milliseconds())
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, publication
}

// DeliverPriority delivers urgent priority messages (such as containment commands)
// under an independent advisory lock (key 319736) and a dedicated query, ensuring that
// emergency reduction cannot be blocked or starved by ordinary queue backlog or shared locks.
func (s *Store) DeliverPriority(ctx context.Context, tenant string, publish func(context.Context, string, string, []byte) error) (bool, error) {
	if !token.MatchString(tenant) || publish == nil {
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
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,319736))`, tenant).Scan(&locked); err != nil {
		return false, err
	}
	if !locked {
		return false, nil
	}
	var id, subject string
	var payload []byte
	var due bool
	var attempts int
	err = tx.QueryRow(ctx, `SELECT event_id::text,subject,payload,next_attempt_at<=clock_timestamp(),attempts FROM ratchet.outbox WHERE tenant_id=$1 AND delivered_at IS NULL AND subject LIKE '%.contain.%' ORDER BY sequence LIMIT 1 FOR UPDATE`, tenant).Scan(&id, &subject, &payload, &due, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !due {
		return false, nil
	}
	publication := publish(ctx, subject, id, payload)
	if publication == nil {
		_, err = tx.Exec(ctx, `UPDATE ratchet.outbox SET delivered_at=clock_timestamp(),attempts=attempts+1 WHERE tenant_id=$1 AND event_id=$2::uuid`, tenant, id)
	} else {
		backoff := time.Duration(1<<min(attempts, 8)) * 100 * time.Millisecond
		_, err = tx.Exec(ctx, `UPDATE ratchet.outbox SET attempts=attempts+1,next_attempt_at=clock_timestamp()+$3*interval '1 millisecond' WHERE tenant_id=$1 AND event_id=$2::uuid`, tenant, id, backoff.Milliseconds())
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, publication
}

func (s *Store) OutboxBacklog(ctx context.Context, tenant string) (Backlog, error) {
	if !token.MatchString(tenant) {
		return Backlog{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Backlog{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := storedb.New(tx).SetTenant(ctx, tenant); err != nil {
		return Backlog{}, err
	}
	var b Backlog
	var age float64
	err = tx.QueryRow(ctx, `SELECT count(*),coalesce(extract(epoch FROM clock_timestamp()-min(created_at)),0)::float8,coalesce(sum(attempts),0)::bigint FROM ratchet.outbox WHERE tenant_id=$1 AND delivered_at IS NULL`, tenant).Scan(&b.Pending, &age, &b.Attempts)
	b.OldestAge = time.Duration(age * float64(time.Second))
	return b, err
}
