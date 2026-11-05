package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// CheckpointSchedule prepares bounded candidates, never Authority signatures.
// Actor must remain authorized by the current signed policy on every tick.
type CheckpointSchedule struct {
	Actor     string
	Interval  time.Duration
	Authority *CheckpointAuthority
}

type CheckpointTickArgs struct {
	Tenant string    `json:"tenant_id"`
	Due    time.Time `json:"due_at"`
}

func (CheckpointTickArgs) Kind() string { return "ratchet_checkpoint_tick_v1" }

type checkpointTickWorker struct {
	river.WorkerDefaults[CheckpointTickArgs]
	service *Service
}

func (w *checkpointTickWorker) Work(ctx context.Context, job *river.Job[CheckpointTickArgs]) error {
	return w.service.TickCheckpoint(ctx, job.Args)
}

type CheckpointDeliveryArgs struct {
	Tenant string       `json:"tenant_id"`
	Digest ports.Digest `json:"checkpoint_digest"`
}

func (CheckpointDeliveryArgs) Kind() string { return "ratchet_checkpoint_delivery_v1" }

type checkpointDeliveryWorker struct {
	river.WorkerDefaults[CheckpointDeliveryArgs]
	service *Service
}

func (w *checkpointDeliveryWorker) Work(ctx context.Context, job *river.Job[CheckpointDeliveryArgs]) error {
	return w.service.DeliverCheckpoint(ctx, job.Args)
}

// DeliverCheckpoint uses the real Authority HTTP boundary outside the tenant
// transaction, retaining the immutable candidate while real members sign it.
func (s *Service) DeliverCheckpoint(ctx context.Context, args CheckpointDeliveryArgs) error {
	schedule, ok := s.config.CheckpointSchedules[args.Tenant]
	if !ok || schedule.Authority == nil || args.Digest.IsZero() {
		return river.JobCancel(domain.ErrInvalid)
	}
	actor := Actor{TenantID: args.Tenant, ID: schedule.Actor}
	signed, err := s.SubmitCheckpoint(ctx, actor, args.Digest, schedule.Authority)
	if errors.Is(err, domain.ErrContextChanged) {
		return river.JobCancel(err)
	}
	if err != nil {
		return err
	}
	var proposal CheckpointProposal
	err = s.Store.WithTenantTx(ctx, args.Tenant, func(tx pgx.Tx, _ time.Time) error {
		_, active, err := s.context(ctx, tx, actor, "checkpoint_manage", nil)
		if err != nil {
			return err
		}
		proposal, err = s.checkpointProposal(ctx, tx, args.Tenant, args.Digest, active.Root)
		return err
	})
	if err != nil {
		return err
	}
	registry, err := policy.VerifyRegistry(proposal.RegistryProof, proposal.Root, args.Tenant)
	if err != nil {
		return err
	}
	ready, err := registry.CheckpointStatus(proposal.Candidate, signed)
	if err != nil {
		return err
	}
	if !ready {
		return river.JobSnooze(min(schedule.Interval, 30*time.Second))
	}
	_, err = s.AcceptCheckpoint(ctx, actor, signed)
	if errors.Is(err, domain.ErrContextChanged) {
		return river.JobCancel(err)
	}
	return err
}

func (s *Service) insertCheckpointTick(ctx context.Context, tx pgx.Tx, tenant string, due time.Time) error {
	_, err := s.jobs.InsertTx(ctx, tx, CheckpointTickArgs{tenant, due.UTC()}, &river.InsertOpts{Queue: tenantQueue(tenant), ScheduledAt: due, MaxAttempts: 100, UniqueOpts: river.UniqueOpts{ByArgs: true}})
	return err
}

func (s *Service) ensureCheckpointSchedules(ctx context.Context) error {
	for tenant := range s.config.CheckpointSchedules {
		if err := s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
			if _, err := tx.Exec(ctx, `INSERT INTO ratchet.checkpoint_schedules(tenant_id,next_run_at) VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, now); err != nil {
				return err
			}
			var due time.Time
			if err := tx.QueryRow(ctx, `SELECT next_run_at FROM ratchet.checkpoint_schedules WHERE tenant_id=$1`, tenant).Scan(&due); err != nil {
				return err
			}
			return s.insertCheckpointTick(ctx, tx, tenant, due)
		}); err != nil {
			return err
		}
	}
	return nil
}

// TickCheckpoint atomically commits a candidate (if needed), the next database-
// time deadline and its durable job. Concurrent/restarted workers share one slot.
// Pending unsigned candidates are retained instead of producing competing roots.
func (s *Service) TickCheckpoint(ctx context.Context, args CheckpointTickArgs) error {
	schedule, ok := s.config.CheckpointSchedules[args.Tenant]
	if !ok || !s.tenants[args.Tenant] || args.Due.IsZero() {
		return river.JobCancel(domain.ErrInvalid)
	}
	return s.Store.WithTenantTx(ctx, args.Tenant, func(tx pgx.Tx, now time.Time) error {
		var due time.Time
		if err := tx.QueryRow(ctx, `SELECT next_run_at FROM ratchet.checkpoint_schedules WHERE tenant_id=$1`, args.Tenant).Scan(&due); err != nil {
			return err
		}
		if !due.Equal(args.Due) {
			return nil
		}
		if now.Before(due) {
			return river.JobSnooze(due.Sub(now))
		}
		actor := Actor{TenantID: args.Tenant, ID: schedule.Actor}
		_, active, err := s.context(ctx, tx, actor, "checkpoint_manage", nil)
		if err != nil {
			return err
		}
		prior, err := s.latestCheckpoint(ctx, tx, args.Tenant, 0, active.Root)
		if err != nil {
			return err
		}
		from := int64(1)
		if prior != nil {
			from = prior.Evidence.Signed.ToSequence + 1
		}
		var digest []byte
		registryJSON, err := json.Marshal(active.RegistryDigest)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT digest FROM ratchet.checkpoint_candidates WHERE tenant_id=$1 AND (convert_from(document,'UTF8')::jsonb->'candidate'->'checkpoint'->>'from_sequence')::bigint=$2 AND convert_from(document,'UTF8')::jsonb->'registry_digest'=$3::jsonb ORDER BY event_position LIMIT 1`, args.Tenant, from, registryJSON).Scan(&digest)
		if err == nil {
			d, err := ports.DigestFromBytes(digest)
			if err != nil {
				return err
			}
			if _, err := s.checkpointProposal(ctx, tx, args.Tenant, d, active.Root); err != nil {
				return err
			}
		} else if errors.Is(err, pgx.ErrNoRows) {
			var head int64
			if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, args.Tenant).Scan(&head); err != nil {
				return err
			}
			if head >= from {
				id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(args.Tenant+":checkpoint-tick:"+due.UTC().Format(time.RFC3339Nano)))
				proposal, err := s.prepareCheckpointWithin(ctx, tx, now, actor, PrepareCheckpointInput{CommandID: id})
				if err != nil {
					return err
				}
				digest = proposal.Candidate.Checkpoint.CheckpointDigest.Bytes()
			}
		} else {
			return err
		}
		if schedule.Authority != nil && len(digest) > 0 {
			d, err := ports.DigestFromBytes(digest)
			if err != nil {
				return err
			}
			if _, err := s.jobs.InsertTx(ctx, tx, CheckpointDeliveryArgs{args.Tenant, d}, &river.InsertOpts{Queue: tenantQueue(args.Tenant), MaxAttempts: 100, UniqueOpts: river.UniqueOpts{ByArgs: true}}); err != nil {
				return err
			}
		}
		// Coalesce missed intervals after downtime; checkpoint ranges still catch up
		// from the last accepted root, bounded by the existing 4096-event limit.
		next := due.Add((now.Sub(due)/schedule.Interval + 1) * schedule.Interval)
		if _, err := tx.Exec(ctx, `UPDATE ratchet.checkpoint_schedules SET next_run_at=$2 WHERE tenant_id=$1`, args.Tenant, next); err != nil {
			return err
		}
		return s.insertCheckpointTick(ctx, tx, args.Tenant, next)
	})
}
