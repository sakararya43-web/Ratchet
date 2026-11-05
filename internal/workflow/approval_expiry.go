package workflow

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type ApprovalExpiryArgs struct {
	Tenant  string       `json:"tenant_id"`
	Request string       `json:"request_id"`
	Digest  ports.Digest `json:"envelope_digest"`
	Expires time.Time    `json:"expires_at"`
}

func (ApprovalExpiryArgs) Kind() string { return "ratchet_approval_expiry_v1" }

type approvalExpiryWorker struct {
	river.WorkerDefaults[ApprovalExpiryArgs]
	service *Service
}

func (w *approvalExpiryWorker) Work(ctx context.Context, job *river.Job[ApprovalExpiryArgs]) error {
	return w.service.ExpireApproval(ctx, job.Args)
}

func (s *Service) scheduleApprovalExpiry(ctx context.Context, tx pgx.Tx, c domain.Change, digest ports.Digest, expires time.Time) error {
	_, err := s.jobs.InsertTx(ctx, tx, ApprovalExpiryArgs{c.TenantID, c.ID, digest, expires}, &river.InsertOpts{Queue: tenantQueue(c.TenantID), ScheduledAt: expires, MaxAttempts: 100, UniqueOpts: river.UniqueOpts{ByArgs: true}})
	return err
}

var errObsoleteExpiry = errors.New("approval expiry superseded or terminal")

// ExpireApproval takes its deadline from the exact persisted envelope. A late job
// may expire still-pending approval; it cannot revoke an executed grant or expire
// a replacement assessment. Revision conflicts retry rather than lose the timer.
func (s *Service) ExpireApproval(ctx context.Context, args ApprovalExpiryArgs) error {
	if !s.tenants[args.Tenant] || args.Digest.IsZero() || args.Expires.IsZero() {
		return river.JobCancel(domain.ErrInvalid)
	}
	c, err := s.Store.ReadChange(ctx, args.Tenant, args.Request)
	if err != nil {
		return err
	}
	digest, err := canon.New().Digest(args)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("approval-expiry:"+args.Tenant+":"+args.Request+":"+digest.String()))
	_, err = s.Store.MutateChange(ctx, eventstore.ChangeMutation{TenantID: args.Tenant, ActorID: "core-approval-expiry", RequestID: args.Request, ID: id, ExpectedRevision: c.Revision, InputDigest: digest}, func(_ pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
		if current.Envelope == nil || current.Digest != args.Digest || !current.Envelope.ExpiresAt.Equal(args.Expires) || !slices.Contains([]domain.State{domain.Allowed, domain.AwaitingApproval, domain.Approved}, current.State) {
			return nil, errObsoleteExpiry
		}
		if now.Before(current.Envelope.ExpiresAt) {
			return nil, river.JobSnooze(current.Envelope.ExpiresAt.Sub(now))
		}
		return domain.Decide(current, domain.Command{Kind: "EXPIRE", At: now})
	})
	if errors.Is(err, errObsoleteExpiry) {
		return nil
	}
	return err
}
