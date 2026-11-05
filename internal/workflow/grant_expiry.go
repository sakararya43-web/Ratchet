package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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

type GrantExpiryArgs struct {
	Tenant      string       `json:"tenant_id"`
	Request     string       `json:"request_id"`
	ExecutionID string       `json:"grant_command_id"`
	Digest      ports.Digest `json:"envelope_digest"`
	Probe       int64        `json:"probe"`
}

func (GrantExpiryArgs) Kind() string { return "ratchet_grant_expiry_v1" }

type grantExpiryWorker struct {
	river.WorkerDefaults[GrantExpiryArgs]
	service *Service
}

func (w *grantExpiryWorker) Work(ctx context.Context, job *river.Job[GrantExpiryArgs]) error {
	return w.service.ExpireGrant(ctx, job.Args)
}
func (s *Service) scheduleGrantExpiry(ctx context.Context, tx pgx.Tx, args GrantExpiryArgs, at time.Time) error {
	_, err := s.jobs.InsertTx(ctx, tx, args, &river.InsertOpts{Queue: tenantQueue(args.Tenant), ScheduledAt: at, MaxAttempts: 100, UniqueOpts: river.UniqueOpts{ByArgs: true}})
	return err
}

// ExpireGrant removes only the exact timer-owned assignment under the original
// post-grant target revision. Later target changes cause a verified refusal,
// never a blind deletion of an independently renewed or permanent assignment.
func (s *Service) ExpireGrant(ctx context.Context, args GrantExpiryArgs) error {
	if !s.tenants[args.Tenant] || args.ExecutionID == "" || args.Digest.IsZero() || args.Probe < 0 {
		return river.JobCancel(domain.ErrInvalid)
	}
	c, err := s.Store.ReadChange(ctx, args.Tenant, args.Request)
	if err != nil {
		return err
	}
	hash, err := canon.New().Digest(args)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("grant-expiry:"+args.Tenant+":"+args.Request+":"+hash.String()))
	var command *PreparedCommand
	var stamp time.Time
	var first bool
	execution := s.executions[args.Tenant]
	if execution == nil || !execution.capability.ScheduledRevocation {
		return ErrDependency
	}
	m := eventstore.ChangeMutation{TenantID: args.Tenant, ActorID: "core-grant-expiry", RequestID: args.Request, ID: id, ExpectedRevision: c.Revision, InputDigest: hash}
	m.Additional = func(tx pgx.Tx, receipt eventstore.Receipt) error {
		if command == nil {
			return eventstore.ErrIntegrity
		}
		if first {
			return execution.stage(ctx, tx, *command, receipt, stamp)
		}
		raw, err := json.Marshal(command)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.outbox(tenant_id,event_id,sequence,subject,payload,created_at) VALUES($1,$2,$3,$4,$5,$6)`, args.Tenant, command.MessageID, receipt.LastSequence, "ratchet."+args.Tenant+".exec."+execution.Connector, raw, stamp)
		return err
	}
	_, err = s.Store.MutateChange(ctx, m, func(tx pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
		if current.ExecutionID != args.ExecutionID || current.Digest != args.Digest || current.GrantExpiresAt.IsZero() || current.State == domain.Revoked || current.State == domain.Failed || current.ExpiryStatus == "FAILED" {
			return nil, errObsoleteExpiry
		}
		if now.Before(current.GrantExpiresAt) {
			return nil, river.JobSnooze(current.GrantExpiresAt.Sub(now))
		}
		if current.State == domain.Executing {
			return nil, river.JobSnooze(time.Second)
		}
		if current.State != domain.Executed {
			return nil, errObsoleteExpiry
		}
		var raw []byte
		var cmd PreparedCommand
		kind := "EXPIRY_RECONCILE"
		if current.ExpiryStatus == "SCHEDULED" {
			if !now.Before(execution.capability.Expires) {
				return nil, ErrDependency
			}
			if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, args.Tenant, args.ExecutionID).Scan(&raw); err != nil {
				return nil, err
			}
			if json.Unmarshal(raw, &cmd) != nil || cmd.Purpose != "TEMPORARY_GRANT" || !cmd.GrantExpiresAt.Equal(current.GrantExpiresAt) || cmd.EnvelopeDigest != current.Digest {
				return nil, eventstore.ErrIntegrity
			}
			cmd.OriginalCommandID = cmd.CommandID
			cmd.CommandID = uuid.NewSHA1(uuid.MustParse(cmd.CommandID), []byte("expire-grant")).String()
			cmd.MessageID = cmd.CommandID
			cmd.Purpose = "EXPIRE_GRANT"
			cmd.ExpectedRevision++
			cmd.BeforeRoles = slices.Clone(cmd.ExpectedRoles)
			cmd.ExpectedRoles = slices.DeleteFunc(slices.Clone(cmd.ExpectedRoles), func(role string) bool { return role == current.Intent.Access })
			cmd.DispatchedAt = now
			cmd.Deadline = now.Add(15 * time.Minute)
			if execution.capability.Expires.Before(cmd.Deadline) {
				cmd.Deadline = execution.capability.Expires
			}
			first, kind = true, "EXPIRE_GRANT"
		} else if current.ExpiryStatus == "REVOKING" {
			if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, args.Tenant, current.ExpiryExecutionID).Scan(&raw); err != nil {
				return nil, err
			}
			if json.Unmarshal(raw, &cmd) != nil || cmd.Purpose != "EXPIRE_GRANT" {
				return nil, eventstore.ErrIntegrity
			}
			cmd.VerifyOnly = true
			cmd.MessageID = uuid.NewSHA1(id, []byte("verify-expiry")).String()
		} else {
			return nil, eventstore.ErrIntegrity
		}
		cmd.Signature = nil
		digest, err := signingDigest("RATCHET_EXEC_COMMAND_V1", cmd)
		if err != nil {
			return nil, err
		}
		cmd.Signature = ed25519.Sign(execution.private, digest[:])
		command, stamp = &cmd, now
		next := args
		next.Probe++
		if err := s.scheduleGrantExpiry(ctx, tx, next, now.Add(20*time.Second)); err != nil {
			return nil, err
		}
		return domain.Decide(current, domain.Command{Kind: kind, At: now, ExecutionID: cmd.CommandID})
	})
	if errors.Is(err, errObsoleteExpiry) {
		return nil
	}
	return err
}

func (s *Service) expiryResult(_ context.Context, _ pgx.Tx, now time.Time, c domain.Change, command PreparedCommand, result ExecutionResult) ([]domain.Event, error) {
	if !result.ReadBackVerified {
		return domain.Decide(c, domain.Command{Kind: "EXPIRY_RECONCILE", At: now, ExecutionID: command.CommandID})
	}
	roles := slices.Clone(result.ObservedRoles)
	slices.Sort(roles)
	digest, err := canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{result.ObservedTenant, result.ObservedTarget, roles, result.ObservedRevision, result.ObservedAt})
	if err != nil {
		return nil, err
	}
	if result.ObservedTenant != c.TenantID || result.ObservedTarget != c.Intent.Target || result.ObservedAt.Before(command.DispatchedAt) || result.ObservedAt.After(now.Add(time.Minute)) || digest != result.ObservationDigest {
		return nil, ErrPermission
	}
	kind := "REVOKE_VERIFIED"
	if result.Success {
		if !applicationTimeValid(command, result) || result.AppliedAt.Before(c.GrantExpiresAt) || result.ObservedRevision != command.ExpectedRevision+1 || !slices.Equal(roles, command.ExpectedRoles) {
			return nil, ErrPermission
		}
	} else {
		// A changed revision is valid evidence of CAS refusal. The timer must not
		// retry a write against that new state without independent review.
		if !result.AppliedAt.IsZero() || result.ObservedRevision < command.ExpectedRevision {
			return nil, ErrPermission
		}
		kind = "EXPIRY_FAILED"
	}
	events, err := domain.Decide(c, domain.Command{Kind: kind, At: now, ExecutionID: command.CommandID, Verified: true})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	events[0].Change.Facts = raw
	return events, nil
}
