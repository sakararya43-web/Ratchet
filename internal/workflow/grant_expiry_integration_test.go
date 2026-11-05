//go:build integration

package workflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func observationDigest(t *testing.T, r *workflow.ExecutionResult) {
	t.Helper()
	slices.Sort(r.ObservedRoles)
	var err error
	r.ObservationDigest, err = canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{r.ObservedTenant, r.ObservedTarget, r.ObservedRoles, r.ObservedRevision, r.ObservedAt})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryGrantRestartsExpiresAndRequiresVerifiedRevocation(t *testing.T) {
	for _, refusal := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "changed-target-refusal"}[refusal], func(t *testing.T) {
			sys, service, c, signer, replacement := readyExecution(t, domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", Emergency: true, DurationSeconds: 2, Resources: []string{"reports"}, Permissions: []string{"read"}})
			if c.GrantExpiresAt.IsZero() || c.ExpiryStatus != "SCHEDULED" || c.Decision.Quorum != 1 || len(c.Approvals) != 1 {
				t.Fatal("temporary dispatch omitted expiry or bypassed approvals")
			}
			var timers int
			if err := sys.pool.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet_jobs.river_job WHERE kind='ratchet_grant_expiry_v1' AND args->>'tenant_id'=$1 AND args->>'request_id'=$2`, sys.tenant, c.ID).Scan(&timers); err != nil || timers != 1 {
				t.Fatal("grant and timer not atomic", timers, err)
			}
			r := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "source", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: true, ReadBackVerified: true, ObservedTenant: sys.tenant, ObservedTarget: c.Intent.Target, ObservedRoles: []string{"role:finance"}, ObservedRevision: 11, AppliedAt: c.UpdatedAt.Add(time.Microsecond), ObservedAt: time.Now().UTC()}
			observationDigest(t, &r)
			if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, r, signer)); err != nil {
				t.Fatal(err)
			}
			waitState(t, sys, c.ID, domain.Executed)
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := service.Stop(stop); err != nil {
				t.Fatal(err)
			}
			cancel()
			for time.Now().Before(c.GrantExpiresAt.Add(100 * time.Millisecond)) {
				time.Sleep(20 * time.Millisecond)
			}
			next := replacement()
			start(t, next, sys.ctx)
			var current domain.Change
			for deadline := time.Now().Add(5 * time.Second); ; {
				var err error
				current, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
				if err != nil {
					t.Fatal(err)
				}
				if current.ExpiryStatus == "REVOKING" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("replacement worker lost expiry", current.ExpiryStatus)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if current.State != domain.Executed {
				t.Fatal("timer falsely claimed revocation")
			}
			var raw []byte
			if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
				return tx.QueryRow(sys.ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, sys.tenant, current.ExpiryExecutionID).Scan(&raw)
			}); err != nil {
				t.Fatal(err)
			}
			var cmd workflow.PreparedCommand
			if json.Unmarshal(raw, &cmd) != nil || cmd.Purpose != "EXPIRE_GRANT" || cmd.OriginalCommandID != c.ExecutionID || cmd.ExpectedRevision != 11 || len(cmd.ExpectedRoles) != 0 || cmd.DispatchedAt.Before(c.GrantExpiresAt) {
				t.Fatal("expiry command did not bind exact timer-owned assignment")
			}
			r.CommandID, r.MessageID = cmd.CommandID, uuid.NewString()
			r.ReadBackVerified = false
			if err := next.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, r, signer)); err != nil {
				t.Fatal(err)
			}
			if got, _ := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID); got.State != domain.Executed {
				t.Fatal("ACK falsely marked revoked")
			}
			r.MessageID, r.ReadBackVerified, r.ObservedRoles, r.ObservedRevision = uuid.NewString(), true, []string{}, 12
			r.ObservedAt = time.Now().UTC()
			r.AppliedAt = cmd.DispatchedAt.Add(time.Microsecond)
			observationDigest(t, &r)
			wrong := r
			wrong.ObservedRoles = []string{"role:finance"}
			observationDigest(t, &wrong)
			if err := next.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, wrong, signer)); !errors.Is(err, workflow.ErrPermission) {
				t.Fatal("grant still present accepted as revoked", err)
			}
			if refusal {
				r.Success, r.AppliedAt, r.ObservedRoles = false, time.Time{}, []string{"role:finance", "role:admin"}
				observationDigest(t, &r)
			}
			if err := next.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, r, signer)); err != nil {
				t.Fatal(err)
			}
			got, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if refusal {
				if got.State != domain.Executed || got.ExpiryStatus != "FAILED" {
					t.Fatal("CAS refusal lost attention state")
				}
				attention, _, err := next.Attention(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"})
				if err != nil || len(attention) != 1 || attention[0].ID != c.ID {
					t.Fatal("failed revocation missing from attention", err)
				}
			} else if got.State != domain.Revoked || got.ExpiryStatus != "REVOKED" {
				t.Fatal("verified removal missing")
			}
			listed, err := next.ListTemporaryGrants(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, "", 0, 0, 10)
			if err != nil || len(listed.Changes) != 1 || listed.Changes[0].ID != c.ID {
				t.Fatal("post-expiry review list missing", err)
			}
		})
	}
}
