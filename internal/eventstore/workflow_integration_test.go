//go:build integration

package eventstore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestWorkflowRollbackIncludesJobProjectionPrivateDataAndOutbox(t *testing.T) {
	ctx, pool, store, tenant := setup(t)
	request := uuid.NewString()
	record, err := eventstore.SealPrivate(bytes.Repeat([]byte{14}, 32), tenant, uuid.New(), "workflow-v1", []byte("private rollback context"))
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: "ratchet_jobs", SkipJobKindValidation: true})
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected failure after append and job insert")
	mutation := eventstore.ChangeMutation{TenantID: tenant, ActorID: "actor", RequestID: request, ID: uuid.New(), InputDigest: ports.Digest{2}, Private: &record, Additional: func(pgx.Tx, eventstore.Receipt) error { return injected }}
	_, err = store.MutateChange(ctx, mutation, func(tx pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
		if _, err := jobs.InsertTx(ctx, tx, workflow.JobArgs{Tenant: tenant, Request: request, Revision: 1, Operation: "assess"}, &river.InsertOpts{Queue: "core"}); err != nil {
			return nil, err
		}
		return domain.Decide(current, domain.Command{Kind: "SUBMIT", At: now, Submission: &domain.Change{ID: request, TenantID: tenant, Requester: "actor", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "actor", Access: "role"}, PrivateReference: record.ID.String(), PrivateDigest: ports.Digest{1}}})
	})
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	events, err := store.LoadStream(ctx, tenant, "change:"+request)
	if err != nil || len(events) != 0 {
		t.Fatal("event escaped rollback", err)
	}
	backlog, err := store.OutboxBacklog(ctx, tenant)
	if err != nil || backlog.Pending != 0 {
		t.Fatal("outbox escaped rollback", err)
	}
	err = store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		for _, query := range []string{`SELECT count(*) FROM ratchet.change_projection WHERE tenant_id=$1`, `SELECT count(*) FROM ratchet.workflow_receipts WHERE tenant_id=$1`, `SELECT count(*) FROM ratchet.private_records WHERE tenant_id=$1`, `SELECT count(*) FROM ratchet_jobs.river_job WHERE args->>'tenant_id'=$1`} {
			var count int
			if err := tx.QueryRow(ctx, query, tenant).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Error("transactional data escaped rollback")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A retry after a rolled-back attempt can use the original key and starts at
	// the first stream/tenant position rather than inheriting a phantom job.
	mutation.Additional = nil
	result, err := store.MutateChange(context.Background(), mutation, func(_ pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
		return domain.Decide(current, domain.Command{Kind: "SUBMIT", At: now, Submission: &domain.Change{ID: request, TenantID: tenant, Requester: "actor", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "actor", Access: "role"}, PrivateReference: record.ID.String(), PrivateDigest: ports.Digest{1}}})
	})
	if err != nil || result.Revision != 1 {
		t.Fatal("rollback consumed command identity or version", err)
	}
}
