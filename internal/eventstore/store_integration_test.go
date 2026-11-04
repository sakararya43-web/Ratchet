//go:build integration

package eventstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

var runtimeDSN, migrationDSN string

func TestMain(m *testing.M) {
	runtimeDSN, migrationDSN = os.Getenv("RATCHET_DATABASE_DSN"), os.Getenv("RATCHET_MIGRATION_DSN")
	if runtimeDSN == "" || migrationDSN == "" {
		fmt.Fprintln(os.Stderr, "integration tests require real PostgreSQL runtime and migration DSNs; see docs/ishaan/core-development.md")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := eventstore.Migrate(ctx, migrationDSN)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func setup(t *testing.T) (context.Context, *pgxpool.Pool, *eventstore.Store, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckRuntimeRole(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, store, "test_" + uuid.NewString()
}

func command(tenant, stream string) eventstore.Command {
	return eventstore.Command{TenantID: tenant, ID: uuid.New(), ActorReference: uuid.New(), StreamID: stream, Events: []eventstore.Event{{Type: "CoreEvidenceRecorded", Facts: json.RawMessage(`{"evidence_digest":"abc"}`)}}}
}

func tenantTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant string) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, "SELECT set_config('ratchet.tenant_id',$1,true)", tenant); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestAppendRestartLoadAndPrivacyRetention(t *testing.T) {
	ctx, pool, store, tenant := setup(t)
	cmd := command(tenant, "evidence:restart")
	key := bytes.Repeat([]byte{7}, 32)
	private, err := eventstore.SealPrivate(key, tenant, uuid.New(), "local-key-reference", []byte("confidential justification"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Events[0].Private = &private
	receipt, err := store.Append(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.FirstSequence != 1 || receipt.StreamVersion != 1 {
		t.Fatal(receipt)
	}
	pool.Close() // An entirely new DB pool/store must reconstruct from durable state.
	pool2, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool2.Close)
	restarted, err := eventstore.New(pool2, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	events, err := restarted.LoadStream(ctx, tenant, cmd.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || bytes.Contains(events[0].Entry.Canonical, []byte("confidential")) || bytes.Contains(events[0].Entry.Canonical, private.Ciphertext) {
		t.Fatal("private content leaked or event lost")
	}
	before := append([]byte(nil), events[0].Entry.Canonical...)
	if err := restarted.DeletePrivateRecord(ctx, tenant, private.ID); err != nil {
		t.Fatal(err)
	}
	events, err = restarted.LoadStream(ctx, tenant, cmd.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, events[0].Entry.Canonical) {
		t.Fatal("retention rewrote immutable evidence")
	}
	if n, _, err := restarted.VerifyTenant(ctx, tenant); err != nil || n != 1 {
		t.Fatalf("verify %d: %v", n, err)
	}
	tx := tenantTx(t, ctx, pool2, tenant)
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM ratchet.private_records").Scan(&count); err != nil || count != 0 {
		t.Fatalf("retained private record: %d %v", count, err)
	}
	var payload []byte
	if err := tx.QueryRow(ctx, "SELECT payload FROM ratchet.outbox").Scan(&payload); err != nil || !bytes.Equal(payload, before) {
		t.Fatalf("outbox not identical to immutable bytes: %v", err)
	}
}

func TestConcurrentStreamsCannotForkTenantChain(t *testing.T) {
	ctx, _, store, tenant := setup(t)
	const writers = 32
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Append(ctx, command(tenant, fmt.Sprintf("evidence:%d", i)))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n, _, err := store.VerifyTenant(ctx, tenant); err != nil || n != writers {
		t.Fatalf("chain %d %v", n, err)
	}
}

func TestConcurrentDuplicateCommandHasOneEffect(t *testing.T) {
	ctx, pool, store, tenant := setup(t)
	cmd := command(tenant, "evidence:dedup")
	var wg sync.WaitGroup
	receipts := make(chan eventstore.Receipt, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r, err := store.Append(ctx, cmd); receipts <- r; errs <- err }()
	}
	wg.Wait()
	close(receipts)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := 0
	for r := range receipts {
		if r.FirstSequence != 1 || r.LastSequence != 1 || r.StreamVersion != 1 {
			t.Fatal(r)
		}
		if !r.Duplicate {
			first++
		}
	}
	if first != 1 {
		t.Fatalf("effects=%d", first)
	}
	cmd.Events[0].Facts = json.RawMessage(`{"different_intent":true}`)
	if _, err := store.Append(ctx, cmd); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatalf("ID conflict: %v", err)
	}
	tx := tenantTx(t, ctx, pool, tenant)
	for _, table := range []string{"events", "command_receipts", "outbox"} {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ratchet."+table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count=%d: %v", table, count, err)
		}
	}
}

func TestExpectedVersionConflictUnderConcurrency(t *testing.T) {
	ctx, _, store, tenant := setup(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := store.Append(ctx, command(tenant, "same-stream")); errs <- err }()
	}
	wg.Wait()
	close(errs)
	accepted := 0
	for err := range errs {
		if err == nil {
			accepted++
		} else if !errors.Is(err, eventstore.ErrVersionConflict) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted=%d", accepted)
	}
}

func TestFailureAfterPartialWritesRollsBackEverything(t *testing.T) {
	ctx, pool, store, tenant := setup(t)
	admin, err := pgx.Connect(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	// Inject a real database error after the second event is inserted, so the
	// first event, first outbox row and private record already exist in the tx.
	ddl := fmt.Sprintf(`CREATE FUNCTION ratchet.test_reject_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.tenant_id='%s' AND NEW.sequence=2 THEN RAISE EXCEPTION 'injected outbox failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER test_reject_outbox BEFORE INSERT ON ratchet.outbox FOR EACH ROW EXECUTE FUNCTION ratchet.test_reject_outbox();`, tenant)
	if _, err := admin.Exec(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_reject_outbox ON ratchet.outbox; DROP FUNCTION IF EXISTS ratchet.test_reject_outbox()`)
	}()
	cmd := command(tenant, "evidence:rollback")
	private, err := eventstore.SealPrivate(bytes.Repeat([]byte{1}, 32), tenant, uuid.New(), "external-key-ref", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Events[0].Private = &private
	cmd.Events = append(cmd.Events, eventstore.Event{Type: "SecondEvidenceRecorded", Facts: json.RawMessage(`{"value":2}`)})
	if _, err := store.Append(ctx, cmd); err == nil {
		t.Fatal("injected transaction unexpectedly committed")
	}
	tx := tenantTx(t, ctx, pool, tenant)
	for _, table := range []string{"events", "outbox", "command_receipts", "tenant_heads", "private_records"} {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ratchet."+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial %s write: %d %v", table, count, err)
		}
	}
	_ = tx.Rollback(ctx)
	if _, err := admin.Exec(ctx, `DROP TRIGGER test_reject_outbox ON ratchet.outbox; DROP FUNCTION ratchet.test_reject_outbox()`); err != nil {
		t.Fatal(err)
	}
	if r, err := store.Append(ctx, cmd); err != nil || r.FirstSequence != 1 || r.LastSequence != 2 {
		t.Fatalf("retry after abort: %+v %v", r, err)
	}
	if n, _, err := store.VerifyTenant(ctx, tenant); err != nil || n != 2 {
		t.Fatalf("chain after abort: %d %v", n, err)
	}
}

func TestRuntimeCannotMutateHistoryOrCrossTenant(t *testing.T) {
	ctx, pool, store, tenant := setup(t)
	if _, err := store.Append(ctx, command(tenant, "evidence:permissions")); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE ratchet.events SET event_type='forged'`, `DELETE FROM ratchet.events`, `TRUNCATE ratchet.events`,
		`UPDATE ratchet.command_receipts SET stream_version=9`, `DELETE FROM ratchet.command_receipts`, `TRUNCATE ratchet.command_receipts`,
		`UPDATE ratchet.outbox SET payload='forged'`, `ALTER TABLE ratchet.events DISABLE TRIGGER ALL`,
	} {
		tx := tenantTx(t, ctx, pool, tenant)
		_, err := tx.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("expected privilege denial for %q: %v", stmt, err)
		}
		_ = tx.Rollback(ctx)
	}
	tx := tenantTx(t, ctx, pool, "another-tenant")
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM ratchet.events WHERE tenant_id=$1", tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cross tenant read %d %v", count, err)
	}
	_, err := tx.Exec(ctx, "INSERT INTO ratchet.tenant_heads(tenant_id) VALUES($1)", tenant+"_other")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("cross tenant write: %v", err)
	}
	_ = tx.Rollback(ctx)
	// A migration connection cannot accidentally be used as the runtime writer.
	ownerPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerPool.Close()
	ownerStore, err := eventstore.New(ownerPool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerStore.CheckRuntimeRole(ctx); err == nil {
		t.Fatal("accepted migration credentials as runtime")
	}
}
