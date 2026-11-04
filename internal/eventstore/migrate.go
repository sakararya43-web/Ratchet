package eventstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"io/fs"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const SchemaVersion int64 = 7

// Migrate is an explicit administrative operation. The serving process must use
// a separate runtime DSN and never keeps the migration credentials in its pool.
func Migrate(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	var role string
	var privileged bool
	if err := db.QueryRowContext(ctx, `SELECT current_user, rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&role, &privileged); err != nil {
		return err
	}
	if role != "ratchet_migrator" || privileged {
		return errors.New("migrations require the non-superuser ratchet_migrator role")
	}
	lock, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if _, err := lock.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext(current_database()),319735)`); err != nil {
		return err
	}
	defer func() {
		_, _ = lock.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext(current_database()),319735)`)
	}()
	files, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		return err
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate core store: %w", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: "ratchet_jobs"})
	if err != nil {
		return err
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("migrate durable jobs: %w", err)
	}
	if _, err := db.ExecContext(ctx, `REVOKE ALL ON ALL TABLES IN SCHEMA ratchet_jobs FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA ratchet_jobs TO ratchet_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA ratchet_jobs TO ratchet_runtime`); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `GRANT SELECT ON public.goose_db_version TO ratchet_runtime`)
	return err
}

func (s *Store) CheckDatabase(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) CheckMigrations(ctx context.Context) error {
	var version int64
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(max(version_id),0) FROM public.goose_db_version WHERE is_applied`).Scan(&version); err != nil {
		return err
	}
	if version != SchemaVersion {
		return fmt.Errorf("schema version %d, required %d", version, SchemaVersion)
	}
	return nil
}

// CheckRuntimeRole refuses elevated database credentials, even if the DSN name
// was misleading. Runtime does not own tables or inherit a migration role.
func (s *Store) CheckRuntimeRole(ctx context.Context) error {
	var unsafe bool
	err := s.pool.QueryRow(ctx, `
SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
 OR pg_has_role(current_user,'ratchet_migrator','MEMBER')
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='ratchet' AND c.relkind='r' AND pg_has_role(current_user,c.relowner,'MEMBER'))
 OR has_table_privilege(current_user,'ratchet.events','UPDATE,DELETE,TRUNCATE')
 OR has_table_privilege(current_user,'ratchet.command_receipts','UPDATE,DELETE,TRUNCATE')
 OR has_schema_privilege(current_user,'ratchet','CREATE')
FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe)
	if err != nil {
		return err
	}
	if unsafe {
		return errors.New("runtime database credentials are overprivileged")
	}
	return nil
}
