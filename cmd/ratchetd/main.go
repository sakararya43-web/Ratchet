package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ratchetd migrate|record-core-evidence|load-stream|verify-chain|serve")
	}
	if args[0] == "graph-serve" {
		return runGraph(ctx, args[1:], out)
	}
	if args[0] == "migrate" {
		if len(args) != 1 {
			return errors.New("migrate takes credentials from RATCHET_MIGRATION_DSN, no arguments")
		}
		dsn := os.Getenv("RATCHET_MIGRATION_DSN")
		if dsn == "" {
			return errors.New("RATCHET_MIGRATION_DSN is required")
		}
		if err := eventstore.Migrate(ctx, dsn); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
		_, err := fmt.Fprintln(out, "core schema migrated")
		return err
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(out)
	tenant := fs.String("tenant", "", "authenticated tenant context")
	stream := fs.String("stream", "", "event stream ID")
	commandID := fs.String("command-id", "", "stable UUID; reuse unchanged when retrying")
	actor := fs.String("actor-reference", "", "opaque operator UUID, no personal name")
	evidence := fs.String("evidence-sha256", "", "digest of the core evidence being recorded")
	expected := fs.Int64("expected-version", 0, "required current stream version")
	listen := fs.String("listen", "127.0.0.1:8080", "health HTTP listen address")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch args[0] {
	case "record-core-evidence", "load-stream", "verify-chain", "serve":
	default:
		return errors.New("unknown operation")
	}
	dsn := os.Getenv("RATCHET_DATABASE_DSN")
	if dsn == "" {
		return errors.New("RATCHET_DATABASE_DSN is required; use runtime credentials")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return errors.New("invalid runtime database configuration")
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		return err
	}
	if args[0] == "serve" {
		return serve(ctx, *listen, api.Health{Database: store.CheckDatabase, Migrations: store.CheckMigrations, RuntimeRole: store.CheckRuntimeRole}.Handler(), out)
	}
	if err := store.CheckRuntimeRole(ctx); err != nil {
		return fmt.Errorf("runtime role check: %w", err)
	}
	if err := store.CheckMigrations(ctx); err != nil {
		return fmt.Errorf("migration readiness: %w", err)
	}
	switch args[0] {
	case "record-core-evidence":
		id, err := uuid.Parse(*commandID)
		if err != nil {
			return errors.New("command-id must be a UUID")
		}
		actorID, err := uuid.Parse(*actor)
		if err != nil {
			return errors.New("actor-reference must be a UUID")
		}
		digest, err := ports.DigestFromHex(*evidence)
		if err != nil {
			return errors.New("evidence-sha256 must be a 64-character SHA-256 digest")
		}
		facts, err := json.Marshal(map[string]string{"evidence_digest": digest.String()})
		if err != nil {
			return err
		}
		receipt, err := store.Append(ctx, eventstore.Command{TenantID: *tenant, ID: id, StreamID: *stream, ExpectedVersion: *expected, ActorReference: actorID, Events: []eventstore.Event{{Type: "CoreEvidenceRecorded", Action: "RECORD_CORE_EVIDENCE", Facts: facts}}})
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(receipt)
	case "load-stream":
		events, err := store.LoadStream(ctx, *tenant, *stream)
		if err != nil {
			return err
		}
		for _, event := range events {
			if _, err := fmt.Fprintln(out, string(event.Entry.Canonical)); err != nil {
				return err
			}
		}
		return nil
	case "verify-chain":
		sequence, tip, err := store.VerifyTenant(ctx, *tenant)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"tenant_id": *tenant, "events_verified": sequence, "tip_digest": tip.String()})
	}
	return errors.New("unreachable operation")
}

func serve(ctx context.Context, address string, handler http.Handler, out io.Writer) error {
	return serveTransport(ctx, address, handler, out, nil)
}

func serveTransport(ctx context.Context, address string, handler http.Handler, out io.Writer, security *tls.Config) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	if security != nil {
		listener = tls.NewListener(listener, security)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	_, _ = fmt.Fprintln(out, "core health listener:", listener.Addr().String())
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
