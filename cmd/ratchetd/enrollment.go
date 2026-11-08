package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/authority"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/webassets"
)

func authorityClients(config consoleConfig) (map[string]*authority.Client, error) {
	clients := map[string]*authority.Client{}
	for _, tenant := range config.Tenants {
		if tenant.AuthorityURL == "" {
			continue
		}
		if tenant.Execution == nil {
			return nil, errors.New("Authority gateway signing identity required")
		}
		raw, err := os.ReadFile(tenant.Execution.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		clear(raw)
		if err != nil || len(key) != 64 || !slices.Equal(key, ed25519.NewKeyFromSeed(key[:32])) {
			return nil, errors.New("invalid Authority gateway signing key")
		}
		client, err := authority.NewClient(tenant.AuthorityURL, tenant.ID, key)
		clear(key)
		if err != nil {
			return nil, err
		}
		clients[tenant.ID] = client
	}
	return clients, nil
}

// Enrollment serving is an explicit operator-selected genesis ceremony, with
// no graph decision, command execution or policy bypass endpoint mounted.
func runEnrollment(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("enrollment-serve", flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("config", "", "private enrollment configuration")
	listen := flags.String("listen", "127.0.0.1:8444", "HTTPS setup address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("enrollment-serve requires --config")
	}
	var config consoleConfig
	if err := configFile(*path, &config); err != nil {
		return err
	}
	if len(config.AuthorityBootstrapActors) == 0 {
		return errors.New("explicit Authority bootstrap actors required")
	}
	clients, err := authorityClients(config)
	if err != nil || len(clients) != 1 {
		return errors.New("one explicit genesis Authority required")
	}
	key, err := key32(config.SessionKey)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		return err
	}
	if err = store.CheckRuntimeRole(ctx); err != nil {
		return err
	}
	if err = store.CheckMigrations(ctx); err != nil {
		return err
	}
	sessions, err := api.NewSessions(pool, config.Origin, key, 8*time.Hour)
	if err != nil {
		return err
	}
	credentials, err := approval.NewPersistentCredentialStore(pool)
	if err != nil {
		return err
	}
	defer credentials.Close()
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Scheme != "https" {
		return errors.New("HTTPS origin required")
	}
	verifier, err := approval.NewApprovalVerifier(credentials, origin.Hostname(), []string{config.Origin})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", sessions.Routes()))
	passkeys := approval.MakePasskeyHandlerFactory(credentials, origin.Hostname(), []string{config.Origin})(ports.PasskeyDeps{RPID: origin.Hostname(), RPOrigins: []string{config.Origin}, SessionAPI: sessions})
	mux.Handle("/api/passkeys/", sessions.Require(http.StripPrefix("/api/passkeys", passkeys)))
	mux.Handle("/api/authority/", sessions.Require(http.StripPrefix("/api/authority", api.AuthorityGateway(clients, credentials, verifier, func(_ context.Context, p api.Principal) error {
		if slices.Contains(config.AuthorityBootstrapActors, p.ActorID) {
			return nil
		}
		return authority.ErrRefused
	}))))
	mux.HandleFunc("GET /api/setup", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mode":"AUTHORITY_GENESIS"}`))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	health := api.Health{Database: store.CheckDatabase, Migrations: store.CheckMigrations, RuntimeRole: store.CheckRuntimeRole}.Handler()
	mux.Handle("/livez", health)
	spa, err := api.NewSPA(webassets.Files())
	if err != nil {
		return err
	}
	mux.Handle("/", spa)
	certificate, err := tls.LoadX509KeyPair(config.ServerCert, config.ServerKey)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: api.NewRequestLimits().Wrap(mux), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		return server.Shutdown(stop)
	}
}
