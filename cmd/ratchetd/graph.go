package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

type graphConfig struct {
	GraphKey        string                `json:"graph_key_hex"`
	CursorKey       string                `json:"cursor_key_hex"`
	NATSURL         string                `json:"nats_url"`
	NATSCredentials string                `json:"nats_credentials"`
	ServerCert      string                `json:"server_cert"`
	ServerKey       string                `json:"server_key"`
	ClientCA        string                `json:"client_ca"`
	Readers         map[string]api.Reader `json:"readers"`
	Connectors      []struct {
		TenantID    string `json:"tenant_id"`
		ConnectorID string `json:"connector_id"`
		PublicKey   string `json:"public_key_hex"`
	} `json:"connectors"`
}

func runGraph(parent context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("graph-serve", flag.ContinueOnError)
	fs.SetOutput(out)
	configPath := fs.String("config", os.Getenv("RATCHET_GRAPH_CONFIG"), "private core transport configuration file")
	listen := fs.String("listen", "127.0.0.1:8443", "mutually authenticated graph API address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || fs.NArg() != 0 {
		return errors.New("graph-serve requires --config and no positional arguments")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.New("cannot open graph configuration")
	}
	defer func() { _ = file.Close() }()
	var config graphConfig
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return errors.New("invalid graph configuration")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("graph configuration must contain exactly one JSON object")
	}
	graphKey, err := hex.DecodeString(config.GraphKey)
	if err != nil || len(graphKey) != 32 {
		return errors.New("graph encryption key must be 32 bytes")
	}
	cursorKey, err := hex.DecodeString(config.CursorKey)
	if err != nil || len(cursorKey) != 32 {
		return errors.New("cursor key must be 32 bytes")
	}
	keyPair, err := tls.LoadX509KeyPair(config.ServerCert, config.ServerKey)
	if err != nil {
		return errors.New("invalid graph server certificate/key")
	}
	ca, err := os.ReadFile(config.ClientCA)
	if err != nil {
		return errors.New("cannot load graph client CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("invalid graph client CA")
	}
	security := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{keyPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	brokerURL, err := url.Parse(config.NATSURL)
	if err != nil || brokerURL.Hostname() == "" {
		return errors.New("invalid NATS URL")
	}
	ip := net.ParseIP(brokerURL.Hostname())
	local := brokerURL.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if !local && (brokerURL.Scheme != "tls" || config.NATSCredentials == "") {
		return errors.New("remote NATS requires TLS and credentials")
	}
	options := []nats.Option{}
	if config.NATSCredentials != "" {
		options = append(options, nats.UserCredentials(config.NATSCredentials))
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	dsn := os.Getenv("RATCHET_DATABASE_DSN")
	if dsn == "" {
		return errors.New("RATCHET_DATABASE_DSN is required")
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
	if err := store.CheckRuntimeRole(ctx); err != nil {
		return err
	}
	if err := store.CheckMigrations(ctx); err != nil {
		return err
	}
	registry, err := graph.NewRegistry(500 * time.Millisecond)
	if err != nil {
		return err
	}
	pins := []bus.ConnectorKey{}
	tenants := map[string]bool{}
	for _, c := range config.Connectors {
		key, err := hex.DecodeString(c.PublicKey)
		if err != nil {
			return errors.New("invalid connector public key")
		}
		pins = append(pins, bus.ConnectorKey{TenantID: c.TenantID, ConnectorID: c.ConnectorID, PublicKey: ed25519.PublicKey(key)})
		tenants[c.TenantID] = true
	}
	for _, reader := range config.Readers {
		if !tenants[reader.TenantID] {
			return errors.New("reader tenant has no configured connector")
		}
	}
	ingestor, err := bus.NewIngestor(store, registry, canon.New(), graphKey, pins)
	if err != nil {
		return err
	}
	handler, err := api.NewGraphHandler(registry, cursorKey, config.Readers)
	if err != nil {
		return err
	}
	broker, err := bus.Connect(config.NATSURL, options...)
	if err != nil {
		return err
	}
	defer broker.Close()
	for tenant := range tenants {
		if err := broker.EnsureTenant(ctx, tenant); err != nil {
			return err
		}
		if err := ingestor.Refresh(ctx, tenant); err != nil && !errors.Is(err, graph.ErrUnavailable) && !errors.Is(err, eventstore.ErrResyncRequired) {
			return err
		}
	}
	logger := slog.New(slog.NewTextHandler(out, nil))
	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", handler))
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "verified client certificate required", http.StatusUnauthorized)
			return
		}
		reader, ok := config.Readers[r.TLS.PeerCertificates[0].Subject.CommonName]
		if !ok {
			http.Error(w, "reader not authorized", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, tenant := range []string{reader.TenantID} {
			backlog, err := store.OutboxBacklog(r.Context(), tenant)
			if err != nil {
				http.Error(w, "backlog unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = fmt.Fprintf(w, "ratchet_outbox_pending{tenant=%q} %d\nratchet_outbox_oldest_seconds{tenant=%q} %g\nratchet_outbox_attempts{tenant=%q} %d\n", tenant, backlog.Pending, tenant, backlog.OldestAge.Seconds(), tenant, backlog.Attempts)
		}
	})
	mux.Handle("/", api.Health{Database: store.CheckDatabase, Migrations: store.CheckMigrations, RuntimeRole: store.CheckRuntimeRole, Graph: func(ctx context.Context) error {
		for tenant := range tenants {
			if _, err := registry.Get(ctx, tenant, 0); err != nil {
				return err
			}
		}
		return nil
	}}.Handler())
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	failures := make(chan error, 2*len(tenants)+2)
	start := func(work func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := work(); err != nil && ctx.Err() == nil {
				select {
				case failures <- err:
				case <-ctx.Done():
				}
			}
		}()
	}
	for tenant := range tenants {
		start(func() error { return broker.Relay(ctx, store, tenant, logger) })
		start(func() error {
			return broker.Consume(ctx, tenant, func(ctx context.Context, payload []byte) error { return ingestor.Handle(ctx, tenant, payload) }, logger)
		})
	}
	start(func() error {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				for tenant := range tenants {
					if err := ingestor.Refresh(ctx, tenant); err != nil && !errors.Is(err, graph.ErrUnavailable) && !errors.Is(err, eventstore.ErrResyncRequired) {
						logger.Warn("graph refresh unavailable", "tenant", tenant)
					}
				}
			}
		}
	})
	start(func() error { return serveTransport(ctx, *listen, mux, out, security) })
	select {
	case <-parent.Done():
		return nil
	case err := <-failures:
		return fmt.Errorf("graph service stopped: %w", err)
	}
}
