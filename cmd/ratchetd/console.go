package main

import (
	"context"
	"crypto/tls"
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
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

type consoleConfig struct {
	Origin                  string           `json:"origin"`
	SessionKey              string           `json:"session_key_hex"`
	GraphKey                string           `json:"graph_key_hex"`
	CursorKey               string           `json:"cursor_key_hex"`
	ServerCert              string           `json:"server_cert"`
	ServerKey               string           `json:"server_key"`
	NATSURL                 string           `json:"nats_url"`
	NATSCredentials         string           `json:"nats_credentials"`
	ContainmentCosts        map[string]int64 `json:"containment_costs"`
	ApprovalLifetimeSeconds int64            `json:"approval_lifetime_seconds"`
	Tenants                 []struct {
		ID                     string `json:"tenant_id"`
		AuthorityFile          string `json:"authority_file"`
		GenesisDigest          string `json:"genesis_digest"`
		BundleFile             string `json:"bundle_file"`
		CheckpointAuthorityURL string `json:"checkpoint_authority_url"`
	} `json:"tenants"`
}

func configFile(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.New("configuration unavailable")
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("one configuration object required")
	}
	return nil
}
func key32(raw string) ([]byte, error) {
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("32-byte key required")
	}
	return key, nil
}
func runConsole(parent context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("console-serve", flag.ContinueOnError)
	fs.SetOutput(out)
	path := fs.String("config", os.Getenv("RATCHET_CONSOLE_CONFIG"), "private console configuration")
	listen := fs.String("listen", "127.0.0.1:8444", "HTTPS console address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("console-serve requires --config")
	}
	var config consoleConfig
	if err := configFile(*path, &config); err != nil {
		return err
	}
	sessionKey, err := key32(config.SessionKey)
	if err != nil {
		return err
	}
	graphKey, err := key32(config.GraphKey)
	if err != nil {
		return err
	}
	cursorKey, err := key32(config.CursorKey)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(config.ServerCert, config.ServerKey)
	if err != nil {
		return errors.New("invalid console TLS configuration")
	}
	pool, err := pgxpool.New(parent, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		return errors.New("invalid runtime database configuration")
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		return err
	}
	if err := store.CheckRuntimeRole(parent); err != nil {
		return err
	}
	if err := store.CheckMigrations(parent); err != nil {
		return err
	}
	sessions, err := api.NewSessions(pool, config.Origin, sessionKey, 8*time.Hour)
	if err != nil {
		return err
	}
	engine := policy.NewEngine()
	registry, err := graph.NewRegistry(500 * time.Millisecond)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(out, nil))
	tenants := map[string]bool{}
	policySources := []policy.FileSource{}
	for _, tenant := range config.Tenants {
		if tenants[tenant.ID] || tenant.ID == "" || tenant.AuthorityFile == "" {
			return errors.New("invalid tenant policy configuration")
		}
		tenants[tenant.ID] = true
		var authority *trust.Store
		if _, err := os.Stat(tenant.AuthorityFile); err == nil {
			authority, err = trust.NewStore(tenant.AuthorityFile)
			if err != nil {
				logger.Warn("authority candidate invalid; restoring verified durable history", "tenant", tenant.ID)
				authority = nil
			}
		}
		root, err := ports.DigestFromHex(tenant.GenesisDigest)
		if err != nil || root.IsZero() {
			return errors.New("pinned genesis digest required")
		}
		manager := policy.Manager{Store: store, Engine: engine, Authority: authority, Root: root, Tenant: tenant.ID}
		if err := manager.Restore(parent); err != nil && !errors.Is(err, policy.ErrUnavailable) {
			return err
		}
		source := policy.FileSource{Manager: manager, AuthorityFile: tenant.AuthorityFile, BundleFile: tenant.BundleFile}
		policySources = append(policySources, source)
		if err := source.Refresh(parent); err != nil {
			logger.Warn("policy source unavailable or refused; enforcing last verified registry", "tenant", tenant.ID)
		}
	}
	if len(tenants) == 0 {
		return errors.New("at least one tenant required")
	}
	for tenant := range tenants {
		snapshot, err := store.CurrentGraph(parent, tenant, graphKey)
		if errors.Is(err, graph.ErrUnavailable) || errors.Is(err, eventstore.ErrResyncRequired) {
			continue
		}
		if err != nil {
			return errors.New("configured tenant graph cannot be recovered with this key")
		}
		if err := registry.Publish(tenant, snapshot); err != nil {
			return err
		}
	}
	// The actual peer factory fails the documented session/origin conformance.
	// No flag can enable it. Passkey routes remain absent until the peer fixes it.
	tenantIDs := []string{}
	for tenant := range tenants {
		tenantIDs = append(tenantIDs, tenant)
	}
	if config.ApprovalLifetimeSeconds < 0 || config.ApprovalLifetimeSeconds > 86400 {
		return errors.New("approval_lifetime_seconds must be between 1 and 86400, or zero for 900")
	}
	service, err := workflow.NewConfigured(pool, store, engine, graphKey, nil, tenantIDs, workflow.Config{ApprovalLifetime: time.Duration(config.ApprovalLifetimeSeconds) * time.Second})
	if err != nil {
		return err
	}
	brokerURL, err := url.Parse(config.NATSURL)
	if err != nil || brokerURL.Hostname() == "" {
		return errors.New("NATS URL required")
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
	broker, err := bus.Connect(config.NATSURL, options...)
	if err != nil {
		return err
	}
	defer broker.Close()
	for tenant := range tenants {
		if err := broker.EnsureTenant(parent, tenant); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if err := service.Start(ctx); err != nil {
		return err
	}
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = service.Stop(stopCtx)
	}()
	changes, err := api.NewChangeHandler(service, cursorKey)
	if err != nil {
		return err
	}
	graphs, err := api.NewSessionGraphHandler(registry, cursorKey, func(ctx context.Context, p api.Principal, operation string) error {
		return service.Authorize(ctx, workflow.Actor{TenantID: p.TenantID, ID: p.ActorID}, operation)
	})
	if err != nil {
		return err
	}
	apiMux := http.NewServeMux()
	apiMux.Handle("/ratchet.v1.ChangeService/", changes)
	apiMux.Handle("/ratchet.v1.OverviewService/", changes)
	apiMux.Handle("/ratchet.v1.GraphService/", graphs)
	apiMux.Handle("/ratchet.v1.ImpactService/", graphs)
	checkpointAuthorities := map[string]*workflow.CheckpointAuthority{}
	for _, tenant := range config.Tenants {
		if tenant.CheckpointAuthorityURL == "" {
			continue
		}
		authority, err := workflow.NewCheckpointAuthority(tenant.CheckpointAuthorityURL, nil)
		if err != nil {
			return err
		}
		checkpointAuthorities[tenant.ID] = authority
	}
	audit, err := api.NewAuditHandler(service, cursorKey, checkpointAuthorities)
	if err != nil {
		return err
	}
	apiMux.Handle("/ratchet.v1.AuditService/", audit)
	incidents, err := api.NewIncidentHandler(service, cursorKey)
	if err != nil {
		return err
	}
	apiMux.Handle("/ratchet.v1.IncidentService/", incidents)
	if len(config.ContainmentCosts) > 0 {
		containment, err := api.NewContainmentHandler(service, config.ContainmentCosts)
		if err != nil {
			return err
		}
		apiMux.Handle("/ratchet.v1.ContainmentService/", containment)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", sessions.Routes()))
	mux.Handle("/api/", http.StripPrefix("/api", sessions.Require(apiMux)))
	mux.Handle("/", api.Health{Database: store.CheckDatabase, Migrations: store.CheckMigrations, RuntimeRole: store.CheckRuntimeRole, Graph: func(ctx context.Context) error {
		for tenant := range tenants {
			if _, err := registry.Get(ctx, tenant, 0); err != nil {
				return err
			}
		}
		return nil
	}, PolicyBundle: service.PolicyReady, Workflow: service.Ready}.Handler())
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	failures := make(chan error, 2*len(tenants)+2)
	start := func(work func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := work(); err != nil && ctx.Err() == nil {
				failures <- err
			}
		}()
	}
	for tenant := range tenants {
		start(func() error { return broker.Relay(ctx, store, tenant, logger) })
		start(func() error {
			return broker.ConsumeResults(ctx, tenant, func(ctx context.Context, raw []byte) error {
				err := service.RecordExecutionResult(ctx, tenant, raw)
				if errors.Is(err, workflow.ErrPermission) || errors.Is(err, domain.ErrInvalid) {
					return eventstore.ErrInvalid
				}
				return err
			}, logger)
		})
	}
	start(func() error {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
			for _, source := range policySources {
				if err := source.Refresh(ctx); err != nil && ctx.Err() == nil {
					logger.Warn("policy source unavailable or refused; enforcing last verified registry", "tenant", source.Manager.Tenant)
				}
			}
		}
	})
	start(func() error {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			for tenant := range tenants {
				snapshot, err := store.CurrentGraph(ctx, tenant, graphKey)
				if err != nil {
					registry.Invalidate(tenant)
				} else {
					_ = registry.Publish(tenant, snapshot)
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	})
	start(func() error {
		return serveTransport(ctx, *listen, mux, out, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	})
	select {
	case <-parent.Done():
		return nil
	case err := <-failures:
		return fmt.Errorf("console stopped: %w", err)
	}
}
func provisionUsers(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("provision-users", flag.ContinueOnError)
	fs.SetOutput(out)
	path := fs.String("config", "", "private password provisioning file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("provision-users requires --config")
	}
	var users []struct {
		Tenant   string `json:"tenant_id"`
		Actor    string `json:"actor_id"`
		Password string `json:"password"`
	}
	if err := configFile(*path, &users); err != nil {
		return err
	}
	if len(users) == 0 || len(users) > 100 {
		return errors.New("1-100 users required")
	}
	pool, err := pgxpool.New(ctx, os.Getenv("RATCHET_MIGRATION_DSN"))
	if err != nil {
		return errors.New("migration credentials required")
	}
	defer pool.Close()
	var role string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil || role != "ratchet_migrator" {
		return errors.New("user provisioning requires migration role")
	}
	for _, user := range users {
		if err := api.ProvisionUser(ctx, pool, api.Principal{TenantID: user.Tenant, ActorID: user.Actor}, user.Password); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, "console accounts provisioned; prior sessions revoked")
	return err
}
