package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

// JetStreamPublisher publishes real JetStream messages with durable message IDs.
type JetStreamPublisher struct {
	broker *bus.Broker
}

func (p *JetStreamPublisher) Publish(ctx context.Context, subject string, data []byte) error {
	msgID := uuid.NewSHA1(uuid.NameSpaceURL, append([]byte(subject+":"), data...)).String()
	return p.broker.Publish(ctx, subject, msgID, data)
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("persistent connector signing key file required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid hexadecimal private key in %s (expected %d bytes)", path, ed25519.PrivateKeySize)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(decoded[:32]), decoded) {
		return nil, fmt.Errorf("inconsistent Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func main() {
	targetDefault := os.Getenv("SIM_BASE_URL")
	if targetDefault == "" {
		targetDefault = "http://localhost:8085"
	}
	natsDefault := os.Getenv("RATCHET_NATS_URL")
	if natsDefault == "" {
		natsDefault = os.Getenv("NATS_URL")
	}
	if natsDefault == "" {
		natsDefault = "nats://127.0.0.1:54222"
	}
	tenantID := flag.String("tenant", "tenant-exchange-demo", "Target tenant ID")
	connectorID := flag.String("id", "connector-sim-01", "Connector identifier")
	targetURL := flag.String("target", targetDefault, "Target simulator API URL")
	brokerToken := flag.String("token", os.Getenv("SIM_BROKER_TOKEN"), "Target broker credential; prefer environment")
	natsURL := flag.String("nats", natsDefault, "NATS JetStream server URL")
	credentials := flag.String("credentials", os.Getenv("RATCHET_NATS_CREDENTIALS"), "NATS credential file; required for remote TLS")
	syncOnly := flag.Bool("sync-only", false, "publish signed snapshots without consuming commands")
	signingKeyPath := flag.String("key", os.Getenv("CONNECTOR_SIGNING_KEY"), "Persistent connector signing key file")
	coreKeyPath := flag.String("core-key", os.Getenv("CORE_PUBLIC_KEY"), "Pinned core Ed25519 public key file")
	stateDirectory := flag.String("state", os.Getenv("CONNECTOR_EXECUTION_STATE"), "Persistent private command/result journal directory")
	cursorPath := flag.String("cursor", "connector_cursor.json", "Persistent source cursor file")
	syncInterval := flag.Duration("interval", 3*time.Second, "Complete snapshot polling interval")
	healthAddress := flag.String("health-listen", "", "Optional loopback readiness listener")
	flag.Parse()
	if *brokerToken == "" || *syncInterval < 100*time.Millisecond {
		log.Fatal("explicit broker credential and polling interval >=100ms required")
	}
	if err := validateTransport(*natsURL, "tls", *credentials != ""); err != nil {
		log.Fatal(err)
	}
	if err := validateTransport(*targetURL, "https", true); err != nil {
		log.Fatal(err)
	}
	signingKey, err := loadSigningKey(*signingKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var options []nats.Option
	if *credentials != "" {
		options = append(options, nats.UserCredentials(*credentials))
	}
	broker, err := bus.Connect(*natsURL, options...)
	if err != nil {
		log.Fatal("NATS unavailable; cursor will not advance")
	}
	defer broker.Close()
	if err = broker.EnsureTenant(ctx, *tenantID); err != nil {
		log.Fatal(err)
	}
	adapter := sim.NewAdapter(*targetURL, *brokerToken, *tenantID, *connectorID)
	consumerError := make(chan error, 1)
	if !*syncOnly {
		raw, err := os.ReadFile(*coreKeyPath)
		if err != nil {
			log.Fatal("pinned core public key required")
		}
		public, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(public) != ed25519.PublicKeySize {
			log.Fatal("invalid pinned core public key")
		}
		executor, err := sim.NewExecutor(*tenantID, *connectorID, *stateDirectory, ed25519.PublicKey(public), signingKey, adapter, broker.Publish)
		if err != nil {
			log.Fatal(err)
		}
		if err = broker.EnsureExecution(ctx, *tenantID, *connectorID); err != nil {
			log.Fatal(err)
		}
		if err = broker.EnsureContainment(ctx, *tenantID, *connectorID); err != nil {
			log.Fatal(err)
		}
		go func() {
			err := broker.ConsumeExecution(ctx, *tenantID, *connectorID, executor.Handle, logger)
			if err != nil && ctx.Err() == nil {
				consumerError <- err
				cancel()
			}
		}()
		go func() {
			err := broker.ConsumeContainment(ctx, *tenantID, *connectorID, executor.Handle, logger)
			if err != nil && ctx.Err() == nil {
				consumerError <- err
				cancel()
			}
		}()
	}
	conn, err := connector.NewConnector(connector.Config{TenantID: *tenantID, ConnectorID: *connectorID, CursorPath: *cursorPath, SyncInterval: *syncInterval, SigningKey: signingKey, SnapshotOnly: true}, adapter, &JetStreamPublisher{broker: broker})
	if err != nil {
		log.Fatal(err)
	}

	if *healthAddress != "" {
		host, _, err := net.SplitHostPort(*healthAddress)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			log.Fatal("health listener must bind a loopback IP")
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			probe, done := context.WithTimeout(r.Context(), 2*time.Second)
			defer done()
			if conn.Ready(time.Now()) != nil || broker.Ready(probe) != nil {
				http.Error(w, "not ready", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		server := &http.Server{Addr: *healthAddress, Handler: mux, ReadHeaderTimeout: 2 * time.Second}
		defer func() {
			shutdown, done := context.WithTimeout(context.Background(), 2*time.Second)
			defer done()
			_ = server.Shutdown(shutdown)
		}()
		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				consumerError <- err
				cancel()
			}
		}()
	}
	logger.Info("connector running", "tenant", *tenantID, "connector", *connectorID, "sync_only", *syncOnly)
	if err = conn.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
	select {
	case err := <-consumerError:
		log.Fatal("execution consumer stopped: ", err)
	default:
	}
}

func validateTransport(address, secureScheme string, authenticated bool) error {
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("explicit valid transport URL without inline credentials required")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	allowedPlain := "http"
	if secureScheme == "tls" {
		allowedPlain = "nats"
	}
	if u.Scheme != secureScheme && (!local || u.Scheme != allowedPlain) {
		return fmt.Errorf("remote transport requires %s", secureScheme)
	}
	if !local && !authenticated {
		return fmt.Errorf("remote transport credentials required")
	}
	return nil
}
