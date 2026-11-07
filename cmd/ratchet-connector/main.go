package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

// LogPublisher logs published events to stdout when NATS is in local standalone mode.
type LogPublisher struct{}

func (lp *LogPublisher) Publish(ctx context.Context, subject string, data []byte) error {
	log.Printf("[NATS STANDALONE OUT] Subject: %s | Bytes: %d", subject, len(data))
	return nil
}

// JetStreamPublisher publishes real JetStream messages with durable message IDs.
type JetStreamPublisher struct {
	broker *bus.Broker
}

func (p *JetStreamPublisher) Publish(ctx context.Context, subject string, data []byte) error {
	msgID := uuid.NewString()
	return p.broker.Publish(ctx, subject, msgID, data)
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid hexadecimal private key in %s (expected %d bytes)", path, ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func main() {
	defaultTargetURL := os.Getenv("SIM_BASE_URL")
	if defaultTargetURL == "" {
		defaultTargetURL = "http://localhost:8085"
	}

	defaultToken := os.Getenv("SIM_BROKER_TOKEN")
	if defaultToken == "" {
		defaultToken = "sim-broker-secret"
	}

	defaultNATSURL := os.Getenv("RATCHET_NATS_URL")
	if defaultNATSURL == "" {
		defaultNATSURL = os.Getenv("NATS_URL")
	}
	if defaultNATSURL == "" {
		defaultNATSURL = "nats://127.0.0.1:54222"
	}

	tenantID := flag.String("tenant", "tenant-exchange-demo", "Target tenant ID")
	connectorID := flag.String("id", "connector-sim-01", "Connector identifier")
	targetURL := flag.String("target", defaultTargetURL, "Target simulator API URL")
	brokerToken := flag.String("token", defaultToken, "Target broker authorization token")
	natsURL := flag.String("nats", defaultNATSURL, "NATS JetStream server URL (set to empty to run standalone)")
	signingKeyPath := flag.String("key", os.Getenv("CONNECTOR_SIGNING_KEY"), "Path to ed25519 signing key file")
	cursorPath := flag.String("cursor", "connector_cursor.json", "Path to local cursor persistence file")
	priorityPath := flag.String("priority-state", "priority_containment.json", "Path to priority containment state file")
	syncInterval := flag.Duration("interval", 3*time.Second, "Sync polling interval")
	flag.Parse()

	adapter := sim.NewAdapter(*targetURL, *brokerToken, *tenantID, *connectorID)
	pce, err := connector.NewPriorityContainmentEngine(adapter, *priorityPath)
	if err != nil {
		log.Printf("Warning: priority containment engine init: %v", err)
	}

	var signingKey ed25519.PrivateKey
	if *signingKeyPath != "" {
		key, err := loadSigningKey(*signingKeyPath)
		if err != nil {
			log.Fatalf("Failed to load signing key: %v", err)
		}
		signingKey = key
	} else {
		// Generate ephemeral signing key for runtime message signing
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		signingKey = key
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var publisher connector.Publisher = &LogPublisher{}
	var broker *bus.Broker

	if *natsURL != "" {
		b, err := bus.Connect(*natsURL)
		if err != nil {
			log.Printf("Warning: NATS connection to %s failed (%v); falling back to standalone logging", *natsURL, err)
		} else {
			broker = b
			defer broker.Close()

			if err := broker.EnsureTenant(ctx, *tenantID); err != nil {
				log.Printf("Warning: EnsureTenant failed: %v", err)
			}
			if err := broker.EnsureExecution(ctx, *tenantID, *connectorID); err != nil {
				log.Printf("Warning: EnsureExecution failed: %v", err)
			}
			publisher = &JetStreamPublisher{broker: broker}
			log.Printf("Connected to NATS JetStream at %s", *natsURL)

			// Start standard command execution consumer
			go func() {
				err := broker.ConsumeExecution(ctx, *tenantID, *connectorID, func(ctx context.Context, raw []byte) error {
					var cmd workflow.PreparedCommand
					decoder := json.NewDecoder(bytes.NewReader(raw))
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&cmd); err != nil {
						if err := json.Unmarshal(raw, &cmd); err != nil {
							return eventstore.ErrInvalid
						}
					}
					if cmd.Tenant != *tenantID || cmd.Connector != *connectorID {
						return eventstore.ErrInvalid
					}
					if !cmd.Deadline.IsZero() && time.Now().After(cmd.Deadline) {
						logger.Warn("execution command expired", "command_id", cmd.CommandID, "deadline", cmd.Deadline)
						return nil
					}

					action := "ASSIGN_ROLE"
					targetIdentity := ""
					resourceOrRole := ""
					isReduction := false

					if cmd.Envelope != nil {
						switch cmd.Envelope.Intent.Kind {
						case "ROLE_ASSIGN":
							action = "ASSIGN_ROLE"
						case "ROLE_REVOKE":
							action = "REVOKE_ROLE"
							isReduction = true
						case "RESTRICT_ACCOUNT":
							action = "RESTRICT_ACCOUNT"
							isReduction = true
						case "TERMINATE_SESSION":
							action = "TERMINATE_SESSION"
							isReduction = true
						}
						targetIdentity = cmd.Envelope.Intent.Target
						resourceOrRole = cmd.Envelope.Intent.Access
					}

					execCmd := &connector.ExecCommand{
						ExpectedTargetRevision: cmd.ExpectedRevision,
						CommandID:              cmd.CommandID,
						TenantID:               cmd.Tenant,
						RequestID:              cmd.RequestID,
						Action:                 action,
						TargetIdentity:         targetIdentity,
						ResourceOrRole:         resourceOrRole,
						IsReduction:            isReduction,
					}

					execRes, _ := adapter.Execute(ctx, execCmd)
					observed, verifyErr := adapter.Verify(ctx, execCmd)

					var observedRoles []string
					var observedRev int64
					if observed != nil {
						observedRoles = observed.CurrentRoles
						observedRev = observed.ObservedRevision
					}

					nowUTC := time.Now().UTC()
					appliedAt := nowUTC
					if execRes != nil && execRes.AppliedAt != "" {
						if t, err := time.Parse(time.RFC3339Nano, execRes.AppliedAt); err == nil {
							appliedAt = t
						}
					}

					obsDigest, _ := canon.New().Digest(struct {
						Tenant   string   `json:"Tenant"`
						Target   string   `json:"Target"`
						Roles    []string `json:"Roles"`
						Revision int64    `json:"Revision"`
						At       string   `json:"At"`
					}{
						Tenant:   cmd.Tenant,
						Target:   targetIdentity,
						Roles:    observedRoles,
						Revision: observedRev,
						At:       nowUTC.Format(time.RFC3339Nano),
					})

					result := workflow.ExecutionResult{
						SchemaVersion:     1,
						Tenant:            cmd.Tenant,
						Connector:         cmd.Connector,
						MessageID:         uuid.NewString(),
						CommandID:         cmd.CommandID,
						RequestID:         cmd.RequestID,
						CorrelationID:     cmd.CorrelationID,
						EnvelopeDigest:    cmd.EnvelopeDigest,
						Success:           execRes != nil && execRes.Success,
						ReadBackVerified:  verifyErr == nil,
						ObservedTenant:    cmd.Tenant,
						ObservedTarget:    targetIdentity,
						ObservedRoles:     observedRoles,
						ObservedRevision:  observedRev,
						ObservedAt:        nowUTC,
						AppliedAt:         appliedAt,
						ObservationDigest: obsDigest,
					}

					if len(signingKey) == ed25519.PrivateKeySize {
						resCopy := result
						resCopy.Signature = nil
						digest, err := canon.New().Digest(struct {
							Domain string `json:"domain"`
							Body   any    `json:"body"`
						}{"RATCHET_EXEC_RESULT_V1", resCopy})
						if err == nil {
							result.Signature = ed25519.Sign(signingKey, digest[:])
						}
					}

					resultBytes, err := json.Marshal(result)
					if err != nil {
						return err
					}

					return broker.Publish(ctx, "ratchet."+cmd.Tenant+".exec.results", result.MessageID, resultBytes)
				}, logger)
				if err != nil && err != context.Canceled {
					logger.Error("execution consumer stopped", "error", err)
				}
			}()
		}
	}

	conn, err := connector.NewConnector(connector.Config{
		TenantID:     *tenantID,
		ConnectorID:  *connectorID,
		CursorPath:   *cursorPath,
		SyncInterval: *syncInterval,
		SigningKey:   signingKey,
	}, adapter, publisher)
	if err != nil {
		log.Fatalf("Failed to initialize connector: %v", err)
	}

	// Keep pce referenced to avoid unused variable warning
	_ = pce

	fmt.Printf("Starting ratchet-connector [%s] for tenant [%s] against target [%s]\n",
		*connectorID, *tenantID, *targetURL)

	if err := conn.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Connector terminated with error: %v", err)
	}
}
