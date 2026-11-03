package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

// LogPublisher logs published events to stdout when NATS is in local standalone mode.
type LogPublisher struct{}

func (lp *LogPublisher) Publish(ctx context.Context, subject string, data []byte) error {
	log.Printf("[NATS OUT] Subject: %s | Bytes: %d", subject, len(data))
	return nil
}

func main() {
	tenantID := flag.String("tenant", "tenant-exchange-demo", "Target tenant ID")
	connectorID := flag.String("id", "connector-sim-01", "Connector identifier")
	targetURL := flag.String("target", "http://localhost:8085", "Target simulator API URL")
	brokerToken := flag.String("token", os.Getenv("SIM_BROKER_TOKEN"), "Target broker authorization token")
	cursorPath := flag.String("cursor", "connector_cursor.json", "Path to local cursor persistence file")
	syncInterval := flag.Duration("interval", 3*time.Second, "Sync polling interval")
	flag.Parse()

	if *brokerToken == "" {
		*brokerToken = "sim-broker-secret"
	}

	adapter := sim.NewAdapter(*targetURL, *brokerToken, *tenantID, *connectorID)
	publisher := &LogPublisher{}

	conn, err := connector.NewConnector(connector.Config{
		TenantID:     *tenantID,
		ConnectorID:  *connectorID,
		CursorPath:   *cursorPath,
		SyncInterval: *syncInterval,
	}, adapter, publisher)
	if err != nil {
		log.Fatalf("Failed to initialize connector: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("Starting ratchet-connector [%s] for tenant [%s] against target [%s]\n",
		*connectorID, *tenantID, *targetURL)

	if err := conn.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Connector terminated with error: %v", err)
	}
}

