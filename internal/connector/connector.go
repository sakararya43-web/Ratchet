package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// Config holds runtime configuration for ratchet-connector.
type Config struct {
	TenantID     string
	ConnectorID  string
	CursorPath   string
	SyncInterval time.Duration
}

// Connector manages communication between an external IAM target and the RATCHET control plane.
type Connector struct {
	cfg         Config
	adapter     TargetAdapter
	publisher   Publisher
	cursorStore *CursorStore
}

// NewConnector creates a new Connector instance.
func NewConnector(cfg Config, adapter TargetAdapter, publisher Publisher) (*Connector, error) {
	if cfg.TenantID == "" {
		cfg.TenantID = "tenant-exchange-demo"
	}
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "connector-sim-01"
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 2 * time.Second
	}

	cs, err := NewCursorStore(cfg.CursorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cursor store: %w", err)
	}

	return &Connector{
		cfg:         cfg,
		adapter:     adapter,
		publisher:   publisher,
		cursorStore: cs,
	}, nil
}

// SyncSubject returns the agreed NATS ingest subject for this tenant.
func (c *Connector) SyncSubject() string {
	return fmt.Sprintf("ratchet.%s.ingest.sync", c.cfg.TenantID)
}

// SyncOnce performs a single synchronization step (snapshot or delta).
func (c *Connector) SyncOnce(ctx context.Context) error {
	lastRevision := c.cursorStore.Get()

	// 1. Initial sync: no saved cursor -> Fetch full snapshot
	if lastRevision == 0 {
		return c.performSnapshotSync(ctx)
	}

	// 2. Incremental sync: fetch delta since last revision
	delta, err := c.adapter.FetchDelta(ctx, lastRevision)
	if err != nil {
		return fmt.Errorf("delta fetch failed: %w", err)
	}

	// Gap or rollback detected: target revision moved backwards -> force full resync
	if delta.ToRevision < lastRevision {
		log.Printf("Target revision rollback detected (was %d, now %d). Forcing resync.", lastRevision, delta.ToRevision)
		return c.performSnapshotSync(ctx)
	}

	// No changes on target
	if delta.ToRevision == lastRevision {
		return nil
	}

	// Publish incremental delta
	payload, err := json.Marshal(map[string]any{
		"type":  "delta",
		"delta": delta,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal delta: %w", err)
	}

	if err := c.publisher.Publish(ctx, c.SyncSubject(), payload); err != nil {
		return fmt.Errorf("failed to publish delta: %w", err)
	}

	return c.cursorStore.Set(delta.ToRevision)
}

func (c *Connector) performSnapshotSync(ctx context.Context) error {
	snapshot, err := c.adapter.FetchSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot fetch failed: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"type":     "snapshot",
		"snapshot": snapshot,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	if err := c.publisher.Publish(ctx, c.SyncSubject(), payload); err != nil {
		return fmt.Errorf("failed to publish snapshot: %w", err)
	}

	return c.cursorStore.Set(snapshot.SourceRevision)
}

// Run starts the continuous background sync loop until context cancellation.
func (c *Connector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.SyncInterval)
	defer ticker.Stop()

	// Perform immediate first sync
	if err := c.SyncOnce(ctx); err != nil {
		log.Printf("Warning: initial sync failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.SyncOnce(ctx); err != nil {
				log.Printf("Sync error: %v", err)
			}
		}
	}
}

