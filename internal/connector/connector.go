package connector

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Config holds runtime configuration for ratchet-connector.
type Config struct {
	TenantID     string
	ConnectorID  string
	CursorPath   string
	SyncInterval time.Duration
	SigningKey   ed25519.PrivateKey
	SnapshotOnly bool // Complete source cuts; used by the small simulator prototype.
}

// Connector manages communication between an external IAM target and the RATCHET control plane.
type Connector struct {
	cfg         Config
	adapter     TargetAdapter
	publisher   Publisher
	cursorStore *CursorStore
	lastSync    atomic.Int64
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
func (c *Connector) SyncOnce(ctx context.Context) (err error) {
	defer func() {
		if err == nil {
			c.lastSync.Store(time.Now().UnixNano())
		}
	}()
	lastRevision := c.cursorStore.Get()

	// 1. Initial sync: no saved cursor -> Fetch full snapshot
	if lastRevision == 0 || c.cfg.SnapshotOnly {
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

	var payload []byte
	if len(c.cfg.SigningKey) == ed25519.PrivateKeySize {
		var nodesAdded []*v1.GraphNode
		for _, n := range delta.NodesAdded {
			nodesAdded = append(nodesAdded, &v1.GraphNode{
				Id:          n.ID,
				Type:        n.Type,
				Tier:        int32(n.Tier),
				DisplayName: n.DisplayName,
				Properties:  n.Properties,
			})
		}
		var edgesAdded []*v1.GraphEdge
		for _, e := range delta.EdgesAdded {
			edgesAdded = append(edgesAdded, &v1.GraphEdge{
				Source:     e.Source,
				Target:     e.Target,
				Kind:       e.Kind,
				Action:     e.Action,
				Properties: e.Properties,
			})
		}
		var edgesRemoved []*v1.GraphEdge
		for _, e := range delta.EdgesRemoved {
			edgesRemoved = append(edgesRemoved, &v1.GraphEdge{
				Source:     e.Source,
				Target:     e.Target,
				Kind:       e.Kind,
				Action:     e.Action,
				Properties: e.Properties,
			})
		}
		msgID := uuid.NewString()
		env := &v1.ConnectorEnvelope{
			SchemaVersion:  1,
			TenantId:       c.cfg.TenantID,
			ConnectorId:    c.cfg.ConnectorID,
			MessageId:      msgID,
			CorrelationId:  msgID,
			SourceRevision: delta.ToRevision,
		}
		protoDelta := &v1.GraphDelta{
			TenantId:     c.cfg.TenantID,
			ConnectorId:  c.cfg.ConnectorID,
			FromRevision: delta.FromRevision,
			ToRevision:   delta.ToRevision,
			NodesAdded:   nodesAdded,
			NodesRemoved: delta.NodesRemoved,
			EdgesAdded:   edgesAdded,
			EdgesRemoved: edgesRemoved,
			Timestamp:    delta.Timestamp,
			Envelope:     env,
		}
		syncMsg := &v1.SignedGraphSync{
			Envelope: env,
			Payload:  &v1.SignedGraphSync_Delta{Delta: protoDelta},
		}
		digest, err := bus.SyncSigningDigest(canon.New(), syncMsg)
		if err != nil {
			return fmt.Errorf("failed to sign delta: %w", err)
		}
		syncMsg.Signature = ed25519.Sign(c.cfg.SigningKey, digest[:])
		raw, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(syncMsg)
		if err != nil {
			return fmt.Errorf("failed to marshal signed delta: %w", err)
		}
		payload = raw
	} else {
		raw, err := json.Marshal(map[string]any{
			"type":  "delta",
			"delta": delta,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal delta: %w", err)
		}
		payload = raw
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

	var payload []byte
	if len(c.cfg.SigningKey) == ed25519.PrivateKeySize {
		var protoNodes []*v1.GraphNode
		for _, n := range snapshot.Nodes {
			protoNodes = append(protoNodes, &v1.GraphNode{
				Id:          n.ID,
				Type:        n.Type,
				Tier:        int32(n.Tier),
				DisplayName: n.DisplayName,
				Properties:  n.Properties,
			})
		}
		var protoEdges []*v1.GraphEdge
		for _, e := range snapshot.Edges {
			protoEdges = append(protoEdges, &v1.GraphEdge{
				Source:     e.Source,
				Target:     e.Target,
				Kind:       e.Kind,
				Action:     e.Action,
				Properties: e.Properties,
			})
		}
		protoSnap := &v1.GraphSnapshot{
			Complete:       snapshot.Complete,
			Envelope:       snapshot.Envelope,
			TenantId:       snapshot.TenantID,
			ConnectorId:    snapshot.ConnectorID,
			SourceRevision: snapshot.SourceRevision,
			Nodes:          protoNodes,
			Edges:          protoEdges,
			Timestamp:      snapshot.Timestamp,
		}
		syncMsg := &v1.SignedGraphSync{
			Envelope: snapshot.Envelope,
			Payload:  &v1.SignedGraphSync_Snapshot{Snapshot: protoSnap},
		}
		digest, err := bus.SyncSigningDigest(canon.New(), syncMsg)
		if err != nil {
			return fmt.Errorf("failed to sign snapshot: %w", err)
		}
		syncMsg.Signature = ed25519.Sign(c.cfg.SigningKey, digest[:])
		raw, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(syncMsg)
		if err != nil {
			return fmt.Errorf("failed to marshal signed snapshot: %w", err)
		}
		payload = raw
	} else {
		raw, err := json.Marshal(map[string]any{
			"type":     "snapshot",
			"snapshot": snapshot,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal snapshot: %w", err)
		}
		payload = raw
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

// Ready requires recent confirmed publication, not just a running process.
func (c *Connector) Ready(now time.Time) error {
	last := c.lastSync.Load()
	limit := 3 * c.cfg.SyncInterval
	if limit < 15*time.Second {
		limit = 15 * time.Second
	}
	if last == 0 || now.Sub(time.Unix(0, last)) > limit {
		return fmt.Errorf("source publication unavailable")
	}
	return nil
}
