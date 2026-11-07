package connector_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
)

func TestConnectorSyncLifecycle(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// 1. Setup simulator server
	store, err := domain.NewStore(filepath.Join(tmpDir, "sim.json"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	server := simserver.NewServer(store, "test-broker-token")
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	// 2. Setup connector with memory publisher and temporary cursor store
	adapter := sim.NewAdapter(ts.URL, "test-broker-token", "tenant-exchange-demo", "connector-sim-01")
	publisher := connector.NewMemoryPublisher()
	cursorPath := filepath.Join(tmpDir, "cursor.json")

	conn, err := connector.NewConnector(connector.Config{
		TenantID:    "tenant-exchange-demo",
		ConnectorID: "connector-sim-01",
		CursorPath:  cursorPath,
	}, adapter, publisher)
	if err != nil {
		t.Fatalf("failed to create connector: %v", err)
	}

	subject := "ratchet.tenant-exchange-demo.ingest.sync"

	// 3. First sync: initial snapshot
	if err := conn.SyncOnce(ctx); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	msgs := publisher.GetMessages(subject)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message published, got %d", len(msgs))
	}

	var snapMsg struct {
		Type     string                  `json:"type"`
		Snapshot connector.GraphSnapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(msgs[0], &snapMsg); err != nil {
		t.Fatalf("failed to parse snapshot message: %v", err)
	}

	if snapMsg.Type != "snapshot" {
		t.Errorf("expected type 'snapshot', got %q", snapMsg.Type)
	}
	if snapMsg.Snapshot.SourceRevision != 1000 {
		t.Errorf("expected source revision 1000, got %d", snapMsg.Snapshot.SourceRevision)
	}
	if len(snapMsg.Snapshot.Nodes) == 0 || len(snapMsg.Snapshot.Edges) == 0 {
		t.Errorf("expected non-empty nodes and edges in snapshot")
	}

	// 4. Second sync with no target mutations: should not publish anything
	if err := conn.SyncOnce(ctx); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	if len(publisher.GetMessages(subject)) != 1 {
		t.Errorf("expected no duplicate message published, still 1")
	}

	// 5. Mutate target: assign Rahul exchange admin
	if err := store.AssignRole("test-admin", "user:rahul", "role:exchange-admin"); err != nil {
		t.Fatalf("assign role error: %v", err)
	}

	// 6. Third sync: should publish incremental delta
	if err := conn.SyncOnce(ctx); err != nil {
		t.Fatalf("third sync failed: %v", err)
	}

	msgsAfterDelta := publisher.GetMessages(subject)
	if len(msgsAfterDelta) != 2 {
		t.Fatalf("expected 2 messages published, got %d", len(msgsAfterDelta))
	}

	var deltaMsg struct {
		Type  string               `json:"type"`
		Delta connector.GraphDelta `json:"delta"`
	}
	if err := json.Unmarshal(msgsAfterDelta[1], &deltaMsg); err != nil {
		t.Fatalf("failed to parse delta message: %v", err)
	}

	if deltaMsg.Type != "delta" {
		t.Errorf("expected type 'delta', got %q", deltaMsg.Type)
	}
	if deltaMsg.Delta.ToRevision != 1001 {
		t.Errorf("expected to_revision 1001, got %d", deltaMsg.Delta.ToRevision)
	}
	if len(deltaMsg.Delta.EdgesAdded) != 1 {
		t.Errorf("expected 1 added edge in delta, got %d", len(deltaMsg.Delta.EdgesAdded))
	}

	// 7. Test Gap / Reset Detection: reset simulator back to 1000
	if err := store.ResetToSeed(); err != nil {
		t.Fatalf("reset error: %v", err)
	}

	// Fourth sync: should detect rollback and force full snapshot resync
	if err := conn.SyncOnce(ctx); err != nil {
		t.Fatalf("gap sync failed: %v", err)
	}

	msgsAfterReset := publisher.GetMessages(subject)
	if len(msgsAfterReset) != 3 {
		t.Fatalf("expected 3 messages published, got %d", len(msgsAfterReset))
	}

	var resyncMsg struct {
		Type     string                  `json:"type"`
		Snapshot connector.GraphSnapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(msgsAfterReset[2], &resyncMsg); err != nil {
		t.Fatalf("failed to parse resync message: %v", err)
	}
	if resyncMsg.Type != "snapshot" {
		t.Errorf("expected type 'snapshot' on gap resync, got %q", resyncMsg.Type)
	}
}
