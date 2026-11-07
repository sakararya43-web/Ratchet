package connector_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCompleteSignedCutsPreserveSessionChangesAcrossRestart(t *testing.T) {
	ctx := context.Background()
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(simserver.NewServer(store, "private-test-token").Routes())
	defer server.Close()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := connector.Config{TenantID: "tenant-exchange-demo", ConnectorID: "source", CursorPath: filepath.Join(t.TempDir(), "cursor.json"), SigningKey: key, SnapshotOnly: true}
	publisher := connector.NewMemoryPublisher()
	adapter := sim.NewAdapter(server.URL, "private-test-token", cfg.TenantID, cfg.ConnectorID)
	c, err := connector.NewConnector(cfg, adapter, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.TerminateSession("test-operator", "session:intern-workstation-1"); err != nil {
		t.Fatal(err)
	}
	c, err = connector.NewConnector(cfg, adapter, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	messages := publisher.GetMessages(c.SyncSubject())
	if len(messages) != 2 {
		t.Fatal("missing complete cut")
	}
	var message v1.SignedGraphSync
	if err = protojson.Unmarshal(messages[1], &message); err != nil {
		t.Fatal(err)
	}
	digest, err := bus.SyncSigningDigest(canon.New(), &message)
	if err != nil || !ed25519.Verify(public, digest[:], message.Signature) {
		t.Fatal("snapshot authentication", err)
	}
	snapshot := message.GetSnapshot()
	if snapshot == nil || !snapshot.Complete || snapshot.SourceRevision != store.GetState().Revision {
		t.Fatal("incomplete/stale source cut")
	}
	found := false
	for _, node := range snapshot.Nodes {
		if node.Id == "session:intern-workstation-1" {
			found = node.Properties["disabled"] == "true"
		}
	}
	if !found {
		t.Fatal("session termination omitted")
	}
}

func TestCursorDoesNotAdvanceWhenPersistenceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor")
	cursor, err := connector.NewCursorStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = cursor.Set(7); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err = cursor.Set(8); err == nil {
		t.Fatal("directory replaced by cursor")
	}
	if cursor.Get() != 7 {
		t.Fatal("failed persistence advanced cursor")
	}
}
