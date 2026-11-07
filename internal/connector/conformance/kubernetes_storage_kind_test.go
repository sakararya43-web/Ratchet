//go:build integration && peerintegration && kindintegration

package conformance_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestActualKindGraphFitsLedgerAndReplays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := eventstore.Migrate(ctx, os.Getenv("RATCHET_MIGRATION_DSN")); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	state, revision, err := configuredPeerAdapter(t).NativeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.KubernetesSource(0, state)
	if err != nil {
		t.Fatal(err)
	}
	data := snapshot.Data()
	tenant := "kind_" + uuid.NewString()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	wire, err := canon.New().Digest(state)
	if err != nil {
		t.Fatal(err)
	}
	input := eventstore.GraphInput{TenantID: tenant, ConnectorID: "k8s-source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: wire.String(), ToRevision: revision, Complete: true, Snapshot: &data}
	receipt, err := store.IngestGraph(ctx, input, key)
	if err != nil {
		t.Fatal("actual full inventory did not fit immutable ingestion", err)
	}
	durable, err := store.CurrentGraph(ctx, tenant, key)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := durable.KubernetesState(state.Cluster)
	if err != nil || !reflect.DeepEqual(state, observed) {
		t.Fatal("encrypted complete source lost facts", err)
	}
	replay, err := store.ReplayGraph(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	public := durable.Data()
	public.Kubernetes = nil
	if !reflect.DeepEqual(public, replay.Data()) || replay.Version() != receipt.Version {
		t.Fatal("retained replay differs from live authority")
	}
	events, err := store.LoadStream(ctx, tenant, "graph:k8s-source")
	if err != nil || len(events) != 1 {
		t.Fatal("missing immutable cut", err)
	}
	var content struct {
		Payload struct {
			Private string `json:"private_record_reference"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(events[0].Entry.Canonical, &content); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(content.Payload.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePrivateRecord(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	after, err := store.ReplayGraph(ctx, tenant)
	if err != nil || !reflect.DeepEqual(replay.Data(), after.Data()) {
		t.Fatal("erasure destroyed authority replay", err)
	}
	t.Logf("actual full cut stored: nodes=%d edges=%d immutable_bytes=%d version=%d", len(data.Nodes), len(data.Edges), len(events[0].Entry.Canonical), receipt.Version)
}
