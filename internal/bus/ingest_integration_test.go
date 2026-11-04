//go:build integration

package bus_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type live struct {
	ctx      context.Context
	store    *eventstore.Store
	registry *graph.Registry
	ingestor *bus.Ingestor
	broker   *bus.Broker
	tenant   string
	private  ed25519.PrivateKey
	key      []byte
}

func setup(t *testing.T) live {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	dsn := os.Getenv("RATCHET_DATABASE_DSN")
	migration := os.Getenv("RATCHET_MIGRATION_DSN")
	if dsn == "" || migration == "" {
		t.Fatal("real PostgreSQL runtime/migration DSNs are required")
	}
	if err := eventstore.Migrate(ctx, migration); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := graph.NewRegistry(100 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "bus_" + uuid.NewString()
	key := bytes.Repeat([]byte{13}, 32)
	ingestor, err := bus.NewIngestor(store, registry, canon.New(), key, []bus.ConnectorKey{{TenantID: tenant, ConnectorID: "source", PublicKey: pub}})
	if err != nil {
		t.Fatal(err)
	}
	url := os.Getenv("RATCHET_NATS_URL")
	if url == "" {
		url = "nats://127.0.0.1:54222"
	}
	broker, err := bus.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Close)
	if err := broker.EnsureTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	return live{ctx, store, registry, ingestor, broker, tenant, private, key}
}
func snapshot(l live) *v1.SignedGraphSync {
	return &v1.SignedGraphSync{Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: l.tenant, ConnectorId: "source", MessageId: uuid.NewString(), CorrelationId: uuid.NewString(), SourceRevision: 10}, Payload: &v1.SignedGraphSync_Snapshot{Snapshot: &v1.GraphSnapshot{TenantId: l.tenant, ConnectorId: "source", SourceRevision: 10, Complete: true, Nodes: []*v1.GraphNode{{Id: "user:a", Type: "Human", DisplayName: "Private Name"}, {Id: "role:r", Type: "Role"}, {Id: "wallet", Type: "Resource", Tier: 0}}, Edges: []*v1.GraphEdge{{Source: "role:r", Target: "wallet", Kind: "GRANTS", Action: "sign"}}}}}
}
func sign(t *testing.T, l live, message *v1.SignedGraphSync) []byte {
	t.Helper()
	d, err := bus.SyncSigningDigest(canon.New(), message)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature = ed25519.Sign(l.private, d[:])
	raw, err := protojson.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedIngestGapRecoveryReplayAndPrivacy(t *testing.T) {
	l := setup(t)
	message := snapshot(l)
	raw := sign(t, l, message)
	if err := l.ingestor.Handle(l.ctx, l.tenant, raw); err != nil {
		t.Fatal(err)
	}
	first, err := l.registry.Get(l.ctx, l.tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ingestor.Handle(l.ctx, l.tenant, raw); err != nil {
		t.Fatal(err)
	}
	same, err := l.registry.Get(l.ctx, l.tenant, 1)
	if err != nil || same.Version() != first.Version() {
		t.Fatal("duplicate advanced graph")
	}
	gap := &v1.SignedGraphSync{Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: l.tenant, ConnectorId: "source", MessageId: uuid.NewString(), CorrelationId: uuid.NewString(), SourceRevision: 12}, Payload: &v1.SignedGraphSync_Delta{Delta: &v1.GraphDelta{TenantId: l.tenant, ConnectorId: "source", FromRevision: 11, ToRevision: 12}}}
	gapRaw := sign(t, l, gap)
	if err := l.ingestor.Handle(l.ctx, l.tenant, gapRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := l.registry.Get(l.ctx, l.tenant, 0); !errors.Is(err, graph.ErrUnavailable) {
		t.Fatal("gap left graph available")
	}
	if _, err := l.store.CurrentGraph(l.ctx, l.tenant, l.key); !errors.Is(err, eventstore.ErrResyncRequired) {
		t.Fatal("quarantine not durable")
	}
	repair := proto.Clone(message).(*v1.SignedGraphSync)
	repair.Envelope.MessageId = uuid.NewString()
	repair.Envelope.SourceRevision = 12
	repair.GetSnapshot().SourceRevision = 12
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, repair)); err != nil {
		t.Fatal(err)
	}
	// Old gap delivery must not invalidate an already repaired newer source.
	if err := l.ingestor.Handle(l.ctx, l.tenant, gapRaw); err != nil {
		t.Fatal(err)
	}
	current, err := l.registry.Get(l.ctx, l.tenant, 0)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := l.store.ReplayGraph(l.ctx, l.tenant)
	if err != nil || replayed.Version() != current.Version() {
		t.Fatalf("replay: %v", err)
	}
	a, _ := current.Reach("user:a")
	b, _ := replayed.Reach("user:a")
	if !reflect.DeepEqual(a.Powers, b.Powers) {
		t.Fatal("replay authority differs")
	}
	events, err := l.store.LoadStream(l.ctx, l.tenant, "graph:source")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if bytes.Contains(event.Entry.Canonical, []byte("Private Name")) {
			t.Fatal("personal data leaked to ledger")
		}
	}
	if _, _, err := l.store.VerifyTenant(l.ctx, l.tenant); err != nil {
		t.Fatal(err)
	}
	changed := proto.Clone(repair).(*v1.SignedGraphSync)
	changed.GetSnapshot().Nodes[0].Tier = 1
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, changed)); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatalf("conflicting ID: %v", err)
	}
}

func TestCrossTenantForgeryIncompleteAndMissingNodesRejected(t *testing.T) {
	l := setup(t)
	m := snapshot(l)
	m.Envelope.TenantId = "another-tenant"
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, m)); !errors.Is(err, bus.ErrAuthentication) {
		t.Fatal(err)
	}
	m = snapshot(l)
	raw := sign(t, l, m)
	m.Signature[0] ^= 1
	raw, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ingestor.Handle(l.ctx, l.tenant, raw); !errors.Is(err, bus.ErrAuthentication) {
		t.Fatal("forgery accepted")
	}
	m = snapshot(l)
	m.GetSnapshot().Complete = false
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, m)); !errors.Is(err, eventstore.ErrInvalid) {
		t.Fatal("partial snapshot accepted")
	}
	m = snapshot(l)
	m.GetSnapshot().Edges[0].Target = "missing"
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, m)); !errors.Is(err, graph.ErrInvalid) {
		t.Fatal("dangling edge accepted")
	}
}

func TestJetStreamDeliveryRestartAndLostPublishAck(t *testing.T) {
	l := setup(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	message := snapshot(l)
	raw := sign(t, l, message)
	consumerCtx, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() {
		done <- l.broker.Consume(consumerCtx, l.tenant, func(ctx context.Context, payload []byte) error { return l.ingestor.Handle(ctx, l.tenant, payload) }, logger)
	}()
	if err := l.broker.Publish(l.ctx, "ratchet."+l.tenant+".ingest.sync", message.Envelope.MessageId, raw); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var before *graph.Snapshot
	for time.Now().Before(deadline) {
		var err error
		before, err = l.registry.Get(l.ctx, l.tenant, 1)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if before == nil {
		t.Fatal("real NATS consumer did not ingest")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Publish persisted but caller saw an error: row must remain pending.
	_, err := l.store.DeliverOne(l.ctx, l.tenant, func(ctx context.Context, subject, id string, payload []byte) error {
		if err := l.broker.Publish(ctx, subject, id, payload); err != nil {
			return err
		}
		return errors.New("lost publish acknowledgement")
	})
	if err == nil {
		t.Fatal("fault injection failed")
	}
	backlog, err := l.store.OutboxBacklog(l.ctx, l.tenant)
	if err != nil || backlog.Pending != 1 || backlog.Attempts != 1 {
		t.Fatalf("backlog %+v %v", backlog, err)
	}
	time.Sleep(120 * time.Millisecond)
	if worked, err := l.store.DeliverOne(l.ctx, l.tenant, l.broker.Publish); err != nil || !worked {
		t.Fatalf("retry %v %v", worked, err)
	}
	backlog, err = l.store.OutboxBacklog(l.ctx, l.tenant)
	if err != nil || backlog.Pending != 0 {
		t.Fatal("ack did not settle outbox")
	}
	url := os.Getenv("RATCHET_NATS_URL")
	if url == "" {
		url = "nats://127.0.0.1:54222"
	}
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	info, err := js.StreamInfo(bus.StreamName(l.tenant, "EVENTS"))
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("broker dedup: %+v %v", info, err)
	}
	// Restarting a durable consumer after its acknowledged input must not replay
	// an effect or lose its persisted cursor.
	restartCtx, stop := context.WithTimeout(l.ctx, 200*time.Millisecond)
	defer stop()
	err = l.broker.Consume(restartCtx, l.tenant, func(context.Context, []byte) error {
		t.Error("acknowledged input replayed after reconnect")
		return nil
	}, logger)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("restart: %v", err)
	}
}
