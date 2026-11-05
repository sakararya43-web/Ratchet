//go:build integration

package bus_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

func nativeState() kube.State {
	return kube.State{Cluster: "native-private-cluster", ResourceVersion: "opaque/source-cut-one", Complete: true, Namespaces: []string{"finance"}, Principals: []kube.Principal{{ID: "native-user", Kind: "User", Name: "Private Native Person", Groups: []string{"Private Native Group"}}}, Resources: []kube.APIResource{{Resource: "pods", Namespaced: true}}, Objects: []kube.Object{{Kind: "Role", Name: "reader", Namespace: "finance", UID: "role-uid", ResourceVersion: "opaque/role-rv", Rules: []kube.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}, {Kind: "RoleBinding", Name: "reader", Namespace: "finance", UID: "binding-uid", ResourceVersion: "opaque/binding-rv", RoleKind: "Role", RoleName: "reader", Subjects: []kube.Subject{{Kind: "User", Name: "Private Native Person"}}}}}
}

func nativeMessage(t *testing.T, l live, state kube.State, revision int64) *v1.SignedGraphSync {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return &v1.SignedGraphSync{Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: l.tenant, ConnectorId: "source", MessageId: uuid.NewString(), CorrelationId: uuid.NewString(), SourceRevision: revision}, Payload: &v1.SignedGraphSync_Kubernetes{Kubernetes: &v1.NormalizedKubernetesSnapshot{TenantId: l.tenant, ConnectorId: "source", SourceRevision: revision, NormalizedStateJson: raw}}}
}

func TestNativeSignedIngestPersistsReplaysAndHoldsAfterPrivacyDeletion(t *testing.T) {
	l := setup(t)
	state := nativeState()
	message := nativeMessage(t, l, state, 10)
	raw := sign(t, l, message)
	consume, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() {
		done <- l.broker.Consume(consume, l.tenant, func(ctx context.Context, payload []byte) error { return l.ingestor.Handle(ctx, l.tenant, payload) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("consumer shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("native ingestion consumer failed to stop")
		}
	})
	if err := l.broker.Publish(l.ctx, "ratchet."+l.tenant+".ingest.sync", message.Envelope.MessageId, raw); err != nil {
		t.Fatal(err)
	}
	var snapshot *graph.Snapshot
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		snapshot, err = l.registry.Get(l.ctx, l.tenant, 1)
		if err == nil {
			break
		}
	}
	if snapshot == nil {
		t.Fatal("actual JetStream did not deliver normalized native snapshot")
	}
	observed, err := snapshot.KubernetesState(state.Cluster)
	if err != nil || !reflect.DeepEqual(observed, state) {
		t.Fatal("normalized source not persisted", err)
	}
	if err := l.ingestor.Handle(l.ctx, l.tenant, raw); err != nil {
		t.Fatal("duplicate native delivery", err)
	}
	restartedRegistry, err := graph.NewRegistry(100 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := bus.NewIngestor(l.store, restartedRegistry, canon.New(), l.key, []bus.ConnectorKey{{TenantID: l.tenant, ConnectorID: "source", PublicKey: l.private.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Refresh(l.ctx, l.tenant); err != nil {
		t.Fatal(err)
	}
	restored, err := restartedRegistry.Get(l.ctx, l.tenant, 1)
	if err != nil || restored.Version() != snapshot.Version() {
		t.Fatal("new ingestor failed to reload durable native state", err)
	}
	// Reconstruct from the database independently of the ingest cache.
	durable, err := l.store.CurrentGraph(l.ctx, l.tenant, l.key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := durable.KubernetesState(state.Cluster)
	if err != nil || !reflect.DeepEqual(again, state) {
		t.Fatal("database reload lost native source", err)
	}
	conflict, err := state.Clone()
	if err != nil {
		t.Fatal(err)
	}
	conflict.ResourceVersion = "opaque/different-source-cut"
	conflict.Objects[0].ResourceVersion = "opaque/different-role-rv"
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, nativeMessage(t, l, conflict, 10))); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("unchanged authority hid conflicting exact preimage revision", err)
	}
	events, err := l.store.LoadStream(l.ctx, l.tenant, "graph:source")
	if err != nil || len(events) != 1 {
		t.Fatal("native duplicate advanced stream", err)
	}
	if bytes.Contains(events[0].Entry.Canonical, []byte("Private Native")) || bytes.Contains(events[0].Entry.Canonical, []byte(state.Cluster)) {
		t.Fatal("personal native context leaked to retained ledger")
	}
	var content struct {
		Payload struct {
			Private string `json:"private_record_reference"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(events[0].Entry.Canonical, &content); err != nil {
		t.Fatal(err)
	}
	private, err := uuid.Parse(content.Payload.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.store.DeletePrivateRecord(l.ctx, l.tenant, private); err != nil {
		t.Fatal(err)
	}
	public, err := l.store.CurrentGraph(l.ctx, l.tenant, l.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.KubernetesState(state.Cluster); !errors.Is(err, graph.ErrUnavailable) {
		t.Fatal("erased source remained available for exact native decisions", err)
	}
	replay, err := l.store.ReplayGraph(l.ctx, l.tenant)
	if err != nil {
		t.Fatal(err)
	}
	id := graph.KubernetesNodeID(state.Cluster, "identity", "native-user")
	before, err := durable.Reach(id)
	if err != nil {
		t.Fatal(err)
	}
	after, err := replay.Reach(id)
	if err != nil || !reflect.DeepEqual(before.Powers, after.Powers) {
		t.Fatal("privacy deletion damaged retained authority replay", err)
	}
	if _, _, err := l.store.VerifyTenant(l.ctx, l.tenant); err != nil {
		t.Fatal("native ledger verification after privacy deletion", err)
	}
}

func TestNativeIngestRejectsIncompleteFactsAndQuarantinesGenericDeltas(t *testing.T) {
	l := setup(t)
	state := nativeState()
	for _, tc := range []struct {
		name string
		edit func(*v1.SignedGraphSync)
	}{
		{"wrong connector", func(m *v1.SignedGraphSync) { m.GetKubernetes().ConnectorId = "other" }},
		{"wrong tenant", func(m *v1.SignedGraphSync) { m.GetKubernetes().TenantId = "other" }},
		{"wrong revision", func(m *v1.SignedGraphSync) { m.GetKubernetes().SourceRevision = 9 }},
		{"unknown normalized field", func(m *v1.SignedGraphSync) {
			m.GetKubernetes().NormalizedStateJson = []byte(`{"complete":true,"invented":true}`)
		}},
		{"trailing normalized object", func(m *v1.SignedGraphSync) {
			m.GetKubernetes().NormalizedStateJson = append(m.GetKubernetes().NormalizedStateJson, []byte(` {}`)...)
		}},
		{"partial roster", func(m *v1.SignedGraphSync) {
			s := state
			s.Complete = false
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			m.GetKubernetes().NormalizedStateJson = raw
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := nativeMessage(t, l, state, 10)
			tc.edit(m)
			if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, m)); err == nil {
				t.Fatal("invalid native source accepted")
			}
		})
	}
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, nativeMessage(t, l, state, 10))); err != nil {
		t.Fatal(err)
	}
	// A second connector cannot silently take ownership of an already observed
	// native cluster, even when every anonymous graph node happens to agree.
	other, err := bus.NewIngestor(l.store, l.registry, canon.New(), l.key, []bus.ConnectorKey{{TenantID: l.tenant, ConnectorID: "other", PublicKey: l.private.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	duplicateCluster := nativeMessage(t, l, state, 1)
	duplicateCluster.Envelope.ConnectorId = "other"
	duplicateCluster.GetKubernetes().ConnectorId = "other"
	if err := other.Handle(l.ctx, l.tenant, sign(t, l, duplicateCluster)); !errors.Is(err, graph.ErrInvalid) {
		t.Fatal("ambiguous native cluster ownership accepted", err)
	}
	delta := &v1.SignedGraphSync{Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: l.tenant, ConnectorId: "source", MessageId: uuid.NewString(), CorrelationId: uuid.NewString(), SourceRevision: 11}, Payload: &v1.SignedGraphSync_Delta{Delta: &v1.GraphDelta{TenantId: l.tenant, ConnectorId: "source", FromRevision: 10, ToRevision: 11}}}
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, delta)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.store.CurrentGraph(l.ctx, l.tenant, l.key); !errors.Is(err, eventstore.ErrResyncRequired) {
		t.Fatal("generic edge delta left stale native preimages ready", err)
	}
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, nativeMessage(t, l, state, 11))); err != nil {
		t.Fatal("native full-cut recovery", err)
	}
	if _, err := l.store.CurrentGraph(l.ctx, l.tenant, l.key); err != nil {
		t.Fatal("native source not restored after complete resync", err)
	}
}
