//go:build integration

package eventstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestExternalPrivacyKeyDeletionRetainsPublicVerification(t *testing.T) {
	ctx, _, store, tenant := setup(t)
	path := filepath.Join(t.TempDir(), "privacy.key")
	if err := eventstore.CreatePrivacyKey(path); err != nil {
		t.Fatal(err)
	}
	if err := eventstore.CreatePrivacyKey(path); err == nil {
		t.Fatal("existing privacy key overwritten")
	}
	key, err := eventstore.LoadPrivacyKey(path)
	if err != nil {
		t.Fatal(err)
	}
	data := graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human", DisplayName: "Sensitive display name"}}}
	if _, err := store.IngestGraph(ctx, eventstore.GraphInput{TenantID: tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{2}).String(), ToRevision: 1, Complete: true, Snapshot: &data}, key); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReplayGraph(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CurrentGraph(ctx, tenant, key); err != nil {
		t.Fatal("live external key could not decrypt source", err)
	}
	count, tip, err := store.VerifyTenant(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if err := eventstore.DestroyPrivacyKey(path); err != nil {
		t.Fatal(err)
	}
	if _, err := eventstore.LoadPrivacyKey(path); !os.IsNotExist(err) {
		t.Fatal("deleted key reopened", err)
	}
	if _, err := store.CurrentGraph(ctx, tenant, key); err == nil {
		t.Fatal("destroyed key decrypted retained private context")
	}
	after, err := store.ReplayGraph(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	a, err := canon.New().Digest(before.Data())
	if err != nil {
		t.Fatal(err)
	}
	b, err := canon.New().Digest(after.Data())
	if err != nil || a != b {
		t.Fatal("key destruction changed retained graph", err)
	}
	end, endTip, err := store.VerifyTenant(ctx, tenant)
	if err != nil || count != end || tip != endTip {
		t.Fatal("key destruction damaged chain", err)
	}
}
