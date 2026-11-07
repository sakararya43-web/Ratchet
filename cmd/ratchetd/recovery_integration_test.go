//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestRecoveryChildProcess(t *testing.T) {
	if tenant := os.Getenv("RATCHET_RECOVERY_CHILD"); tenant != "" {
		if err := runRecovery(t.Context(), []string{"--tenant", tenant, "--rebuild"}, os.Stdout); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecoveryRebuildsRetainedEvidenceInNewProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
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
	tenant := "recovery_" + uuid.NewString()
	data := graph.Data{Nodes: []graph.Node{{ID: "role:reader", Type: "Role"}, {ID: "report", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{Source: "role:reader", Target: "report", Kind: "GRANTS", Action: "read"}}}
	if _, err := store.IngestGraph(ctx, eventstore.GraphInput{TenantID: tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{1}).String(), ToRevision: 1, Complete: true, Snapshot: &data}, bytes.Repeat([]byte{4}, 32)); err != nil {
		t.Fatal(err)
	}
	var before bytes.Buffer
	if err := runRecovery(ctx, []string{"--tenant", tenant}, &before); err != nil {
		t.Fatal(err)
	}
	if err := store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		_, err := tx.Exec(ctx, `UPDATE ratchet.audit_projection SET display='{}' WHERE tenant_id=$1`, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryChildProcess$")
	child.Env = append(os.Environ(), "RATCHET_RECOVERY_CHILD="+tenant)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("new process recovery: %v %s", err, output)
	}
	var after bytes.Buffer
	if err := runRecovery(ctx, []string{"--tenant", tenant}, &after); err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	if json.Unmarshal(before.Bytes(), &a) != nil || json.Unmarshal(after.Bytes(), &b) != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatal("recovery changed committed graph, chain or display commitments")
	}
}
