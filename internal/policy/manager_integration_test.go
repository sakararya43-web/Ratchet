//go:build integration

package policy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func TestDurableGovernanceFloorOfflineRestoreAndBundleRollback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Getenv("RATCHET_MIGRATION_DSN") == "" {
		t.Fatal("real PostgreSQL required")
	}
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
	tenant := "governance_" + uuid.NewString()
	authorityFile := filepath.Join(t.TempDir(), "authority.json")
	authority, root, keys, members := governedTenant(t, tenant, authorityFile)
	modules := map[string]string{}
	for _, name := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile("../../policies/" + name)
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = string(raw)
	}
	bundle := func(version string) []byte {
		t.Helper()
		g, err := authority.GetGenesis()
		if err != nil {
			t.Fatal(err)
		}
		p, err := authority.ProposeBundle(tenant, version, "governance integration", modules, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		d := trust.ComputePolicySigningDigest(tenant, g.Epoch, p.BundleDigest)
		for i, member := range members {
			if (g.Epoch == 1 && i < 2) || (g.Epoch == 2 && i == 2) {
				sig, err := ecdsa.SignASN1(rand.Reader, keys[i], d[:])
				if err != nil {
					t.Fatal(err)
				}
				if err := authority.SignProposal(p.ProposalID, trust.MemberSignature{ActorID: member.ActorID, Signature: sig}); err != nil {
					t.Fatal(err)
				}
			}
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	m := policy.Manager{Store: store, Engine: policy.NewEngine(), Authority: authority, Root: root, Tenant: tenant}
	first := bundle("1.0.0")
	// Reproduce a real schema-5 activation, which has no frozen trust-proof
	// column yet. The upgrade must establish verified proof without rewriting it.
	var legacy trust.PolicyBundle
	if err := json.Unmarshal(first, &legacy); err != nil {
		t.Fatal(err)
	}
	if err := store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		facts, err := json.Marshal(map[string]any{"bundle_digest": legacy.BundleDigest.String(), "bundle_version": legacy.BundleVersion, "genesis_digest": root.String(), "registry_epoch": 1})
		if err != nil {
			return err
		}
		receipt, err := store.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.New(), StreamID: "policy:bundles", ActorReference: uuid.New(), Events: []eventstore.Event{{Type: "PolicyBundleActivated", Facts: facts}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.policy_artifacts(tenant_id,version,digest,raw_bundle,event_position) VALUES($1,$2,$3,$4,$5)`, tenant, legacy.BundleVersion, legacy.BundleDigest.Bytes(), first, receipt.LastSequence)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	legacyOffline := m
	legacyOffline.Authority = nil
	legacyOffline.Engine = policy.NewEngine()
	if err := legacyOffline.Restore(ctx); err != nil {
		t.Fatal("legacy proof was not durably established", err)
	}
	second := bundle("1.1.0")
	if err := m.Activate(ctx, second); err != nil {
		t.Fatal(err)
	}
	if m.Activate(ctx, first) == nil {
		t.Fatal("obsolete signed bundle rolled back policy")
	}
	last, err := m.Engine.Current(tenant)
	if err != nil {
		t.Fatal(err)
	}
	bundleFile := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(bundleFile, second, 0600); err != nil {
		t.Fatal(err)
	}
	source := policy.FileSource{Manager: m, AuthorityFile: authorityFile, BundleFile: bundleFile}
	if err := source.Refresh(ctx); err != nil {
		t.Fatal("actual file refresh", err)
	}
	if err := os.WriteFile(authorityFile, []byte("invalid Authority candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(ctx); err == nil {
		t.Fatal("invalid source admitted")
	}
	if current, err := m.Engine.Current(tenant); err != nil || current.Hash != last.Hash {
		t.Fatal("unverified source erased last valid operation", err)
	}
	offline := m
	offline.Authority = nil
	offline.Engine = policy.NewEngine()
	if err := offline.Restore(ctx); err != nil {
		t.Fatal("Authority outage lost persisted policy", err)
	}
	if a, err := offline.Engine.Current(tenant); err != nil || a.Hash != last.Hash {
		t.Fatal("last valid bundle lost", err)
	}
	rotation(t, authority, keys, members)
	if err := m.RefreshRegistry(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Engine.Current(tenant); !errors.Is(err, policy.ErrUnavailable) {
		t.Fatal("old policy stayed active across registry change", err)
	}
	stale := policy.Manager{Store: store, Engine: offline.Engine, Authority: nil, Root: root, Tenant: tenant}
	if err := stale.Restore(ctx); !errors.Is(err, policy.ErrUnavailable) {
		t.Fatal("restart bypassed durable epoch floor", err)
	}
	current := bundle("1.2.0")
	if err := m.Activate(ctx, current); err != nil {
		t.Fatal(err)
	}
	if a, err := m.Engine.Current(tenant); err != nil || a.RegistryEpoch != 2 {
		t.Fatal("new-epoch bundle unavailable", err)
	}
	offline.Engine = policy.NewEngine()
	if err := offline.Restore(ctx); err != nil {
		t.Fatal("rotated proof could not restore offline", err)
	}
	if err := offline.Activate(ctx, first); err == nil {
		t.Fatal("offline activation bypass")
	}
	if _, _, err := store.VerifyTenant(ctx, tenant); err != nil {
		t.Fatal("governance events not chained", err)
	}
}
