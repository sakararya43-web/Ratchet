package domain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeterministicSeed(t *testing.T) {
	s1 := NewSeedOrgState()
	s2 := NewSeedOrgState()

	b1, err := json.Marshal(s1)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	b2, err := json.Marshal(s2)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	if string(b1) != string(b2) {
		t.Errorf("expected deterministic seed state, got mismatch:\n%s\nvs\n%s", string(b1), string(b2))
	}

	// Verify Rahul, Sec Leads, Tier-0 Wallet Signer and Safeguard exist
	foundRahul := false
	foundWalletSigner := false
	foundWithdrawalSafeguard := false
	foundControl := false

	for _, id := range s1.Identities {
		if id.ID == "user:rahul" {
			foundRahul = true
		}
	}
	for _, res := range s1.Resources {
		if res.ID == "svc:wallet-signer" && res.Tier == 0 {
			foundWalletSigner = true
		}
	}
	for _, sg := range s1.Safeguards {
		if sg.ID == "safeguard:withdrawal-rule" && sg.Tier == 0 {
			foundWithdrawalSafeguard = true
		}
	}
	for _, cr := range s1.ControlRelations {
		if cr.ControllerID == "user:rahul" && cr.ControlledID == "user:rahul-assistant" {
			foundControl = true
		}
	}

	if !foundRahul {
		t.Errorf("user:rahul missing from seed")
	}
	if !foundWalletSigner {
		t.Errorf("svc:wallet-signer (Tier 0) missing from seed")
	}
	if !foundWithdrawalSafeguard {
		t.Errorf("safeguard:withdrawal-rule (Tier 0) missing from seed")
	}
	if !foundControl {
		t.Errorf("Rahul control relation missing from seed")
	}
}

func TestStorePersistenceAndRestart(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sim_test_state.json")

	// 1. Initialize store
	store, err := NewStore(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// 2. Perform a mutation
	if err := store.AssignRole("test-admin", "user:rahul", "role:exchange-admin"); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	state1 := store.GetState()
	if state1.Revision != 1001 {
		t.Errorf("expected revision 1001, got %d", state1.Revision)
	}

	// 3. Simulate process restart by reloading from the same file
	reloadedStore, err := NewStore(filePath)
	if err != nil {
		t.Fatalf("failed to reload store from file: %v", err)
	}

	reloadedState := reloadedStore.GetState()
	if reloadedState.Revision != 1001 {
		t.Errorf("restart did not preserve revision: got %d, want 1001", reloadedState.Revision)
	}

	hasAdminGrant := false
	for _, g := range reloadedState.Grants {
		if g.IdentityID == "user:rahul" && g.RoleID == "role:exchange-admin" {
			hasAdminGrant = true
			break
		}
	}
	if !hasAdminGrant {
		t.Errorf("restart did not preserve assigned admin grant")
	}

	// 4. Test ResetToSeed
	if err := reloadedStore.ResetToSeed(); err != nil {
		t.Fatalf("reset error: %v", err)
	}

	resetState := reloadedStore.GetState()
	if resetState.Revision != 1000 {
		t.Errorf("expected reset revision 1000, got %d", resetState.Revision)
	}
}

func TestExportSeedFixture(t *testing.T) {
	// Generate the official testdata/orgs/exchange-v1.json from simulator seed
	seed := NewSeedOrgState()
	data, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Serialization verification must not rewrite the reviewed repository fixture.
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir error: %v", err)
	}

	destPath := filepath.Join(dir, "exchange-v1.json")
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		t.Fatalf("write fixture error: %v", err)
	}

	// Verify file is readable and parses back
	readBack, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read back error: %v", err)
	}

	var parsed OrgState
	if err := json.Unmarshal(readBack, &parsed); err != nil {
		t.Fatalf("unmarshal back error: %v", err)
	}

	if parsed.TenantID != "tenant-exchange-demo" {
		t.Errorf("unexpected tenant ID in fixture: %s", parsed.TenantID)
	}
}
