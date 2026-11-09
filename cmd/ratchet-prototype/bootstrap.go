package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func randomHex() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func privateFile(path string, raw []byte) error { return os.WriteFile(path, raw, 0600) }

func initialize(ctx context.Context, pool *pgxpool.Pool, root, policyDir string) error {
	core, edge, operator := filepath.Join(root, "core"), filepath.Join(root, "edge"), filepath.Join(root, "operator")
	for _, dir := range []string{core, edge, operator} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	marker := filepath.Join(operator, "initialized.json")
	if _, err := os.Stat(marker); err == nil {
		return refreshCapability(root)
	} else if !os.IsNotExist(err) {
		return err
	}
	// A partial setup requires operator review; never silently replace pinned keys.
	if _, err := os.Stat(filepath.Join(core, "console.json")); err == nil {
		return errors.New("partial initialization; preserve volumes and investigate before retry")
	}
	_, coreKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public, edgeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	for path, raw := range map[string][]byte{filepath.Join(core, "signing.key"): []byte(hex.EncodeToString(coreKey)), filepath.Join(edge, "signing.key"): []byte(hex.EncodeToString(edgeKey)), filepath.Join(edge, "core.pub"): []byte(hex.EncodeToString(coreKey.Public().(ed25519.PublicKey)))} {
		if err := privateFile(path, raw); err != nil {
			return err
		}
	}
	if err := certificateFiles(core); err != nil {
		return err
	}
	authority, err := trust.NewStore(filepath.Join(core, "authority.json"))
	if err != nil {
		return err
	}
	keys := make([]*ecdsa.PrivateKey, 2)
	members := make([]trust.AuthorityMember, 2)
	for i, id := range []string{"bootstrap-lead-1", "bootstrap-lead-2"} {
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		raw, err := x509.MarshalPKIXPublicKey(&keys[i].PublicKey)
		if err != nil {
			return err
		}
		members[i] = trust.AuthorityMember{ActorID: id, DisplayName: id, PublicKey: raw, IsActive: true}
	}
	genesis, err := authority.InitGenesis(tenant, 2, 2, members)
	if err != nil {
		return err
	}
	modules := map[string]string{}
	for _, name := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile(filepath.Join(policyDir, name))
		if err != nil {
			return err
		}
		modules[name] = string(raw)
	}
	bundle, err := authority.ProposeBundle(tenant, "1.0.0", "Read-only prototype policy; local operator genesis, not live Authority passkey administration", modules, map[string]any{"resource_owners": map[string]any{"res:finance-reports": []string{"user:finance-lead"}, "res:daily-exchange-ledger": []string{"user:finance-lead"}, "svc:wallet-signer": []string{"user:sec-lead-1", "user:sec-lead-2"}}})
	if err != nil {
		return err
	}
	digest := trust.ComputePolicySigningDigest(tenant, 1, bundle.BundleDigest)
	for i, key := range keys {
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			return err
		}
		if err = authority.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: members[i].ActorID, Signature: sig}); err != nil {
			return err
		}
	}
	if _, err = authority.ActivateBundle(bundle.ProposalID); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(core, "bundle.json"), bundle); err != nil {
		return err
	}
	// Bootstrap signing keys are not retained by the serving core or connector.
	sessionKey, err := randomHex()
	if err != nil {
		return err
	}
	graphKey, err := randomHex()
	if err != nil {
		return err
	}
	cursorKey, err := randomHex()
	if err != nil {
		return err
	}
	console := map[string]any{"serve_web": true, "origin": "https://localhost:8444", "session_key_hex": sessionKey, "graph_key_hex": graphKey, "cursor_key_hex": cursorKey, "server_cert": "/data/core/server.pem", "server_key": "/data/core/server.key", "nats_url": "nats://127.0.0.1:4222", "tenants": []any{map[string]any{"tenant_id": tenant, "authority_file": "/data/core/authority.json", "genesis_digest": genesis.GenesisDigest.String(), "bundle_file": "/data/core/bundle.json", "execution": map[string]string{"connector_id": connectorID, "connector_public_key_hex": hex.EncodeToString(public), "core_signing_key_file": "/data/core/signing.key", "capability_file": "/data/core/capability.json"}}}}
	graph := map[string]any{"graph_key_hex": graphKey, "cursor_key_hex": cursorKey, "server_cert": "/data/core/server.pem", "server_key": "/data/core/server.key", "client_ca": "/data/core/ca.pem", "nats_url": "nats://127.0.0.1:4222", "readers": map[string]any{"prototype-operator": map[string]string{"tenant_id": tenant, "actor_id": "user:sec-lead-1"}}, "connectors": []any{map[string]string{"tenant_id": tenant, "connector_id": connectorID, "public_key_hex": hex.EncodeToString(public)}}}
	if err = writeJSON(filepath.Join(core, "console.json"), console); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(core, "graph.json"), graph); err != nil {
		return err
	}

	users := []demoUser{}
	for _, id := range []string{"user:rahul-assistant", "user:finance-lead", "user:sec-lead-1", "user:sec-lead-2"} {
		password, err := randomHex()
		if err != nil {
			return err
		}
		principal := api.Principal{TenantID: tenant, ActorID: id}
		if err = api.ProvisionUser(ctx, pool, principal, password); err != nil {
			return err
		}
		ticket, err := api.ProvisionCredentialAuthorization(ctx, pool, principal, "enroll", "", time.Hour)
		if err != nil {
			return err
		}
		users = append(users, demoUser{Actor: id, Password: password, Enrollment: ticket})
	}
	if err = writeJSON(filepath.Join(operator, "users.json"), map[string]any{"tenant_id": tenant, "origin": "https://localhost:8444", "users": users}); err != nil {
		return err
	}
	if err = refreshCapability(root); err != nil {
		return err
	}
	return writeJSON(marker, map[string]any{"genesis_digest": genesis.GenesisDigest.String(), "created_at": time.Now().UTC(), "policy_scope": "read-only operator bootstrap; live governance remains outside prototype"})
}

func refreshCapability(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "edge", "signing.key"))
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(string(raw))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("persistent connector key unavailable")
	}
	coreRaw, err := os.ReadFile(filepath.Join(root, "core", "signing.key"))
	if err != nil {
		return err
	}
	coreKey, err := hex.DecodeString(string(coreRaw))
	if err != nil || len(coreKey) != ed25519.PrivateKeySize {
		return errors.New("persistent core key unavailable")
	}
	var config struct {
		Tenants []struct {
			Genesis string `json:"genesis_digest"`
		} `json:"tenants"`
	}
	configRaw, err := os.ReadFile(filepath.Join(root, "core", "console.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(configRaw, &config); err != nil {
		return err
	}
	if len(config.Tenants) != 1 || config.Tenants[0].Genesis == "" {
		return errors.New("pinned genesis unavailable")
	}
	if err = writeJSON(filepath.Join(root, "core", "identity.json"), map[string]string{"core_public_key": hex.EncodeToString(ed25519.PrivateKey(coreKey).Public().(ed25519.PublicKey)), "connector_public_key": hex.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)), "genesis_digest": config.Tenants[0].Genesis}); err != nil {
		return err
	}
	capability := workflow.Capability{
		Tenant:              tenant,
		Connector:           connectorID,
		Protocol:            "RATCHET_EXEC_V1",
		Expires:             time.Now().UTC().Add(23 * time.Hour),
		BoundCommands:       true,
		AtomicPreconditions: true,
		DurableDedup:        true,
		IndependentReadBack: true,
		ScheduledRevocation: true,
		ProvenReductions:    true,
	}
	digest, err := canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{"RATCHET_EXEC_CAPABILITY_V1", capability})
	if err != nil {
		return err
	}
	capability.Signature = ed25519.Sign(ed25519.PrivateKey(key), digest[:])
	return writeJSON(filepath.Join(root, "core", "capability.json"), capability)
}
