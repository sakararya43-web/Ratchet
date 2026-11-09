package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/authority"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// initializeLive never creates a software Authority signing key or a substitute
// signed bundle. Users first enroll their actual browser passkeys; the operator
// pins the resulting independent genesis only after its first quorum policy.
func initializeLive(ctx context.Context, pool *pgxpool.Pool, root, policyDir, costFile string) error {
	core, edge, operator, authorityDir := filepath.Join(root, "core"), filepath.Join(root, "edge"), filepath.Join(root, "operator"), filepath.Join(root, "authority")
	marker := filepath.Join(operator, "live-initialized.json")
	if _, err := os.Stat(marker); err == nil {
		var config map[string]any
		if err = readJSON(filepath.Join(core, "console.json"), &config); err != nil {
			return err
		}
		first, err := liveTenant(config)
		if err != nil {
			return err
		}
		if digest, _ := first["genesis_digest"].(string); digest != "" {
			return refreshCapability(root)
		}
		return nil
	}
	if _, err := os.Stat(filepath.Join(core, "console.json")); err == nil {
		return errors.New("existing or partial root configuration; live genesis requires a fresh preserved profile")
	}
	var costs map[string]int64
	if costFile == "" || readJSON(costFile, &costs) != nil || graph.ValidateRevocationCosts(costs) != nil {
		return errors.New("explicit validated operator containment costs required")
	}
	for _, directory := range []string{core, edge, operator, authorityDir} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
	}
	corePublic, coreKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	edgePublic, edgeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	for path, raw := range map[string][]byte{filepath.Join(core, "signing.key"): []byte(hex.EncodeToString(coreKey)), filepath.Join(edge, "signing.key"): []byte(hex.EncodeToString(edgeKey)), filepath.Join(edge, "core.pub"): []byte(hex.EncodeToString(corePublic))} {
		if err = privateFile(path, raw); err != nil {
			return err
		}
	}
	if _, err = os.Stat(filepath.Join(core, "server.pem")); err == nil {
		if _, err = tls.LoadX509KeyPair(filepath.Join(core, "server.pem"), filepath.Join(core, "server.key")); err != nil {
			return err
		}
	} else if err = certificateFiles(core); err != nil {
		return err
	}
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
	actors := []string{"user:sec-lead-1", "user:sec-lead-2"}
	console := map[string]any{"serve_web": true, "origin": "https://localhost:8444", "session_key_hex": sessionKey, "graph_key_hex": graphKey, "cursor_key_hex": cursorKey, "server_cert": "/data/core/server.pem", "server_key": "/data/core/server.key", "nats_url": "nats://127.0.0.1:4222", "authority_bootstrap_actors": actors, "containment_costs": costs, "tenants": []any{map[string]any{"tenant_id": tenant, "authority_url": "http://127.0.0.1:8446", "authority_file": "/data/authority/public/authority.json", "bundle_file": "/data/authority/public/bundle.json", "execution": map[string]string{"connector_id": connectorID, "connector_public_key_hex": hex.EncodeToString(edgePublic), "core_signing_key_file": "/data/core/signing.key", "capability_file": "/data/core/capability.json"}}}}
	graphConfig := map[string]any{"graph_key_hex": graphKey, "cursor_key_hex": cursorKey, "server_cert": "/data/core/server.pem", "server_key": "/data/core/server.key", "client_ca": "/data/core/ca.pem", "nats_url": "nats://127.0.0.1:4222", "readers": map[string]any{"prototype-operator": map[string]string{"tenant_id": tenant, "actor_id": actors[0]}}, "connectors": []any{map[string]string{"tenant_id": tenant, "connector_id": connectorID, "public_key_hex": hex.EncodeToString(edgePublic)}}}
	if err = writeJSON(filepath.Join(core, "console.json"), console); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(core, "graph.json"), graphConfig); err != nil {
		return err
	}
	config := struct {
		Bootstrap       authority.Bootstrap `json:"bootstrap"`
		ExportDirectory string              `json:"export_directory"`
	}{authority.Bootstrap{Tenant: tenant, Actors: actors, Threshold: 2, RPID: "localhost", Origin: "https://localhost:8444", CorePublic: corePublic}, "/data/authority/public"}
	if err = writeJSON(filepath.Join(authorityDir, "config.json"), config); err != nil {
		return err
	}
	modules := map[string]string{}
	for _, name := range []string{"authz.rego", "change.rego"} {
		raw, e := os.ReadFile(filepath.Join(policyDir, name))
		if e != nil {
			return e
		}
		modules[name] = string(raw)
	}
	if err = writeJSON(filepath.Join(operator, "initial-policy.json"), map[string]any{"version": "1.0.0", "description": "Independent Authority initial policy", "modules": modules, "data": map[string]any{"resource_owners": map[string]any{"res:finance-reports": []string{"user:finance-lead"}, "res:daily-exchange-ledger": []string{"user:finance-lead"}, "svc:wallet-signer": actors}}}); err != nil {
		return err
	}
	users := []demoUser{}
	for _, id := range []string{"user:rahul-assistant", "user:finance-lead", actors[0], actors[1]} {
		password, e := randomHex()
		if e != nil {
			return e
		}
		principal := api.Principal{TenantID: tenant, ActorID: id}
		if e = api.ProvisionUser(ctx, pool, principal, password); e != nil {
			return e
		}
		ticket, e := api.ProvisionCredentialAuthorization(ctx, pool, principal, "enroll", "", time.Hour)
		if e != nil {
			return e
		}
		users = append(users, demoUser{Actor: id, Password: password, Enrollment: ticket})
	}
	if err = writeJSON(filepath.Join(operator, "users.json"), map[string]any{"tenant_id": tenant, "origin": "https://localhost:8444", "users": users}); err != nil {
		return err
	}
	return writeJSON(marker, map[string]any{"mode": "LIVE_AUTHORITY_ENROLLMENT", "created_at": time.Now().UTC()})
}

func readJSON(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func liveTenant(config map[string]any) (map[string]any, error) {
	tenants, ok := config["tenants"].([]any)
	if !ok || len(tenants) != 1 {
		return nil, errors.New("one live tenant required")
	}
	first, ok := tenants[0].(map[string]any)
	if !ok || first["tenant_id"] != tenant {
		return nil, errors.New("invalid live tenant configuration")
	}
	return first, nil
}

func finalizeLive(ctx context.Context, pool *pgxpool.Pool, root string) error {
	core, operator := filepath.Join(root, "core"), filepath.Join(root, "operator")
	if _, err := os.Stat(filepath.Join(operator, "live-initialized.json")); err != nil {
		return errors.New("explicit live enrollment profile required")
	}
	store, err := trust.NewStore(filepath.Join(root, "authority", "public", "authority.json"))
	if err != nil {
		return err
	}
	genesis, err := store.GetGenesis()
	if err != nil || genesis.TenantID != tenant {
		return errors.New("verified Authority genesis unavailable")
	}
	for _, member := range genesis.Members {
		if len(member.CredentialID) == 0 || member.RPID != "localhost" || len(member.Origins) != 1 || member.Origins[0] != "https://localhost:8444" {
			return errors.New("native passkey Authority genesis required")
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "authority", "public", "bundle.json"))
	if err != nil {
		return err
	}
	if _, err = policy.Prepare(ctx, store, genesis.GenesisDigest, tenant, raw); err != nil {
		return err
	}
	var config map[string]any
	if err = readJSON(filepath.Join(core, "console.json"), &config); err != nil {
		return err
	}
	first, err := liveTenant(config)
	if err != nil {
		return err
	}
	if prior, _ := first["genesis_digest"].(string); prior != "" && prior != genesis.GenesisDigest.String() {
		return errors.New("refusing to replace pinned genesis")
	}
	if first["genesis_digest"] == nil || first["genesis_digest"] == "" {
		// The first operator pin cross-checks the independent genesis against
		// actual active enrollment. Later restarts preserve the historical root;
		// rotation or revocation must never silently replace it.
		if genesis.Epoch != 1 {
			return errors.New("first pin requires the original enrollment epoch")
		}
		credentials, err := approval.NewPersistentCredentialStore(pool)
		if err != nil {
			return err
		}
		defer credentials.Close()
		for _, member := range genesis.Members {
			user, err := credentials.User(ctx, tenant, member.ActorID)
			if err != nil {
				return err
			}
			found := false
			for _, key := range user.Credentials {
				found = found || (slices.Equal(key.ID, member.CredentialID) && slices.Equal(key.PublicKey, member.PublicKey))
			}
			if !found {
				return errors.New("genesis member does not match active native enrollment")
			}
		}
	}
	first["genesis_digest"] = genesis.GenesisDigest.String()
	if err = connector.WritePrivateJSON(filepath.Join(core, "console.json"), config); err != nil {
		return err
	}
	return refreshCapability(root)
}
