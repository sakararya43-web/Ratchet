//go:build integration

package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/passkeyevidence"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func nativeProof(t *testing.T, key *ecdsa.PrivateKey, member trust.AuthorityMember, digest ports.Digest) ports.ApprovalSubmission {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	challenge := passkeyevidence.Challenge("authority-test", member.ActorID, digest, nonce)
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": member.Origins[0], "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 37)
	rp := sha256.Sum256([]byte(member.RPID))
	copy(auth, rp[:])
	auth[32] = 5
	clientHash := sha256.Sum256(client)
	message := sha256.Sum256(append(append([]byte(nil), auth...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, message[:])
	if err != nil {
		t.Fatal(err)
	}
	return ports.ApprovalSubmission{TenantID: "authority-test", ActorID: member.ActorID, CredentialID: member.CredentialID, ClientDataJSON: client, AuthenticatorData: auth, Signature: signature, ChallengeNonce: nonce}
}

func TestIndependentAuthorityNativeGovernanceAndRestart(t *testing.T) {
	if os.Getenv("RATCHET_AUTHORITY_DSN") == "" {
		t.Skip("dedicated independent database acceptance runs via scripts/core-authority-check.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, os.Getenv("RATCHET_AUTHORITY_MIGRATION_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if !strings.HasPrefix(admin.Config().ConnConfig.Database, "ratchet_authority_test_") {
		t.Fatal("owned scratch Authority database required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := Bootstrap{Tenant: "authority-test", Actors: []string{"alice", "bob"}, Threshold: 2, RPID: "localhost", Origin: "https://localhost:8444", CorePublic: public}
	if err = Initialize(ctx, admin, bootstrap); err != nil {
		t.Fatal(err)
	}
	changed := bootstrap
	changed.Threshold = 1
	if Initialize(ctx, admin, changed) == nil {
		t.Fatal("silently changed bootstrap threshold")
	}
	runtimePool, err := pgxpool.New(ctx, os.Getenv("RATCHET_AUTHORITY_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	service, err := Open(ctx, runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	if Initialize(ctx, runtimePool, bootstrap) == nil {
		t.Fatal("runtime initialized Authority")
	}
	server := httptest.NewServer(service.Handler())
	defer server.Close()
	client, err := NewClient(server.URL, bootstrap.Tenant, private)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(server.URL + "/v1/state")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("public Authority access", response.StatusCode)
	}
	keys := map[string]*ecdsa.PrivateKey{}
	members := map[string]trust.AuthorityMember{}
	for _, actor := range []string{"alice", "bob", "carol"} {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		encoded, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		keys[actor] = key
		members[actor] = trust.AuthorityMember{ActorID: actor, PublicKey: encoded, IsActive: true, CredentialID: []byte("credential-" + actor), RPID: bootstrap.RPID, Origins: []string{bootstrap.Origin}}
	}
	apply := func(actor string, input Input) State {
		t.Helper()
		var preview Preview
		if e := client.Do(ctx, actor, "/v1/prepare", &input, &preview); e != nil {
			t.Fatal(actor, input.Operation, e)
		}
		input.Proof = nativeProof(t, keys[actor], members[actor], preview.Digest)
		var state State
		if e := client.Do(ctx, actor, "/v1/apply", &input, &state); e != nil {
			t.Fatal(actor, input.Operation, e)
		}
		var retry State
		if e := client.Do(ctx, actor, "/v1/apply", &input, &retry); e != nil {
			t.Fatal("exact retry", e)
		}
		return state
	}
	carol := members["carol"]
	if _, err = service.Prepare(ctx, "carol", Input{ID: uuid.NewString(), Operation: "enroll", Member: &carol}); err == nil {
		t.Fatal("uninvited bootstrap member")
	}
	for _, actor := range bootstrap.Actors {
		member := members[actor]
		apply(actor, Input{ID: uuid.NewString(), Operation: "enroll", Member: &member})
	}
	state, err := service.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store, err := trust.Import(state.Authority)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := store.GetGenesis()
	if err != nil {
		t.Fatal(err)
	}
	root := genesis.GenesisDigest
	modules := map[string]string{}
	for _, name := range []string{"authz.rego", "change.rego"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "policies", name))
		if e != nil {
			t.Fatal(e)
		}
		modules[name] = string(raw)
	}
	state = apply("alice", Input{ID: uuid.NewString(), Operation: "bundle_propose", Epoch: 1, Version: "1.0.0", Description: "native governed policy", Modules: modules, Data: map[string]any{}})
	store, _ = trust.Import(state.Authority)
	proposal := store.ListProposals()[0]
	var prepared Preview
	if err = client.Do(ctx, "carol", "/v1/prepare", &Input{ID: uuid.NewString(), Operation: "bundle_sign", Epoch: 1, Proposal: proposal.ProposalID}, &prepared); err == nil {
		t.Fatal("candidate signed without current membership")
	}
	apply("alice", Input{ID: uuid.NewString(), Operation: "bundle_sign", Epoch: 1, Proposal: proposal.ProposalID})
	activation := Input{ID: uuid.NewString(), Operation: "bundle_activate", Epoch: 1, Proposal: proposal.ProposalID}
	preview, err := service.Prepare(ctx, "alice", activation)
	if err != nil {
		t.Fatal(err)
	}
	activation.Proof = nativeProof(t, keys["alice"], members["alice"], preview.Digest)
	if _, err = service.Apply(ctx, "alice", activation); err == nil {
		t.Fatal("activated without distinct member quorum")
	}
	apply("bob", Input{ID: uuid.NewString(), Operation: "bundle_sign", Epoch: 1, Proposal: proposal.ProposalID})
	state = apply("alice", Input{ID: uuid.NewString(), Operation: "bundle_activate", Epoch: 1, Proposal: proposal.ProposalID})
	store, _ = trust.Import(state.Authority)
	active, err := store.GetActiveBundle()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(active)
	if _, err = trust.NewBundleVerifier(store).Verify(ctx, raw); err != nil {
		t.Fatal(err)
	}
	// Enrollment alone grants no Authority vote. Current quorum must approve the
	// explicit removal, addition and threshold transition.
	member := members["carol"]
	state = apply("carol", Input{ID: uuid.NewString(), Operation: "enroll", Epoch: 1, Member: &member})
	if len(state.Candidates) != 1 || state.Candidates["carol"].ActorID != "carol" {
		t.Fatal("candidate received other members' enrollment data")
	}
	if err = client.Do(ctx, "alice", "/v1/state", nil, &state); err != nil {
		t.Fatal(err)
	}
	newMembers := []trust.AuthorityMember{state.Candidates["alice"], state.Candidates["carol"]}
	state = apply("alice", Input{ID: uuid.NewString(), Operation: "registry_propose", Epoch: 1, Members: newMembers, Threshold: 1})
	store, _ = trust.Import(state.Authority)
	rotation := store.ListRegistryProposals()[0]
	apply("alice", Input{ID: uuid.NewString(), Operation: "registry_sign", Epoch: 1, Proposal: rotation.ProposalID})
	state = apply("bob", Input{ID: uuid.NewString(), Operation: "registry_sign", Epoch: 1, Proposal: rotation.ProposalID})
	state = apply("alice", Input{ID: uuid.NewString(), Operation: "registry_activate", Epoch: 1, Proposal: rotation.ProposalID})
	store, _ = trust.Import(state.Authority)
	genesis, err = store.GetGenesis()
	if err != nil || genesis.Epoch != 2 || genesis.GenesisDigest != root {
		t.Fatal("registry did not preserve root", err)
	}
	if _, err = service.Prepare(ctx, "bob", Input{ID: uuid.NewString(), Operation: "bundle_propose", Epoch: 2}); err == nil {
		t.Fatal("removed member retained authority")
	}
	if _, err = service.Prepare(ctx, "alice", Input{ID: uuid.NewString(), Operation: "bundle_propose", Epoch: 1}); err == nil {
		t.Fatal("accepted stale epoch")
	}
	service, err = Open(ctx, runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	export := t.TempDir()
	if err = service.ExportFiles(ctx, export); err != nil {
		t.Fatal(err)
	}
	if _, err = trust.NewStore(filepath.Join(export, "authority.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = runtimePool.Exec(ctx, "UPDATE authority.events SET actor='forged'"); err == nil {
		t.Fatal("runtime rewrote immutable history")
	}
	if _, err = runtimePool.Exec(ctx, "DELETE FROM authority.settings"); err == nil {
		t.Fatal("runtime removed bootstrap pins")
	}
	if _, err = runtimePool.Exec(ctx, `UPDATE authority.state SET document='{}'`); err != nil {
		t.Fatal(err)
	}
	if _, err = service.State(ctx); err == nil {
		t.Fatal("trusted mutable head inconsistent with retained events")
	}
}
