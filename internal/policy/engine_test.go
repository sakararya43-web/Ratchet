package policy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func signed(t *testing.T, extra string) (*trust.Store, ports.Digest, []byte) {
	t.Helper()
	store, err := trust.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := store.InitGenesis("tenant", 1, 1, []trust.AuthorityMember{{ActorID: "leader", PublicKey: pub, IsActive: true}})
	if err != nil {
		t.Fatal(err)
	}
	modules := map[string]string{}
	for _, file := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile("../../policies/" + file)
		if err != nil {
			t.Fatal(err)
		}
		modules[file] = string(raw)
	}
	if extra != "" {
		modules["extra.rego"] = extra
	}
	bundle, err := store.ProposeBundle("tenant", "1.0.0", "demo policy", modules, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	digest := trust.ComputePolicySigningDigest("tenant", 1, bundle.BundleDigest)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "leader", Signature: sig}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return store, genesis.GenesisDigest, raw
}
func TestSignedPreparedPolicyDecisionsAndAuthorization(t *testing.T) {
	store, root, raw := signed(t, "")
	a, err := policy.Prepare(context.Background(), store, root, "tenant", raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		facts   policy.Facts
		outcome string
		quorum  int
	}{
		{policy.Facts{}, "HOLD", 0},
		{policy.Facts{Complete: true, Tier0Weakening: true}, "REJECT", 0},
		{policy.Facts{Complete: true, Reduction: true, Responder: true}, "ALLOW", 0},
		{policy.Facts{Complete: true, NewTier0: true}, "REQUIRE_APPROVAL", 2},
		{policy.Facts{Complete: true, Owners: []string{"owner"}}, "REQUIRE_APPROVAL", 1},
		{policy.Facts{Complete: true, Owners: []string{"owner"}, Intent: domain.Intent{Emergency: true}}, "HOLD", 0},
	} {
		d, err := a.Decision(context.Background(), tc.facts)
		if err != nil || d.Outcome != tc.outcome || d.Quorum != tc.quorum {
			t.Fatalf("%+v: %+v %v", tc.facts, d, err)
		}
	}
	if a.Authorize(context.Background(), policy.Facts{Actor: "stranger", Operation: "approve"}) == nil {
		t.Fatal("arbitrary actor approval authorization")
	}
	if err := a.Authorize(context.Background(), policy.Facts{Actor: "owner", Operation: "approve", Owners: []string{"owner"}}); err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine()
	if err := engine.Publish("tenant", a); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if _, err := policy.Prepare(context.Background(), store, root, "tenant", raw); err == nil {
		t.Fatal("tampered bundle accepted")
	}
	active, err := engine.Current("tenant")
	if err != nil || active.Hash != a.Hash {
		t.Fatal("invalid replacement lost last valid bundle")
	}
	if policy.Newer("1.9.0", "1.10.0") || !policy.Newer("1.10.0", "1.9.0") || policy.Newer("01.1.1", "1.0.0") {
		t.Fatal("unsafe version ordering")
	}
}
func TestPolicyCannotUseNetworkOrWallClockAndRequiresPinnedRoot(t *testing.T) {
	for _, module := range []string{`package unwanted
 value := time.now_ns()`, `package unwanted
 value := http.send({"url":"https://example.com","method":"GET"})`} {
		store, root, raw := signed(t, module)
		if _, err := policy.Prepare(context.Background(), store, root, "tenant", raw); err == nil {
			t.Fatal("nondeterministic builtin accepted")
		}
	}
	store, _, raw := signed(t, "")
	if _, err := policy.Prepare(context.Background(), store, ports.Digest{7}, "tenant", raw); err == nil {
		t.Fatal("wrong genesis pin")
	}
}
