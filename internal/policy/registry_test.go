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

	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func governed(t *testing.T) (*trust.Store, ports.Digest, []*ecdsa.PrivateKey, []trust.AuthorityMember) {
	t.Helper()
	store, err := trust.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	keys := []*ecdsa.PrivateKey{}
	members := []trust.AuthorityMember{}
	for _, id := range []string{"first", "second", "replacement"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		members = append(members, trust.AuthorityMember{ActorID: id, PublicKey: pub, IsActive: true})
	}
	g, err := store.InitGenesis("tenant", 2, 2, members[:2])
	if err != nil {
		t.Fatal(err)
	}
	return store, g.GenesisDigest, keys, members
}
func rotation(t *testing.T, store *trust.Store, keys []*ecdsa.PrivateKey, members []trust.AuthorityMember) {
	t.Helper()
	p, err := store.ProposeRegistryChange("tenant", 1, 1, members[2:])
	if err != nil {
		t.Fatal(err)
	}
	digest := trust.ComputeRegistrySigningDigest("tenant", 1, 2, p.ProposalDigest)
	for i := range 2 {
		sig, err := ecdsa.SignASN1(rand.Reader, keys[i], digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SignRegistryProposal(p.ProposalID, trust.MemberSignature{ActorID: members[i].ActorID, Signature: sig}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, err := store.ActivateRegistryProposal(p.ProposalID); err == nil {
				t.Fatal("new lower threshold authorized itself")
			}
		}
	}
	if _, err := store.ActivateRegistryProposal(p.ProposalID); err != nil {
		t.Fatal(err)
	}
}
func TestVerifiedRotationUsesPriorQuorumAndRejectsInventedHistory(t *testing.T) {
	store, root, keys, members := governed(t)
	first, err := policy.RegistryFromStore(store, root, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	rotation(t, store, keys, members)
	current, err := policy.RegistryFromStore(store, root, "tenant")
	if err != nil || current.Epoch != 2 || current.Digest == first.Digest {
		t.Fatal("valid rotation", err)
	}
	for _, name := range []string{"missing-quorum", "duplicate-signer", "changed-threshold", "gap", "forged-genesis"} {
		t.Run(name, func(t *testing.T) {
			var proof policy.RegistryProof
			if err := json.Unmarshal(current.Proof, &proof); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing-quorum":
				proof.Rotations[0].Signatures = proof.Rotations[0].Signatures[:1]
			case "duplicate-signer":
				proof.Rotations[0].Signatures[1] = proof.Rotations[0].Signatures[0]
			case "changed-threshold":
				proof.Rotations[0].ProposedM = 2
			case "gap":
				proof.Rotations[0].TargetEpoch = 3
			case "forged-genesis":
				proof.Genesis.Members[0].PublicKey = members[2].PublicKey
			}
			raw, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policy.VerifyRegistry(raw, root, "tenant"); err == nil {
				t.Fatal("unproved registry accepted")
			}
		})
	}
	if _, err := policy.VerifyRegistry(current.Proof, root, "different-tenant"); err == nil {
		t.Fatal("cross-tenant root")
	}
	engine := policy.NewEngine()
	if err := engine.PublishRegistry("tenant", current); err != nil {
		t.Fatal(err)
	}
	if engine.PublishRegistry("tenant", first) == nil {
		t.Fatal("registry rollback")
	}
}

func TestRotatedBundleAndOfflineHistoricalVerification(t *testing.T) {
	store, root, keys, members := governed(t)
	modules := map[string]string{}
	for _, name := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile("../../policies/" + name)
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = string(raw)
	}
	bundle, err := store.ProposeBundle("tenant", "1.0.0", "before rotation", modules, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	d := trust.ComputePolicySigningDigest("tenant", 1, bundle.BundleDigest)
	for i := range 2 {
		sig, err := ecdsa.SignASN1(rand.Reader, keys[i], d[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: members[i].ActorID, Signature: sig}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	old, err := policy.Prepare(context.Background(), store, root, "tenant", raw)
	if err != nil {
		t.Fatal(err)
	}
	rotation(t, store, keys, members)
	if _, err := policy.Prepare(context.Background(), store, root, "tenant", raw); err == nil {
		t.Fatal("old-epoch bundle activated")
	}
	if _, err := policy.PrepareHistorical(context.Background(), old.TrustProof, root, "tenant", raw); err != nil {
		t.Fatal("offline historical replay", err)
	}
	newBundle, err := store.ProposeBundle("tenant", "1.1.0", "after rotation", modules, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	d = trust.ComputePolicySigningDigest("tenant", 2, newBundle.BundleDigest)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[2], d[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SignProposal(newBundle.ProposalID, trust.MemberSignature{ActorID: members[2].ActorID, Signature: sig}); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(newBundle)
	if err != nil {
		t.Fatal(err)
	}
	a, err := policy.Prepare(context.Background(), store, root, "tenant", raw)
	if err != nil || a.RegistryEpoch != 2 {
		t.Fatal(err)
	}
	engine := policy.NewEngine()
	r, err := policy.RegistryFromStore(store, root, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.PublishRegistry("tenant", r); err != nil {
		t.Fatal(err)
	}
	if engine.Publish("tenant", old) == nil {
		t.Fatal("old policy published over new registry")
	}
	if err := engine.Publish("tenant", a); err != nil {
		t.Fatal(err)
	}
}
