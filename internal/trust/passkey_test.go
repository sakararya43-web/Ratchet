package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/passkeyevidence"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func nativeAuthoritySignature(t *testing.T, key *ecdsa.PrivateKey, member AuthorityMember, digest ports.Digest) MemberSignature {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	challenge := passkeyevidence.Challenge("tenant-native", member.ActorID, digest, nonce)
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": member.Origins[0], "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 37)
	rp := sha256.Sum256([]byte(member.RPID))
	copy(auth, rp[:])
	auth[32] = 5
	clientHash := sha256.Sum256(client)
	signed := sha256.Sum256(append(append([]byte(nil), auth...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	return MemberSignature{ActorID: member.ActorID, CredentialID: member.CredentialID, ClientDataJSON: client, AuthenticatorData: auth, ChallengeNonce: nonce, Signature: signature}
}

func TestAuthorityNativePasskeyQuorumAndDomainBinding(t *testing.T) {
	keys := []*ecdsa.PrivateKey{}
	members := []AuthorityMember{}
	for _, actor := range []string{"alice", "bob"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		members = append(members, AuthorityMember{ActorID: actor, IsActive: true, PublicKey: public, CredentialID: []byte("native-" + actor), RPID: "localhost", Origins: []string{"https://localhost:8444"}})
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.InitGenesis("tenant-native", 2, 2, members); err != nil {
		t.Fatal(err)
	}
	bundle, err := store.ProposeBundle("tenant-native", "1.0.0", "native review", map[string]string{"main.rego": "package example"}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	digest := ports.Digest(ComputePolicySigningDigest(bundle.TenantID, bundle.Epoch, bundle.BundleDigest))
	first := nativeAuthoritySignature(t, keys[0], members[0], digest)
	bad := first
	bad.AuthenticatorData = append([]byte(nil), first.AuthenticatorData...)
	bad.AuthenticatorData[32] = 1
	if store.SignProposal(bundle.ProposalID, bad) == nil {
		t.Fatal("accepted no-UV evidence")
	}
	bad = first
	bad.ClientDataJSON = []byte(`{"type":"webauthn.get","origin":"https://evil.example","challenge":"bad"}`)
	if store.SignProposal(bundle.ProposalID, bad) == nil {
		t.Fatal("accepted wrong-origin evidence")
	}
	if err = store.SignProposal(bundle.ProposalID, first); err != nil {
		t.Fatal(err)
	}
	if store.SignProposal(bundle.ProposalID, first) == nil {
		t.Fatal("counted same human twice")
	}
	if _, err = store.ActivateBundle(bundle.ProposalID); err == nil {
		t.Fatal("activated without quorum")
	}
	second := nativeAuthoritySignature(t, keys[1], members[1], digest)
	if err = store.SignProposal(bundle.ProposalID, second); err != nil {
		t.Fatal(err)
	}
	active, err := store.ActivateBundle(bundle.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewBundleVerifier(store).Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	rotation, err := store.ProposeRegistryChange("tenant-native", 1, 2, members)
	if err != nil {
		t.Fatal(err)
	}
	if store.SignRegistryProposal(rotation.ProposalID, first) == nil {
		t.Fatal("replayed policy assertion as registry authorization")
	}
	registryDigest := ports.Digest(ComputeRegistrySigningDigest("tenant-native", 1, 2, rotation.ProposalDigest))
	if err = store.SignRegistryProposal(rotation.ProposalID, nativeAuthoritySignature(t, keys[0], members[0], registryDigest)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActivateRegistryProposal(rotation.ProposalID); err == nil {
		t.Fatal("used proposed weaker quorum to authorize itself")
	}
	if err = store.SignRegistryProposal(rotation.ProposalID, nativeAuthoritySignature(t, keys[1], members[1], registryDigest)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActivateRegistryProposal(rotation.ProposalID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActivateBundle(bundle.ProposalID); err == nil {
		t.Fatal("reactivated old epoch policy")
	}
}
