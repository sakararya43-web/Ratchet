//go:build peerintegration

package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestPeerApprovalVerifierAndSessionFactoryConformance(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := ports.Digest{9}
	assertion := func(origin, rp, kind string, public []byte) (*approval.CredentialStore, ports.ApprovalSubmission) {
		store := approval.NewCredentialStore()
		if err := store.SaveCredential("tenant", "actor", "conformance", &webauthn.Credential{ID: []byte("credential"), PublicKey: public}); err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		challenge := approval.ComputeApprovalChallenge("tenant", "actor", digest, nonce)
		client, err := json.Marshal(map[string]string{"type": kind, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin})
		if err != nil {
			t.Fatal(err)
		}
		rpHash := sha256.Sum256([]byte(rp))
		auth := make([]byte, 37)
		copy(auth, rpHash[:])
		auth[32] = 5
		clientHash := sha256.Sum256(client)
		signed := append(append([]byte(nil), auth...), clientHash[:]...)
		hash := sha256.Sum256(signed)
		signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		store.SaveSession("tenant", "actor", digest.String(), nonce, &webauthn.SessionData{Challenge: base64.RawURLEncoding.EncodeToString(challenge)})
		return store, ports.ApprovalSubmission{TenantID: "tenant", ActorID: "actor", CredentialID: []byte("credential"), ClientDataJSON: client, AuthenticatorData: auth, Signature: signature, ChallengeNonce: nonce}
	}
	for _, tc := range []struct{ name, origin, rp, kind string }{{"wrong-origin", "https://evil.test", "console.test", "webauthn.get"}, {"wrong-rp", "https://console.test", "evil.test", "webauthn.get"}, {"wrong-ceremony", "https://console.test", "console.test", "webauthn.create"}} {
		t.Run(tc.name, func(t *testing.T) {
			store, sub := assertion(tc.origin, tc.rp, tc.kind, der)
			verifier, err := approval.NewApprovalVerifier(store, "console.test", []string{"https://console.test"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(context.Background(), sub, digest); err == nil {
				t.Fatal("invalid WebAuthn context accepted")
			}
		})
	}
	t.Run("normal-WebAuthn-COSE-key", func(t *testing.T) {
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			t.Fatal(err)
		}
		store, sub := assertion("https://console.test", "console.test", "webauthn.get", cose)
		verifier, err := approval.NewApprovalVerifier(store, "console.test", []string{"https://console.test"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), sub, digest); err != nil {
			t.Fatalf("normal enrolled COSE public key cannot be verified: %v", err)
		}
	})
	t.Run("sessionless-factory", func(t *testing.T) {
		store := approval.NewCredentialStore()
		factory := approval.MakePasskeyHandlerFactory(store, "console.test", []string{"https://console.test"})
		handler := factory(ports.PasskeyDeps{RPID: "console.test", RPOrigins: []string{"https://console.test"}})
		request := httptest.NewRequest(http.MethodGet, "https://console.test/list?tenant_id=tenant&actor_id=actor", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated credential management returned %d", response.Code)
		}
	})
}
