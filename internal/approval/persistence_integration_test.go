//go:build integration

package approval_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestRealWebAuthnCeremoniesPersistAndBindAuthenticatedOwner(t *testing.T) {
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
	admin, err := pgxpool.New(ctx, os.Getenv("RATCHET_MIGRATION_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	tenant := "passkey_" + uuid.NewString()
	password := "Long real test password for passkey sessions"
	for _, actor := range []string{"owner", "other"} {
		if err := api.ProvisionUser(ctx, admin, api.Principal{TenantID: tenant, ActorID: actor}, password); err != nil {
			t.Fatal(err)
		}
	}
	credentials, err := approval.NewPersistentCredentialStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Close()
	sessions, err := api.NewSessions(pool, "https://console.test", bytes.Repeat([]byte{4}, 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", sessions.Routes()))
	factory := approval.MakePasskeyHandlerFactory(credentials, "console.test", []string{"https://console.test"})
	mux.Handle("/passkeys/", sessions.Require(http.StripPrefix("/passkeys", factory(ports.PasskeyDeps{SessionAPI: sessions}))))
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	post := func(client *http.Client, path, csrf string, in any, out any) int {
		t.Helper()
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", server.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", "https://console.test")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err = io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if out != nil && response.StatusCode == 200 {
			if err := json.Unmarshal(raw, out); err != nil {
				t.Fatalf("response decode: %v %s", err, raw)
			}
		}
		return response.StatusCode
	}
	login := func(actor string) (*http.Client, string) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: server.Client().Transport, Jar: jar, Timeout: 5 * time.Second}
		var result struct {
			CSRF string `json:"csrf_token"`
		}
		if status := post(client, "/auth/login", "", map[string]string{"tenant_id": tenant, "actor_id": actor, "password": password}, &result); status != 200 {
			t.Fatal("password login", status)
		}
		return client, result.CSRF
	}
	owner, csrf := login("owner")
	other, otherCSRF := login("other")
	var begin struct {
		Session string `json:"session_id"`
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if status := post(owner, "/passkeys/register/begin", csrf, approval.RegisterBeginRequest{TenantID: tenant, ActorID: "other"}, nil); status != 403 {
		t.Fatal("forged registration owner", status)
	}
	if status := post(owner, "/passkeys/register/begin", csrf, approval.RegisterBeginRequest{}, &begin); status != 200 {
		t.Fatal("real registration begin", status)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("console.test"))
	auth := make([]byte, 37)
	copy(auth, rp[:])
	auth[32] = 0x45
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id)))
	auth = append(auth, id...)
	auth = append(auth, cose...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		t.Fatal(err)
	}
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.create", "origin": "https://console.test", "challenge": begin.Options.PublicKey.Challenge})
	b64 := base64.RawURLEncoding.EncodeToString
	registration := map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(clientData), "attestationObject": b64(attestation)}, "clientExtensionResults": map[string]any{}}
	finish := "/passkeys/register/finish?session_id=" + begin.Session
	if status := post(other, finish, otherCSRF, registration, nil); status != 400 {
		t.Fatal("another session consumed registration", status)
	}
	if status := post(owner, finish, csrf, registration, nil); status != 200 {
		t.Fatal("real WebAuthn registration finish", status)
	}
	if status := post(owner, finish, csrf, registration, nil); status != 400 {
		t.Fatal("registration replay", status)
	}
	var assertionBegin struct {
		Session string `json:"session_id"`
		Nonce   string `json:"challenge_nonce"`
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	digest := ports.Digest{9}
	if status := post(owner, "/passkeys/assert/begin", csrf, approval.AssertBeginRequest{ChangeDigest: digest.String()}, &assertionBegin); status != 200 {
		t.Fatal("real assertion begin", status)
	}
	clientData, _ = json.Marshal(map[string]string{"type": "webauthn.get", "origin": "https://console.test", "challenge": assertionBegin.Options.PublicKey.Challenge})
	auth = make([]byte, 37)
	copy(auth, rp[:])
	auth[32] = 5
	hash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), auth...), hash[:]...)
	signedHash := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	in := approval.AssertFinishRequest{SessionID: assertionBegin.Session, CredentialID: hex.EncodeToString(id), ClientDataJSON: base64.StdEncoding.EncodeToString(clientData), AuthenticatorData: base64.StdEncoding.EncodeToString(auth), Signature: base64.StdEncoding.EncodeToString(signature)}
	if status := post(other, "/passkeys/assert/finish", otherCSRF, in, nil); status != 400 {
		t.Fatal("another actor consumed assertion", status)
	}
	var result struct {
		Verified   bool                     `json:"verified"`
		Submission ports.ApprovalSubmission `json:"submission"`
	}
	if status := post(owner, "/passkeys/assert/finish", csrf, in, &result); status != 200 || !result.Verified {
		t.Fatal("real assertion verification", status)
	}
	if status := post(owner, "/passkeys/assert/finish", csrf, in, nil); status != 400 {
		t.Fatal("assertion replay", status)
	}
	restarted, err := approval.NewPersistentCredentialStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	verifier, err := approval.NewApprovalVerifier(restarted, "console.test", []string{"https://console.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, result.Submission, digest); err != nil {
		t.Fatal("restart lost enrolled credential", err)
	}
	if err := restarted.RevokeCredential(tenant, "owner", id); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, result.Submission, digest); err == nil {
		t.Fatal("revoked credential still verifies")
	}
	user, err := credentials.User(ctx, tenant, "owner")
	if err != nil || len(user.Credentials) != 0 {
		t.Fatal("another instance missed revocation", err)
	}
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	if count, _, err := store.VerifyTenant(ctx, tenant); err != nil || count != 2 {
		t.Fatal("credential history not retained atomically", count, err)
	}
}
