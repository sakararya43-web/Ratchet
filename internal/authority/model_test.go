package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

func TestBootstrapValidation(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	valid := Bootstrap{
		Tenant:     "exchange-demo",
		Actors:     []string{"user:sec1", "user:sec2"},
		Threshold:  2,
		RPID:       "localhost",
		Origin:     "https://localhost:8443",
		CorePublic: pub,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid bootstrap, got: %v", err)
	}

	// Invalid cases
	invalidTenant := valid
	invalidTenant.Tenant = ""
	if err := invalidTenant.Validate(); err == nil {
		t.Fatal("expected error for empty tenant")
	}

	invalidThresholdZero := valid
	invalidThresholdZero.Threshold = 0
	if err := invalidThresholdZero.Validate(); err == nil {
		t.Fatal("expected error for threshold = 0")
	}

	invalidThresholdTooHigh := valid
	invalidThresholdTooHigh.Threshold = 3
	if err := invalidThresholdTooHigh.Validate(); err == nil {
		t.Fatal("expected error for threshold > len(actors)")
	}

	invalidDupActors := valid
	invalidDupActors.Actors = []string{"user:sec1", "user:sec1"}
	if err := invalidDupActors.Validate(); err == nil {
		t.Fatal("expected error for duplicate actors")
	}

	invalidOrigin := valid
	invalidOrigin.Origin = "http://localhost:8443" // must be https://
	if err := invalidOrigin.Validate(); err == nil {
		t.Fatal("expected error for non-https origin")
	}

	invalidKeyLen := valid
	invalidKeyLen.CorePublic = []byte("short-key")
	if err := invalidKeyLen.Validate(); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestInputDigestValidation(t *testing.T) {
	// Nil or invalid command ID
	_, err := InputDigest("exchange-demo", "user:sec1", Input{
		ID:        "invalid-uuid",
		Operation: "bundle_propose",
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}

	cmdID := uuid.New().String()

	// Unsupported operation
	_, err = InputDigest("exchange-demo", "user:sec1", Input{
		ID:        cmdID,
		Operation: "unknown_op",
	}, nil)
	if err == nil {
		t.Fatal("expected error for unknown operation")
	}

	// Supported general action
	digest, err := InputDigest("exchange-demo", "user:sec1", Input{
		ID:        cmdID,
		Operation: "bundle_propose",
		Version:   "1.0.0",
	}, nil)
	if err != nil {
		t.Fatalf("expected valid input digest, got: %v", err)
	}
	if digest.IsZero() {
		t.Fatal("digest must not be zero")
	}
}

func TestValidMembersCheck(t *testing.T) {
	m1 := trust.AuthorityMember{
		ActorID:      "user:sec1",
		CredentialID: []byte("cred-1"),
		PublicKey:    []byte("pk-1"),
		RPID:         "localhost",
		Origins:      []string{"https://localhost:8443"},
		IsActive:     true,
	}
	m2 := trust.AuthorityMember{
		ActorID:      "user:sec2",
		CredentialID: []byte("cred-2"),
		PublicKey:    []byte("pk-2"),
		RPID:         "localhost",
		Origins:      []string{"https://localhost:8443"},
		IsActive:     true,
	}

	candidates := map[string]trust.AuthorityMember{
		"user:sec1": m1,
		"user:sec2": m2,
	}

	// Valid quorum of 2 with 2 members
	if err := validMembers([]trust.AuthorityMember{m1, m2}, 2, candidates); err != nil {
		t.Fatalf("expected valid members, got: %v", err)
	}

	// Threshold higher than active
	if err := validMembers([]trust.AuthorityMember{m1, m2}, 3, candidates); err == nil {
		t.Fatal("expected error when threshold > active count")
	}

	// Duplicate actor
	if err := validMembers([]trust.AuthorityMember{m1, m1}, 1, candidates); err == nil {
		t.Fatal("expected error on duplicate actor")
	}

	// Duplicate credential ID
	m2DupCred := m2
	m2DupCred.CredentialID = m1.CredentialID
	candidatesDup := map[string]trust.AuthorityMember{
		"user:sec1": m1,
		"user:sec2": m2DupCred,
	}
	if err := validMembers([]trust.AuthorityMember{m1, m2DupCred}, 1, candidatesDup); err == nil {
		t.Fatal("expected error on duplicate credential ID")
	}

	// Unknown candidate
	m3Unknown := trust.AuthorityMember{
		ActorID:      "user:sec3",
		CredentialID: []byte("cred-3"),
		IsActive:     true,
	}
	if err := validMembers([]trust.AuthorityMember{m1, m3Unknown}, 2, candidates); err == nil {
		t.Fatal("expected error for un-enrolled candidate")
	}
}

func TestClientTransportValidation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Valid local client
	client, err := NewClient("http://localhost:8444", "exchange-demo", priv)
	if err != nil {
		t.Fatalf("expected valid local client, got: %v", err)
	}
	if client == nil || client.URL != "http://localhost:8444" {
		t.Fatal("client URL not set properly")
	}

	// Invalid URL scheme (insecure remote http)
	_, err = NewClient("http://example.com:8444", "exchange-demo", priv)
	if err == nil {
		t.Fatal("expected error for remote non-https URL")
	}

	// Invalid path in base URL
	_, err = NewClient("http://localhost:8444/api/v1", "exchange-demo", priv)
	if err == nil {
		t.Fatal("expected error for URL with path component")
	}

	// Empty tenant
	_, err = NewClient("http://localhost:8444", "", priv)
	if err == nil {
		t.Fatal("expected error for empty tenant")
	}

	// Short private key
	_, err = NewClient("http://localhost:8444", "exchange-demo", []byte("short"))
	if err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestIdentityDigestIntegrity(t *testing.T) {
	id := Identity{
		Tenant:  "exchange-demo",
		Actor:   "user:sec1",
		Method:  "POST",
		Path:    "/authority/bundle/propose",
		Body:    ports.Digest{1, 2, 3},
		Expires: 1700000000,
	}

	d1, err := identityDigest(id)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := identityDigest(id)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("identity digests must be deterministic")
	}

	// Modified identity
	idTampered := id
	idTampered.Actor = "user:attacker"
	dTampered, err := identityDigest(idTampered)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == dTampered {
		t.Fatal("tampered identity must have distinct digest")
	}
}
