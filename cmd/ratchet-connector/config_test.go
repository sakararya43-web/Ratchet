package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSigningIdentityMustBeExplicitAndConsistent(t *testing.T) {
	if _, err := loadSigningKey(""); err == nil {
		t.Fatal("missing key accepted")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSigningKey(path)
	if err != nil || !loaded.Equal(private) {
		t.Fatal("persistent identity changed", err)
	}
	private[63] ^= 1
	if err := os.WriteFile(path, []byte(hex.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigningKey(path); err == nil {
		t.Fatal("inconsistent key accepted")
	}
}

func TestTransportRejectsRemotePlaintextAndInlineCredentials(t *testing.T) {
	for _, address := range []string{"nats://example.com:4222", "tls://example.com:4222", "tls://user:secret@example.com:4222", "file:///tmp/broker"} {
		if err := validateTransport(address, "tls", false); err == nil {
			t.Fatal("unsafe broker", address)
		}
	}
	if err := validateTransport("tls://example.com:4222", "tls", true); err != nil {
		t.Fatal(err)
	}
	if err := validateTransport("nats://127.0.0.1:4222", "tls", false); err != nil {
		t.Fatal(err)
	}
	if err := validateTransport("http://example.com", "https", true); err == nil {
		t.Fatal("unsafe target")
	}
}
