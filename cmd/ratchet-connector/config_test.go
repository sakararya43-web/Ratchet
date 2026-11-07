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
