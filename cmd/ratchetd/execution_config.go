package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

type executionConfig struct {
	Connector      string `json:"connector_id"`
	PublicKey      string `json:"connector_public_key_hex"`
	PrivateKeyFile string `json:"core_signing_key_file"`
	CapabilityFile string `json:"capability_file"`
}

func (c executionConfig) load(tenant string) (*workflow.Execution, error) {
	if !filepath.IsAbs(c.PrivateKeyFile) || !filepath.IsAbs(c.CapabilityFile) {
		return nil, errors.New("absolute execution key/capability paths required")
	}
	info, err := os.Stat(c.PrivateKeyFile)
	if err != nil || info.Size() > 130 {
		return nil, errors.New("invalid execution key file")
	}
	raw, err := os.ReadFile(c.PrivateKeyFile)
	if err != nil {
		return nil, errors.New("execution key unavailable")
	}
	defer clear(raw)
	private, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(private) != 64 {
		return nil, errors.New("Ed25519 signing key required")
	}
	defer clear(private)
	if !bytes.Equal(ed25519.NewKeyFromSeed(private[:32]), private) {
		return nil, errors.New("inconsistent Ed25519 signing key")
	}
	public, err := key32(c.PublicKey)
	if err != nil {
		return nil, err
	}
	var capability workflow.Capability
	if err := configFile(c.CapabilityFile, &capability); err != nil {
		return nil, err
	}
	return workflow.NewExecution(tenant, c.Connector, ed25519.PublicKey(public), ed25519.PrivateKey(private), capability)
}
