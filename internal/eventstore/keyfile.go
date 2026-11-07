package eventstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CreatePrivacyKey creates a new external AES-256 key without returning its bytes
// to CLI output or overwriting an existing key. The parent directory must exist.
func CreatePrivacyKey(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute privacy key path required")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		_ = os.Remove(path)
		return err
	}
	return file.Sync()
}

func LoadPrivacyKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute privacy key path required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("privacy key must be a private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 67))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > 66 {
		return nil, errors.New("invalid privacy key file")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errors.New("invalid privacy key file")
	}
	return key, nil
}

// DestroyPrivacyKey removes an external key file after its readers are stopped.
// This is logical deletion: operators must also remove backup/config copies.
// It does not promise physical SSD erasure or erase another process's memory.
func DestroyPrivacyKey(path string) error {
	key, err := LoadPrivacyKey(path)
	if err != nil {
		return err
	}
	clear(key)
	return os.Remove(path)
}
