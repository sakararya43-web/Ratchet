package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"

	"github.com/gowebpki/jcs"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// Digester implements the ports.Digester interface using RFC 8785 JSON Canonicalization Scheme (JCS).
type Digester struct{}

// New returns a new Digester instance.
func New() *Digester {
	return &Digester{}
}

// Canonicalize converts any Go value into RFC 8785 canonical JSON bytes.
// If v is already []byte or json.RawMessage, it treats it as raw JSON and canonicalizes it directly.
func (d *Digester) Canonicalize(v any) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}

	var rawJSON []byte
	switch val := v.(type) {
	case []byte:
		rawJSON = val
	case json.RawMessage:
		rawJSON = val
	case string:
		// If it's a string, we check if it's already a JSON structure (starts with { or [ or ")
		// To be safe and deterministic: if passed as string, we marshal it as a JSON string
		// unless caller specifically passed raw bytes.
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(val); err != nil {
			return nil, fmt.Errorf("failed to encode string: %w", err)
		}
		rawJSON = bytes.TrimRight(buf.Bytes(), "\n")
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return nil, fmt.Errorf("non-finite number not allowed: %v", val)
		}
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(val); err != nil {
			return nil, err
		}
		rawJSON = bytes.TrimRight(buf.Bytes(), "\n")
	case float32:
		f := float64(val)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("non-finite number not allowed: %v", val)
		}
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(val); err != nil {
			return nil, err
		}
		rawJSON = bytes.TrimRight(buf.Bytes(), "\n")
	default:
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(val); err != nil {
			return nil, fmt.Errorf("failed to encode JSON: %w", err)
		}
		rawJSON = bytes.TrimRight(buf.Bytes(), "\n")
	}

	return d.CanonicalizeJSON(rawJSON)
}

// CanonicalizeJSON validates raw JSON and transforms it into RFC 8785 canonical format.
func (d *Digester) CanonicalizeJSON(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("cannot canonicalize empty input")
	}

	// Validate that raw is valid JSON
	if !json.Valid(raw) {
		return nil, fmt.Errorf("invalid JSON input")
	}

	// Transform using RFC 8785 reference implementation
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("RFC 8785 canonicalization failed: %w", err)
	}

	return canonical, nil
}

// Digest canonicalizes the input and computes its SHA-256 hash.
func (d *Digester) Digest(v any) (ports.Digest, error) {
	canonicalBytes, err := d.Canonicalize(v)
	if err != nil {
		return ports.Digest{}, err
	}
	return sha256.Sum256(canonicalBytes), nil
}

// DigestJSON canonicalizes raw JSON bytes and computes its SHA-256 hash.
func (d *Digester) DigestJSON(raw []byte) (ports.Digest, error) {
	canonicalBytes, err := d.CanonicalizeJSON(raw)
	if err != nil {
		return ports.Digest{}, err
	}
	return sha256.Sum256(canonicalBytes), nil
}
