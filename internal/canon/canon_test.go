package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type CanonicalVector struct {
	Name            string `json:"name"`
	InputRaw        string `json:"input_raw"`
	ExpectedBytes   string `json:"expected_bytes"`
	ExpectedHexHash string `json:"expected_hex_hash"`
	ShouldFail      bool   `json:"should_fail"`
	FailureReason   string `json:"failure_reason,omitempty"`
}

type VectorsFile struct {
	Description string            `json:"description"`
	Vectors     []CanonicalVector `json:"vectors"`
}

func TestCanonicalizeAndDigest(t *testing.T) {
	d := New()

	// 1. Basic key reordering
	input1 := []byte(`{"b": 2, "a": 1}`)
	res1, err := d.CanonicalizeJSON(input1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected1 := `{"a":1,"b":2}`
	if string(res1) != expected1 {
		t.Errorf("got %s, want %s", string(res1), expected1)
	}

	// 2. Escaping: < > & / must NOT be escaped
	input2 := []byte(`{"html": "<tag>&'\"/"}`)
	res2, err := d.CanonicalizeJSON(input2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected2 := `{"html":"<tag>&'\"/"}`
	if string(res2) != expected2 {
		t.Errorf("got %s, want %s", string(res2), expected2)
	}

	// 3. Digest check
	hash := sha256.Sum256(res1)
	digest, err := d.DigestJSON(input1)
	if err != nil {
		t.Fatalf("digest error: %v", err)
	}
	if digest != hash {
		t.Errorf("digest mismatch: got %x, want %x", digest, hash)
	}
}

func TestRejectNonFinite(t *testing.T) {
	d := New()
	if _, err := d.Canonicalize(math.NaN()); err == nil {
		t.Errorf("expected error on NaN, got nil")
	}
	if _, err := d.Canonicalize(math.Inf(1)); err == nil {
		t.Errorf("expected error on +Inf, got nil")
	}
	if _, err := d.Canonicalize(math.Inf(-1)); err == nil {
		t.Errorf("expected error on -Inf, got nil")
	}
}

func TestGoldenVectors(t *testing.T) {
	vectorsPath := filepath.Join("..", "..", "testdata", "canon", "vectors.json")
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Skipf("testdata vectors not present yet: %v", err)
		return
	}

	var vf VectorsFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("failed to unmarshal vectors file: %v", err)
	}

	d := New()
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.ShouldFail {
				_, err := d.CanonicalizeJSON([]byte(v.InputRaw))
				if err == nil {
					t.Errorf("expected failure for %s, but succeeded", v.Name)
				}
				return
			}

			canonical, err := d.CanonicalizeJSON([]byte(v.InputRaw))
			if err != nil {
				t.Fatalf("unexpected canonicalize error: %v", err)
			}

			if string(canonical) != v.ExpectedBytes {
				t.Errorf("canonical bytes mismatch:\ngot:  %s\nwant: %s", string(canonical), v.ExpectedBytes)
			}

			digest, err := d.DigestJSON([]byte(v.InputRaw))
			if err != nil {
				t.Fatalf("unexpected digest error: %v", err)
			}

			if hex.EncodeToString(digest[:]) != v.ExpectedHexHash {
				t.Errorf("hash mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(digest[:]), v.ExpectedHexHash)
			}
		})
	}
}
