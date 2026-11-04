// Package ledger defines the versioned canonical bytes shared with offline audit verification.
package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

const MaxSafeInteger int64 = 1<<53 - 1

// Content deliberately matches the content hashed by the peer audit verifier.
// The actor and target are opaque references; personal display data is stored separately.
type Content struct {
	Action            string          `json:"action"`
	ActorID           string          `json:"actor_id"`
	EventType         string          `json:"event_type"`
	Payload           json.RawMessage `json:"payload"`
	PreviousEventHash string          `json:"previous_event_hash"`
	Sequence          int64           `json:"sequence"`
	TargetIdentity    string          `json:"target_identity"`
	TenantID          string          `json:"tenant_id"`
	Timestamp         string          `json:"timestamp"`
}

type Entry struct {
	Canonical []byte
	Previous  ports.Digest
	Hash      ports.Digest
}

func Build(digester ports.Digester, previous ports.Digest, content Content) (Entry, error) {
	if digester == nil {
		return Entry{}, errors.New("real canonical digester is required")
	}
	if content.Sequence < 1 || content.Sequence > MaxSafeInteger || content.TenantID == "" || content.EventType == "" {
		return Entry{}, errors.New("invalid ledger sequence or identity")
	}
	stamp, err := time.Parse(time.RFC3339Nano, content.Timestamp)
	if err != nil || content.Timestamp != stamp.UTC().Format(time.RFC3339Nano) || stamp.Nanosecond()%1000 != 0 {
		return Entry{}, errors.New("timestamp must be canonical UTC at PostgreSQL microsecond precision")
	}
	content.PreviousEventHash = previous.String()
	canonical, err := digester.Canonicalize(content)
	if err != nil {
		return Entry{}, fmt.Errorf("canonical event: %w", err)
	}
	return Entry{Canonical: canonical, Previous: previous, Hash: hash(previous, canonical)}, nil
}

func Verify(digester ports.Digester, entry Entry, tenant string, sequence int64, previous ports.Digest) (Content, error) {
	if digester == nil {
		return Content{}, errors.New("real canonical digester is required")
	}
	var content Content
	if err := json.Unmarshal(entry.Canonical, &content); err != nil {
		return Content{}, fmt.Errorf("decode canonical event: %w", err)
	}
	if entry.Previous != previous || content.PreviousEventHash != previous.String() || content.TenantID != tenant || content.Sequence != sequence {
		return Content{}, errors.New("ledger context or predecessor mismatch")
	}
	rebuilt, err := Build(digester, previous, content)
	if err != nil {
		return Content{}, err
	}
	if !bytes.Equal(entry.Canonical, rebuilt.Canonical) || entry.Hash != rebuilt.Hash {
		return Content{}, errors.New("ledger content or hash mismatch")
	}
	return content, nil
}

func hash(previous ports.Digest, canonical []byte) ports.Digest {
	h := sha256.New()
	_, _ = h.Write(previous[:])
	_, _ = h.Write(canonical)
	var digest ports.Digest
	copy(digest[:], h.Sum(nil))
	return digest
}
