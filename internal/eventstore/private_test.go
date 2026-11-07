package eventstore_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

func TestPrivateCiphertextBindsTenantRecordAndKey(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	record, err := eventstore.SealPrivate(key, "exchange", uuid.New(), "key-ref", []byte("private justification"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := eventstore.OpenPrivate(key, "exchange", record)
	if err != nil || string(plain) != "private justification" {
		t.Fatalf("decrypt: %s %v", plain, err)
	}
	if _, err := eventstore.OpenPrivate(key, "other", record); err == nil {
		t.Fatal("accepted different tenant")
	}
	copyRecord := record
	copyRecord.ID = uuid.New()
	if _, err := eventstore.OpenPrivate(key, "exchange", copyRecord); err == nil {
		t.Fatal("accepted different record")
	}
	if _, err := eventstore.OpenPrivate(bytes.Repeat([]byte{4}, 32), "exchange", record); err == nil {
		t.Fatal("accepted deleted/replaced key")
	}
	record.Ciphertext[len(record.Ciphertext)-1] ^= 1
	if _, err := eventstore.OpenPrivate(key, "exchange", record); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
}
