package eventstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// PrivateRecord stores only encrypted bytes and an external key reference.
// Keys and plaintext never enter the immutable event or outbox.
type PrivateRecord struct {
	ID           uuid.UUID `json:"id"`
	KeyReference string    `json:"key_reference"`
	Ciphertext   []byte    `json:"ciphertext"`
}

func SealPrivate(key []byte, tenant string, id uuid.UUID, keyReference string, plaintext []byte) (PrivateRecord, error) {
	if len(key) != 32 || tenant == "" || id == uuid.Nil || keyReference == "" || len(plaintext) == 0 {
		return PrivateRecord{}, errors.New("private record requires an AES-256 key, tenant, reference and content")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return PrivateRecord{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return PrivateRecord{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return PrivateRecord{}, err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, privateAAD(tenant, id))
	return PrivateRecord{ID: id, KeyReference: keyReference, Ciphertext: sealed}, nil
}

func OpenPrivate(key []byte, tenant string, record PrivateRecord) ([]byte, error) {
	if len(key) != 32 || tenant == "" || record.ID == uuid.Nil {
		return nil, errors.New("invalid private record key or context")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(record.Ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("truncated encrypted record")
	}
	return aead.Open(nil, record.Ciphertext[:aead.NonceSize()], record.Ciphertext[aead.NonceSize():], privateAAD(tenant, record.ID))
}

func privateAAD(tenant string, id uuid.UUID) []byte {
	return []byte(fmt.Sprintf("ratchet-private-v1:%d:%s:%s", len(tenant), tenant, id))
}
