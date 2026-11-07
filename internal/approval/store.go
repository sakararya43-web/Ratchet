package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

// StoredCredential wraps a WebAuthn credential with RATCHET metadata.
type StoredCredential struct {
	TenantID   string              `json:"tenant_id"`
	ActorID    string              `json:"actor_id"`
	Label      string              `json:"label"`
	Credential webauthn.Credential `json:"credential"`
	CreatedAt  time.Time           `json:"created_at"`
	LastUsedAt time.Time           `json:"last_used_at"`
	IsRevoked  bool                `json:"is_revoked"`
}

// User implements webauthn.User for a human principal in RATCHET.
type User struct {
	TenantID    string
	ActorID     string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte {
	id := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", len(u.TenantID), u.TenantID, u.ActorID)))
	return id[:]
}

func (u *User) WebAuthnName() string {
	return u.ActorID
}

func (u *User) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.ActorID
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// ActiveSession stores session data during ongoing registration or assertion ceremony.
type ActiveSession struct {
	SessionID      string
	TenantID       string
	ActorID        string
	ChangeDigest   string
	ChallengeNonce []byte
	Data           *webauthn.SessionData
	ExpiresAt      time.Time
}

// CredentialStore provides thread-safe storage for enrolled passkeys and active WebAuthn challenges.
type CredentialStore struct {
	pool        *pgxpool.Pool
	readPool    *pgxpool.Pool
	events      *eventstore.Store
	mu          sync.RWMutex
	credentials map[string][]*StoredCredential // key: tenantID + ":" + actorID
	sessions    map[string]*ActiveSession      // key: sessionID
}

func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make(map[string][]*StoredCredential),
		sessions:    make(map[string]*ActiveSession),
	}
}

func (cs *CredentialStore) userKey(tenantID, actorID string) string {
	return fmt.Sprintf("%d:%s:%s", len(tenantID), tenantID, actorID)
}

// SaveCredential registers a new passkey credential for an actor.
func (cs *CredentialStore) SaveCredential(tenantID, actorID, label string, cred *webauthn.Credential) error {
	if cs.pool != nil {
		return cs.savePersistent(tenantID, actorID, label, cred)
	}
	if cred == nil || len(cred.ID) == 0 || len(cred.PublicKey) == 0 {
		return fmt.Errorf("credential required")
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	key := cs.userKey(tenantID, actorID)
	for _, sc := range cs.credentials[key] {
		if hex.EncodeToString(sc.Credential.ID) == hex.EncodeToString(cred.ID) {
			return fmt.Errorf("credential already registered")
		}
	}

	cs.credentials[key] = append(cs.credentials[key], &StoredCredential{
		TenantID:   tenantID,
		ActorID:    actorID,
		Label:      label,
		Credential: cloneCredential(*cred),
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		IsRevoked:  false,
	})
	return nil
}

// GetUser constructs a webauthn.User with all active, unrevoked credentials.
func (cs *CredentialStore) GetUser(tenantID, actorID, displayName string) *User {
	if cs.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		user, err := cs.User(ctx, tenantID, actorID)
		if err != nil {
			return &User{TenantID: tenantID, ActorID: actorID}
		}
		user.DisplayName = displayName
		return user
	}
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	key := cs.userKey(tenantID, actorID)
	var activeCreds []webauthn.Credential
	for _, sc := range cs.credentials[key] {
		if !sc.IsRevoked {
			activeCreds = append(activeCreds, cloneCredential(sc.Credential))
		}
	}

	return &User{
		TenantID:    tenantID,
		ActorID:     actorID,
		DisplayName: displayName,
		Credentials: activeCreds,
	}
}

// ListCredentials lists all credentials for an actor.
func (cs *CredentialStore) ListCredentials(tenantID, actorID string) []*StoredCredential {
	if cs.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		list, _ := cs.listPersistent(ctx, tenantID, actorID)
		return list
	}
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	key := cs.userKey(tenantID, actorID)
	var list []*StoredCredential
	for _, sc := range cs.credentials[key] {
		copySc := *sc
		copySc.Credential = cloneCredential(sc.Credential)
		list = append(list, &copySc)
	}
	return list
}

// RevokeCredential marks a credential as revoked.
func (cs *CredentialStore) RevokeCredential(tenantID, actorID string, credentialID []byte) error {
	if cs.pool != nil {
		return cs.revokePersistent(tenantID, actorID, credentialID)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	key := cs.userKey(tenantID, actorID)
	credHex := hex.EncodeToString(credentialID)
	for _, sc := range cs.credentials[key] {
		if hex.EncodeToString(sc.Credential.ID) == credHex {
			sc.IsRevoked = true
			return nil
		}
	}
	return fmt.Errorf("credential not found")
}

// SaveSession registers an active WebAuthn session.
func (cs *CredentialStore) SaveSession(tenantID, actorID, changeDigest string, nonce []byte, data *webauthn.SessionData) string {
	if cs.pool != nil {
		return cs.savePersistentSession(tenantID, actorID, changeDigest, nonce, data)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	sessionBytes := make([]byte, 16)
	_, _ = rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)

	cs.sessions[sessionID] = &ActiveSession{
		SessionID:      sessionID,
		TenantID:       tenantID,
		ActorID:        actorID,
		ChangeDigest:   changeDigest,
		ChallengeNonce: nonce,
		Data:           data,
		ExpiresAt:      time.Now().UTC().Add(5 * time.Minute),
	}
	return sessionID
}

// ConsumeSession retrieves and removes an active session (replay protection).
func (cs *CredentialStore) ConsumeSession(sessionID string) (*ActiveSession, error) {
	if cs.pool != nil {
		return nil, fmt.Errorf("persistent sessions require authenticated owner scope")
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	sess, ok := cs.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found or already consumed")
	}
	delete(cs.sessions, sessionID)

	if time.Now().UTC().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("session challenge expired")
	}
	return sess, nil
}

func cloneCredential(c webauthn.Credential) webauthn.Credential {
	raw, _ := json.Marshal(c)
	var out webauthn.Credential
	_ = json.Unmarshal(raw, &out)
	return out
}

func (cs *CredentialStore) User(ctx context.Context, tenant, actor string) (*User, error) {
	if cs.pool == nil {
		return cs.GetUser(tenant, actor, actor), nil
	}
	list, err := cs.listPersistent(ctx, tenant, actor)
	if err != nil {
		return nil, err
	}
	u := &User{TenantID: tenant, ActorID: actor, DisplayName: actor}
	for _, sc := range list {
		if !sc.IsRevoked {
			u.Credentials = append(u.Credentials, sc.Credential)
		}
	}
	return u, nil
}

func (cs *CredentialStore) ConsumeOwnedSession(ctx context.Context, id, tenant, actor string) (*ActiveSession, error) {
	if cs.pool != nil {
		return cs.consumePersistentSession(ctx, id, tenant, actor)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	s := cs.sessions[id]
	if s == nil || s.TenantID != tenant || s.ActorID != actor || !time.Now().Before(s.ExpiresAt) {
		return nil, fmt.Errorf("ceremony absent, expired or wrong owner")
	}
	delete(cs.sessions, id)
	return s, nil
}
