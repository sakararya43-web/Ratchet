package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
)

func NewPersistentCredentialStore(pool *pgxpool.Pool) (*CredentialStore, error) {
	if pool == nil {
		return nil, errors.New("credential database required")
	}
	events, err := eventstore.New(pool, canon.New())
	if err != nil {
		return nil, err
	}
	config := pool.Config()
	config.MaxConns = 4
	config.MinConns = 0
	reader, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}
	return &CredentialStore{pool: pool, readPool: reader, events: events}, nil
}

// Close releases the dedicated read pool. The supplied runtime/write pool is
// caller-owned. Verification cannot starve behind writers waiting on tenant locks.
func (cs *CredentialStore) Close() {
	if cs.readPool != nil {
		cs.readPool.Close()
	}
}
func credentialStream(id []byte) string {
	h := sha256.Sum256(id)
	return "credential:" + hex.EncodeToString(h[:])
}

var credentialTenant = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (cs *CredentialStore) readTx(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	if !credentialTenant.MatchString(tenant) {
		return errors.New("invalid credential tenant")
	}
	tx, err := cs.readPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('ratchet.tenant_id',$1,true)`, tenant); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func credentialFacts(tenant, actor string, c webauthn.Credential) map[string]string {
	id, key := sha256.Sum256(c.ID), sha256.Sum256(c.PublicKey)
	return map[string]string{"credential_digest": hex.EncodeToString(id[:]), "public_key_digest": hex.EncodeToString(key[:]), "actor_reference": uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+actor)).String()}
}
func (cs *CredentialStore) savePersistent(tenant, actor, label string, c *webauthn.Credential) error {
	if c == nil || actor == "" || len(actor) > 256 || len(label) > 128 || len(c.ID) == 0 || len(c.ID) > 1024 || len(c.PublicKey) == 0 || len(c.PublicKey) > 16384 {
		return errors.New("invalid credential")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return cs.events.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ratchet.approval_credentials WHERE tenant_id=$1 AND actor_id=$2`, tenant, actor).Scan(&count); err != nil {
			return err
		}
		if count >= 32 {
			return errors.New("credential capacity reached")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ratchet.approval_credentials(tenant_id,credential_id,actor_id,label,credential,enrolled_at) VALUES($1,$2,$3,$4,$5,$6)`, tenant, c.ID, actor, label, raw, now); err != nil {
			return err
		}
		facts, err := json.Marshal(credentialFacts(tenant, actor, *c))
		if err != nil {
			return err
		}
		_, err = cs.events.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+credentialStream(c.ID)+":enroll")), StreamID: credentialStream(c.ID), ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+actor)), Events: []eventstore.Event{{Type: "CredentialEnrolled", Facts: facts}}})
		return err
	})
}
func (cs *CredentialStore) listPersistent(ctx context.Context, tenant, actor string) ([]*StoredCredential, error) {
	var list []*StoredCredential
	err := cs.readTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT credential_id,label,credential,enrolled_at,revoked_at IS NOT NULL FROM ratchet.approval_credentials WHERE tenant_id=$1 AND actor_id=$2 ORDER BY enrolled_at,credential_id LIMIT 33`, tenant, actor)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, raw []byte
			s := &StoredCredential{TenantID: tenant, ActorID: actor}
			if err := rows.Scan(&id, &s.Label, &raw, &s.CreatedAt, &s.IsRevoked); err != nil {
				rows.Close()
				return err
			}
			if json.Unmarshal(raw, &s.Credential) != nil || hex.EncodeToString(id) != hex.EncodeToString(s.Credential.ID) {
				rows.Close()
				return eventstore.ErrIntegrity
			}
			list = append(list, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(list) > 32 {
			return eventstore.ErrIntegrity
		}
		for _, stored := range list {
			events, err := cs.events.StreamWithin(ctx, tx, tenant, credentialStream(stored.Credential.ID))
			if err != nil {
				return err
			}
			if len(events) == 0 || events[0].Type != "CredentialEnrolled" {
				return eventstore.ErrIntegrity
			}
			var content ledger.Content
			var payload struct {
				Facts map[string]string `json:"facts"`
			}
			if json.Unmarshal(events[0].Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil {
				return eventstore.ErrIntegrity
			}
			for k, v := range credentialFacts(tenant, actor, stored.Credential) {
				if payload.Facts[k] != v {
					return eventstore.ErrIntegrity
				}
			}
			if stored.IsRevoked != (len(events) == 2 && events[1].Type == "CredentialRevoked") || len(events) > 2 {
				return eventstore.ErrIntegrity
			}
			stored.CreatedAt = events[0].RecordedAt
		}
		return nil
	})
	return list, err
}
func (cs *CredentialStore) revokePersistent(tenant, actor string, id []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return cs.events.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		tag, err := tx.Exec(ctx, `UPDATE ratchet.approval_credentials SET revoked_at=$4 WHERE tenant_id=$1 AND actor_id=$2 AND credential_id=$3 AND revoked_at IS NULL`, tenant, actor, id, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("active credential not found")
		}
		facts, _ := json.Marshal(map[string]string{"credential_digest": credentialStream(id)[len("credential:"):]})
		_, err = cs.events.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+credentialStream(id)+":revoke")), StreamID: credentialStream(id), ExpectedVersion: 1, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+actor)), Events: []eventstore.Event{{Type: "CredentialRevoked", Facts: facts}}})
		return err
	})
}
func (cs *CredentialStore) savePersistentSession(tenant, actor, digest string, nonce []byte, data *webauthn.SessionData) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return ""
	}
	id := hex.EncodeToString(secret)
	err := cs.events.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		if _, err := tx.Exec(ctx, `DELETE FROM ratchet.approval_sessions WHERE tenant_id=$1 AND expires_at<=$2`, tenant, now); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ratchet.approval_sessions WHERE tenant_id=$1 AND actor_id=$2`, tenant, actor).Scan(&n); err != nil {
			return err
		}
		if n >= 64 {
			return errors.New("ceremony capacity reached")
		}
		s := ActiveSession{SessionID: id, TenantID: tenant, ActorID: actor, ChangeDigest: digest, ChallengeNonce: nonce, Data: data, ExpiresAt: now.Add(5 * time.Minute)}
		raw, err := json.Marshal(s)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.approval_sessions(tenant_id,session_id,actor_id,expires_at,document) VALUES($1,$2,$3,$4,$5)`, tenant, id, actor, s.ExpiresAt, raw)
		return err
	})
	if err != nil {
		return ""
	}
	return id
}
func (cs *CredentialStore) consumePersistentSession(ctx context.Context, id, tenant, actor string) (*ActiveSession, error) {
	var s ActiveSession
	err := cs.events.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `DELETE FROM ratchet.approval_sessions WHERE tenant_id=$1 AND actor_id=$2 AND session_id=$3 AND expires_at>$4 RETURNING document`, tenant, actor, id, now).Scan(&raw); err != nil {
			return err
		}
		if json.Unmarshal(raw, &s) != nil || s.TenantID != tenant || s.ActorID != actor || s.SessionID != id || !now.Before(s.ExpiresAt) {
			return fmt.Errorf("invalid ceremony context")
		}
		return nil
	})
	return &s, err
}
