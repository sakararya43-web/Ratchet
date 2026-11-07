package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const CredentialAuthorizationHeader = "X-Ratchet-Credential-Authorization"

func credentialOperation(operation, credential string) bool {
	if operation == "enroll" {
		return credential == ""
	}
	raw, err := hex.DecodeString(credential)
	return operation == "revoke" && err == nil && len(raw) > 0 && len(raw) <= 1024 && hex.EncodeToString(raw) == credential
}

// ProvisionCredentialAuthorization is an out-of-band local operator operation.
// Runtime SQL privileges cannot mint tickets. Raw tickets never enter the ledger.
func ProvisionCredentialAuthorization(ctx context.Context, pool *pgxpool.Pool, p Principal, operation, credential string, lifetime time.Duration) (string, error) {
	if !credentialOperation(operation, credential) || lifetime < time.Minute || lifetime > time.Hour {
		return "", errors.New("invalid credential authorization")
	}
	var role string
	if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil || role != "ratchet_migrator" {
		return "", errors.New("credential authorization requires the migration/operator role")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	err := authTx(ctx, pool, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ratchet.credential_authorizations(tenant_id,token_hash,actor_id,operation,credential_id,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+$6*interval '1 second')`, p.TenantID, digest[:], p.ActorID, operation, credential, int64(lifetime/time.Second))
		return err
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// AuthorizePasskeyChange requires more than possession of an application session.
// A ticket authorizes exactly one actor/operation/credential and expires by DB time.
func (s *Sessions) AuthorizePasskeyChange(r *http.Request, operation, credential string) error {
	p, ok := SessionPrincipal(r.Context())
	if !ok || !credentialOperation(operation, credential) {
		return errors.New("credential operator authorization required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.Header.Get(CredentialAuthorizationHeader))
	if err != nil || len(raw) != 32 {
		return errors.New("credential operator authorization required")
	}
	digest := sha256.Sum256(raw)
	return authTx(r.Context(), s.pool, p.TenantID, func(tx pgx.Tx) error {
		result, err := tx.Exec(r.Context(), `DELETE FROM ratchet.credential_authorizations WHERE tenant_id=$1 AND token_hash=$2 AND actor_id=$3 AND operation=$4 AND credential_id=$5 AND expires_at>clock_timestamp()`, p.TenantID, digest[:], p.ActorID, operation, credential)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return errors.New("credential authorization absent, expired or consumed")
		}
		return nil
	})
}
