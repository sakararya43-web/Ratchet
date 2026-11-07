-- name: SetTenant :exec
SELECT set_config('ratchet.tenant_id', sqlc.arg(tenant_id)::text, true);

-- name: EnsureTenantHead :exec
INSERT INTO ratchet.tenant_heads (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING;

-- name: LockTenantHead :one
SELECT sequence, hash FROM ratchet.tenant_heads WHERE tenant_id = $1 FOR UPDATE;

-- name: AdvanceTenantHead :exec
UPDATE ratchet.tenant_heads SET sequence = $2, hash = $3 WHERE tenant_id = $1;

-- name: FindCommand :one
SELECT * FROM ratchet.command_receipts WHERE tenant_id = $1 AND command_id = $2;

-- name: SaveCommand :exec
INSERT INTO ratchet.command_receipts
(tenant_id, command_id, command_digest, stream_id, first_sequence, last_sequence, stream_version)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: StreamVersion :one
SELECT coalesce(max(stream_version), 0)::bigint FROM ratchet.events WHERE tenant_id = $1 AND stream_id = $2;

-- name: InsertEvent :exec
INSERT INTO ratchet.events
(tenant_id, sequence, event_id, command_id, stream_id, stream_version, event_type,
 actor_reference, private_record_id, canonical_content, previous_hash, hash, recorded_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: InsertOutbox :exec
INSERT INTO ratchet.outbox (tenant_id, event_id, sequence, subject, payload, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: InsertPrivateRecord :exec
INSERT INTO ratchet.private_records (tenant_id, record_id, key_reference, ciphertext)
VALUES ($1, $2, $3, $4);

-- name: DeletePrivateRecord :exec
DELETE FROM ratchet.private_records WHERE tenant_id = $1 AND record_id = $2;

-- name: LoadStream :many
SELECT * FROM ratchet.events WHERE tenant_id = $1 AND stream_id = $2 ORDER BY stream_version;

-- name: LoadTenantChain :many
SELECT * FROM ratchet.events WHERE tenant_id = $1 AND sequence > $2 ORDER BY sequence LIMIT $3;

-- name: DatabaseTime :one
SELECT clock_timestamp()::timestamptz;
