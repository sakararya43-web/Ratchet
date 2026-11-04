-- +goose Up
CREATE SCHEMA ratchet;

CREATE TABLE ratchet.tenant_heads (
    tenant_id text PRIMARY KEY CHECK (tenant_id <> ''),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence BETWEEN 0 AND 9007199254740991),
    hash bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(hash) = 32)
);

CREATE TABLE ratchet.command_receipts (
    tenant_id text NOT NULL,
    command_id uuid NOT NULL,
    command_digest bytea NOT NULL CHECK (octet_length(command_digest) = 32),
    stream_id text NOT NULL CHECK (stream_id <> ''),
    first_sequence bigint NOT NULL,
    last_sequence bigint NOT NULL,
    stream_version bigint NOT NULL,
    PRIMARY KEY (tenant_id, command_id),
    CHECK (first_sequence > 0 AND last_sequence >= first_sequence),
    CHECK (stream_version > 0)
);

CREATE TABLE ratchet.private_records (
    tenant_id text NOT NULL,
    record_id uuid NOT NULL,
    key_reference text NOT NULL CHECK (key_reference <> ''),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, record_id)
);

CREATE TABLE ratchet.events (
    tenant_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    event_id uuid NOT NULL,
    command_id uuid NOT NULL,
    stream_id text NOT NULL CHECK (stream_id <> ''),
    stream_version bigint NOT NULL CHECK (stream_version BETWEEN 1 AND 9007199254740991),
    event_type text NOT NULL CHECK (event_type <> ''),
    actor_reference uuid NOT NULL,
    private_record_id uuid,
    canonical_content bytea NOT NULL CHECK (octet_length(canonical_content) > 0),
    previous_hash bytea NOT NULL CHECK (octet_length(previous_hash) = 32),
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, stream_id, stream_version),
    UNIQUE (tenant_id, event_id)
);

CREATE TABLE ratchet.outbox (
    tenant_id text NOT NULL,
    event_id uuid NOT NULL,
    sequence bigint NOT NULL,
    subject text NOT NULL CHECK (subject <> ''),
    payload bytea NOT NULL CHECK (octet_length(payload) > 0),
    created_at timestamptz NOT NULL,
    delivered_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, sequence) REFERENCES ratchet.events (tenant_id, sequence)
);
CREATE INDEX outbox_pending ON ratchet.outbox (tenant_id, sequence) WHERE delivered_at IS NULL;

-- Defense in depth beyond grants: accidental grants still cannot rewrite history.
-- +goose StatementBegin
CREATE FUNCTION ratchet.reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'append-only relation' USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.events
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
CREATE TRIGGER receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.command_receipts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();

ALTER TABLE ratchet.tenant_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.tenant_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_heads_isolation ON ratchet.tenant_heads
USING (tenant_id = current_setting('ratchet.tenant_id', true))
WITH CHECK (tenant_id = current_setting('ratchet.tenant_id', true));
ALTER TABLE ratchet.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.events FORCE ROW LEVEL SECURITY;
CREATE POLICY events_isolation ON ratchet.events
USING (tenant_id = current_setting('ratchet.tenant_id', true))
WITH CHECK (tenant_id = current_setting('ratchet.tenant_id', true));
ALTER TABLE ratchet.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.command_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY receipts_isolation ON ratchet.command_receipts
USING (tenant_id = current_setting('ratchet.tenant_id', true))
WITH CHECK (tenant_id = current_setting('ratchet.tenant_id', true));
ALTER TABLE ratchet.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_isolation ON ratchet.outbox
USING (tenant_id = current_setting('ratchet.tenant_id', true))
WITH CHECK (tenant_id = current_setting('ratchet.tenant_id', true));
ALTER TABLE ratchet.private_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.private_records FORCE ROW LEVEL SECURITY;
CREATE POLICY private_records_isolation ON ratchet.private_records
USING (tenant_id = current_setting('ratchet.tenant_id', true))
WITH CHECK (tenant_id = current_setting('ratchet.tenant_id', true));

REVOKE ALL ON SCHEMA ratchet FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ratchet FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ratchet FROM PUBLIC;
GRANT USAGE ON SCHEMA ratchet TO ratchet_runtime, ratchet_projector;
GRANT SELECT, INSERT ON ratchet.events, ratchet.command_receipts TO ratchet_runtime;
GRANT SELECT, INSERT, UPDATE ON ratchet.tenant_heads TO ratchet_runtime;
GRANT SELECT, INSERT ON ratchet.outbox TO ratchet_runtime;
GRANT UPDATE (delivered_at, attempts) ON ratchet.outbox TO ratchet_runtime;
GRANT SELECT, INSERT, DELETE ON ratchet.private_records TO ratchet_runtime;
GRANT SELECT ON ratchet.events TO ratchet_projector;

-- +goose Down
-- A down migration would erase security evidence. Restore a verified backup instead.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'event store migration is irreversible'; END $$;
-- +goose StatementEnd
