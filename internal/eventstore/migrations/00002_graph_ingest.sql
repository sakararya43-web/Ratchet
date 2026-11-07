-- +goose Up
CREATE TABLE ratchet.graph_sources (
    tenant_id text NOT NULL,
    connector_id text NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision BETWEEN 0 AND 9007199254740991),
    graph_version bigint NOT NULL,
    public_graph jsonb NOT NULL,
    private_record_id uuid,
    needs_resync boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, connector_id)
);
CREATE TABLE ratchet.ingest_receipts (
    tenant_id text NOT NULL,
    message_id uuid NOT NULL,
    connector_id text NOT NULL,
    input_digest bytea NOT NULL CHECK (octet_length(input_digest)=32),
    graph_version bigint NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('applied','resync_required')),
    PRIMARY KEY (tenant_id,message_id)
);
CREATE TRIGGER ingest_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.ingest_receipts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
ALTER TABLE ratchet.graph_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.graph_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY graph_sources_isolation ON ratchet.graph_sources
USING (tenant_id=current_setting('ratchet.tenant_id',true)) WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
ALTER TABLE ratchet.ingest_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.ingest_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY ingest_receipts_isolation ON ratchet.ingest_receipts
USING (tenant_id=current_setting('ratchet.tenant_id',true)) WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT,UPDATE ON ratchet.graph_sources TO ratchet_runtime;
GRANT SELECT,INSERT ON ratchet.ingest_receipts TO ratchet_runtime;
ALTER TABLE ratchet.outbox ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp();
GRANT UPDATE (next_attempt_at) ON ratchet.outbox TO ratchet_runtime;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'graph evidence migration is irreversible'; END $$;
-- +goose StatementEnd
