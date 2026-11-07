-- +goose Up
CREATE TABLE ratchet.drift_receipts (
 tenant_id text NOT NULL, connector_id text NOT NULL,
 drift_id uuid NOT NULL, operation_id uuid NOT NULL,
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 document jsonb NOT NULL, event_position bigint NOT NULL,
 PRIMARY KEY(tenant_id,connector_id,operation_id),
 UNIQUE(tenant_id,connector_id,drift_id)
);
ALTER TABLE ratchet.drift_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.drift_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.drift_receipts
 USING(tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
CREATE TRIGGER drift_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.drift_receipts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
GRANT SELECT,INSERT ON ratchet.drift_receipts TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'drift evidence migration is irreversible'; END $$;
-- +goose StatementEnd
