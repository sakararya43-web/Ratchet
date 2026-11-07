-- +goose Up
CREATE TABLE ratchet.native_admissions (
 tenant_id text NOT NULL, connector_id text NOT NULL, command_id uuid NOT NULL,
 request_id uuid NOT NULL, admission_uid text NOT NULL,
 context_digest bytea NOT NULL CHECK(octet_length(context_digest)=32),
 mutation_digest bytea NOT NULL CHECK(octet_length(mutation_digest)=32),
 authorized_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,command_id), UNIQUE(tenant_id,connector_id,admission_uid)
);
ALTER TABLE ratchet.native_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.native_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.native_admissions
 USING(tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
CREATE TRIGGER native_admissions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.native_admissions
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
GRANT SELECT,INSERT ON ratchet.native_admissions TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'native admission evidence migration is irreversible'; END $$;
-- +goose StatementEnd
