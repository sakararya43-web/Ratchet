-- +goose Up
CREATE TABLE ratchet.execution_attempts (
 tenant_id text NOT NULL, command_id uuid NOT NULL, request_id uuid NOT NULL,
 connector_id text NOT NULL, source_revision bigint NOT NULL,
 envelope_digest bytea NOT NULL, expected_roles jsonb NOT NULL,
 deadline timestamptz NOT NULL, command_payload bytea NOT NULL,
 PRIMARY KEY(tenant_id,command_id)
);
ALTER TABLE ratchet.execution_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.execution_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.execution_attempts
USING(tenant_id=current_setting('ratchet.tenant_id',true)) WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
CREATE TRIGGER execution_attempts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.execution_attempts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
GRANT SELECT,INSERT ON ratchet.execution_attempts TO ratchet_runtime;
GRANT DELETE ON ratchet.change_projection TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'execution evidence migration is irreversible'; END $$;
-- +goose StatementEnd
