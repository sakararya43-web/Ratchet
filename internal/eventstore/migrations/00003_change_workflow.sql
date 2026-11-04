-- +goose Up
CREATE SCHEMA ratchet_jobs;
REVOKE ALL ON SCHEMA ratchet_jobs FROM PUBLIC;
GRANT USAGE ON SCHEMA ratchet_jobs TO ratchet_runtime;
CREATE TABLE ratchet.console_users (
 tenant_id text NOT NULL, actor_id text NOT NULL,
 salt bytea NOT NULL CHECK(octet_length(salt)=16),
 password_hash bytea NOT NULL CHECK(octet_length(password_hash)=32),
 disabled boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,actor_id)
);
CREATE TABLE ratchet.console_sessions (
 tenant_id text NOT NULL, token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 actor_id text NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,token_hash),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES ratchet.console_users(tenant_id,actor_id)
);
CREATE TABLE ratchet.change_projection (
 tenant_id text NOT NULL, request_id uuid NOT NULL, event_position bigint NOT NULL,
 state text NOT NULL, updated_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,request_id)
);
CREATE INDEX change_attention ON ratchet.change_projection(tenant_id,state,event_position,request_id);
CREATE TABLE ratchet.workflow_receipts (
 tenant_id text NOT NULL, command_id uuid NOT NULL, request_id uuid NOT NULL,
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32), document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,command_id)
);
CREATE TRIGGER workflow_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.workflow_receipts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
CREATE TABLE ratchet.policy_artifacts (
 tenant_id text NOT NULL, version text NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32),
 raw_bundle bytea NOT NULL, event_position bigint NOT NULL,
 PRIMARY KEY(tenant_id,version), UNIQUE(tenant_id,digest)
);
CREATE TRIGGER policy_artifacts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.policy_artifacts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
-- +goose StatementBegin
DO $$ DECLARE relation text; BEGIN
 FOREACH relation IN ARRAY ARRAY['console_users','console_sessions','change_projection','workflow_receipts','policy_artifacts'] LOOP
  EXECUTE format('ALTER TABLE ratchet.%I ENABLE ROW LEVEL SECURITY',relation);
  EXECUTE format('ALTER TABLE ratchet.%I FORCE ROW LEVEL SECURITY',relation);
  EXECUTE format('CREATE POLICY tenant_isolation ON ratchet.%I USING (tenant_id=current_setting(''ratchet.tenant_id'',true)) WITH CHECK (tenant_id=current_setting(''ratchet.tenant_id'',true))',relation);
 END LOOP;
END $$;
-- +goose StatementEnd
GRANT SELECT ON ratchet.console_users TO ratchet_runtime;
GRANT SELECT,INSERT,DELETE ON ratchet.console_sessions TO ratchet_runtime;
GRANT SELECT,INSERT,UPDATE ON ratchet.change_projection TO ratchet_runtime;
GRANT SELECT,INSERT ON ratchet.workflow_receipts,ratchet.policy_artifacts TO ratchet_runtime;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'workflow evidence migration is irreversible'; END $$;
-- +goose StatementEnd
