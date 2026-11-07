-- +goose Up
CREATE TABLE ratchet.approval_credentials (
 tenant_id text NOT NULL, credential_id bytea NOT NULL, actor_id text NOT NULL,
 label text NOT NULL, credential jsonb NOT NULL, enrolled_at timestamptz NOT NULL,
 revoked_at timestamptz, PRIMARY KEY(tenant_id,credential_id)
);
CREATE TABLE ratchet.approval_sessions (
 tenant_id text NOT NULL, session_id text NOT NULL, actor_id text NOT NULL,
 expires_at timestamptz NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_id,session_id)
);
ALTER TABLE ratchet.approval_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.approval_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE ratchet.approval_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.approval_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY approval_credentials_tenant ON ratchet.approval_credentials
 USING(tenant_id=current_setting('ratchet.tenant_id',true)) WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
CREATE POLICY approval_sessions_tenant ON ratchet.approval_sessions
 USING(tenant_id=current_setting('ratchet.tenant_id',true)) WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT ON ratchet.approval_credentials TO ratchet_runtime;
GRANT UPDATE(revoked_at) ON ratchet.approval_credentials TO ratchet_runtime;
GRANT SELECT,INSERT,DELETE ON ratchet.approval_sessions TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'credential history migration is irreversible'; END $$;
-- +goose StatementEnd
