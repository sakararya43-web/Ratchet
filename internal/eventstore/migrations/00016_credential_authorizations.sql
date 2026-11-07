-- +goose Up
CREATE TABLE ratchet.credential_authorizations (
 tenant_id text NOT NULL, token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 actor_id text NOT NULL, operation text NOT NULL CHECK(operation IN ('enroll','revoke')),
 credential_id text NOT NULL DEFAULT '', expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,token_hash),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES ratchet.console_users(tenant_id,actor_id),
 CHECK((operation='enroll' AND credential_id='') OR (operation='revoke' AND credential_id<>''))
);
ALTER TABLE ratchet.credential_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.credential_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_authorizations_tenant ON ratchet.credential_authorizations
 USING(tenant_id=current_setting('ratchet.tenant_id',true)) WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,DELETE ON ratchet.credential_authorizations TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'credential authorization migration is irreversible'; END $$;
-- +goose StatementEnd
