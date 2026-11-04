-- +goose Up
CREATE TABLE ratchet.registry_artifacts (
 tenant_id text NOT NULL, epoch bigint NOT NULL CHECK(epoch>0),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 trust_proof bytea NOT NULL, event_position bigint NOT NULL,
 PRIMARY KEY(tenant_id,epoch), UNIQUE(tenant_id,digest)
);
CREATE TRIGGER registry_artifacts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.registry_artifacts
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
ALTER TABLE ratchet.registry_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.registry_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.registry_artifacts
 USING (tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT ON ratchet.registry_artifacts TO ratchet_runtime;
ALTER TABLE ratchet.policy_artifacts ADD COLUMN registry_epoch bigint NOT NULL DEFAULT 1;
ALTER TABLE ratchet.policy_artifacts ADD COLUMN trust_proof bytea;
-- Existing artifacts retain NULL proof until an actual Authority verifies them.
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'registry history migration is irreversible'; END $$;
-- +goose StatementEnd
