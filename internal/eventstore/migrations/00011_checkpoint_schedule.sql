-- +goose Up
CREATE TABLE ratchet.checkpoint_schedules (
 tenant_id text PRIMARY KEY,
 next_run_at timestamptz NOT NULL
);
ALTER TABLE ratchet.checkpoint_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.checkpoint_schedules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.checkpoint_schedules
 USING(tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT,UPDATE ON ratchet.checkpoint_schedules TO ratchet_runtime;
-- +goose Down
DROP TABLE ratchet.checkpoint_schedules;
