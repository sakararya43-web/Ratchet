-- +goose Up
CREATE TABLE ratchet.native_change_plans (
 tenant_id text NOT NULL, request_id uuid NOT NULL,
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 document jsonb NOT NULL, event_position bigint NOT NULL,
 PRIMARY KEY(tenant_id,request_id)
);
ALTER TABLE ratchet.native_change_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.native_change_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.native_change_plans
 USING(tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('ratchet.tenant_id',true));
CREATE TRIGGER native_change_plans_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.native_change_plans
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
GRANT SELECT,INSERT ON ratchet.native_change_plans TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'native change evidence migration is irreversible'; END $$;
-- +goose StatementEnd
