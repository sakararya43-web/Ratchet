-- +goose Up
CREATE TABLE ratchet.containment_plans (
 tenant_id text NOT NULL, plan_id uuid NOT NULL,
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 document jsonb NOT NULL, event_position bigint NOT NULL,
 PRIMARY KEY(tenant_id,plan_id)
);
CREATE TRIGGER containment_plans_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.containment_plans
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
ALTER TABLE ratchet.containment_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.containment_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.containment_plans
 USING (tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT ON ratchet.containment_plans TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'containment plan evidence migration is irreversible'; END $$;
-- +goose StatementEnd
