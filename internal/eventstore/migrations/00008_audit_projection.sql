-- +goose Up
CREATE TABLE ratchet.audit_projection (
 tenant_id text NOT NULL, sequence bigint NOT NULL CHECK(sequence>0),
 actor_reference text NOT NULL, request_id text NOT NULL, incident_id text NOT NULL,
 resource_refs text[] NOT NULL, recorded_at timestamptz NOT NULL,
 display jsonb NOT NULL, PRIMARY KEY(tenant_id,sequence)
);
CREATE INDEX audit_actor_time ON ratchet.audit_projection(tenant_id,actor_reference,recorded_at,sequence);
CREATE INDEX audit_request ON ratchet.audit_projection(tenant_id,request_id,sequence);
CREATE INDEX audit_incident ON ratchet.audit_projection(tenant_id,incident_id,sequence);
CREATE INDEX audit_resources ON ratchet.audit_projection USING gin(resource_refs);
ALTER TABLE ratchet.audit_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.audit_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.audit_projection
 USING (tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT,UPDATE,DELETE ON ratchet.audit_projection TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'audit projection migration is irreversible'; END $$;
-- +goose StatementEnd
