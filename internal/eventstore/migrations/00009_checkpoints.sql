-- +goose Up
CREATE TABLE ratchet.checkpoint_candidates (
 tenant_id text NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32),
 command_id uuid NOT NULL, input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 document bytea NOT NULL, event_position bigint NOT NULL,
 PRIMARY KEY(tenant_id,digest), UNIQUE(tenant_id,command_id),
 FOREIGN KEY(tenant_id,event_position) REFERENCES ratchet.events(tenant_id,sequence)
);
CREATE TABLE ratchet.accepted_checkpoints (
 tenant_id text NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32),
 from_sequence bigint NOT NULL CHECK(from_sequence>0),
 to_sequence bigint NOT NULL CHECK(to_sequence>=from_sequence),
 document bytea NOT NULL, event_position bigint NOT NULL CHECK(event_position>to_sequence),
 PRIMARY KEY(tenant_id,digest), UNIQUE(tenant_id,from_sequence), UNIQUE(tenant_id,to_sequence),
 FOREIGN KEY(tenant_id,digest) REFERENCES ratchet.checkpoint_candidates(tenant_id,digest),
 FOREIGN KEY(tenant_id,event_position) REFERENCES ratchet.events(tenant_id,sequence)
);
CREATE TRIGGER checkpoint_candidates_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.checkpoint_candidates
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
CREATE TRIGGER accepted_checkpoints_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ratchet.accepted_checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION ratchet.reject_history_mutation();
ALTER TABLE ratchet.checkpoint_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.checkpoint_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE ratchet.accepted_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratchet.accepted_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ratchet.checkpoint_candidates
 USING (tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
CREATE POLICY tenant_isolation ON ratchet.accepted_checkpoints
 USING (tenant_id=current_setting('ratchet.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('ratchet.tenant_id',true));
GRANT SELECT,INSERT ON ratchet.checkpoint_candidates,ratchet.accepted_checkpoints TO ratchet_runtime;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'checkpoint evidence migration is irreversible'; END $$;
-- +goose StatementEnd
