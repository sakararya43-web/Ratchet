-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF to_regclass('ratchet_jobs.river_job') IS NOT NULL THEN
  UPDATE ratchet_jobs.river_job
  SET queue='r_' || encode(substring(sha256(convert_to(args->>'tenant_id','UTF8')) from 1 for 24),'hex')
  WHERE kind='ratchet_change_v1' AND queue='core'
    AND jsonb_typeof(args->'tenant_id')='string' AND args->>'tenant_id'<>'';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'tenant job queue migration is irreversible'; END $$;
-- +goose StatementEnd
