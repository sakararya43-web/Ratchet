"""Verify a real local PostgreSQL custom-format backup in an owned scratch DB.

Writers must be quiesced. Original data is never dropped or restored over.
All core/River tables are compared by count and ordered SHA-256 row commitments.
The private dump lives only in the owned PostgreSQL container and is removed.
"""
import json
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
SQL = """
CREATE TEMP TABLE verification(schema_name text,table_name text,rows bigint,digest text);
DO $body$ DECLARE t record; n bigint; d text; BEGIN
FOR t IN SELECT schemaname,tablename FROM pg_tables WHERE schemaname IN ('ratchet','ratchet_jobs') ORDER BY 1,2 LOOP
EXECUTE format('SELECT count(*), encode(sha256(convert_to(coalesce(string_agg(h, '''' ORDER BY h),''''),''UTF8'')),''hex'') FROM (SELECT encode(sha256(convert_to(row_to_json(r)::text,''UTF8'')),''hex'') h FROM %I.%I r) q',t.schemaname,t.tablename) INTO n,d;
INSERT INTO verification VALUES(t.schemaname,t.tablename,n,d);
END LOOP; END $body$;
SELECT row_to_json(v)::text FROM verification v ORDER BY schema_name,table_name;
"""


def main():
    container = subprocess.check_output(["docker", "compose", "--env-file", ".local/core.env", "-f", "deploy/compose/compose.yaml", "ps", "-q", "postgres"], cwd=ROOT, text=True).strip()
    if not container:
        raise SystemExit("owned core PostgreSQL must already be running")
    token = uuid.uuid4().hex
    database = "ratchet_restore_" + token
    dump = "/tmp/ratchet-backup-" + token + ".dump"

    def sql(db, statement):
        return subprocess.check_output(["docker", "exec", "-i", container, "psql", "-X", "--quiet", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", db], input=statement, text=True)

    created = False
    try:
        before = sql("ratchet", SQL)
        subprocess.run(["docker", "exec", "--user", "postgres", container, "pg_dump", "-U", "postgres", "-d", "ratchet", "--format=custom", "--file=" + dump], check=True)
        sql("postgres", 'CREATE DATABASE "' + database + '" OWNER ratchet_migrator;')
        created = True
        subprocess.run(["docker", "exec", "--user", "postgres", container, "pg_restore", "-U", "postgres", "--exit-on-error", "--dbname=" + database, dump], check=True)
        after = sql(database, SQL)
        if before != after:
            raise SystemExit("restored table commitments differ; restore refused (or source writers were not quiesced)")
        tables = [json.loads(line) for line in after.splitlines() if line]
        output = ROOT / ".local" / "phase7-backup.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps({"custom_format_backup": True, "isolated_restore": True, "all_table_commitments_match": True, "tables": len(tables), "rows": sum(t["rows"] for t in tables)}, indent=2) + "\n")
        print("PASS: isolated PostgreSQL backup/restore; all", len(tables), "core/job table commitments match")
    finally:
        # Both names are generated here, never accepted as deletion targets.
        if created:
            sql("postgres", 'DROP DATABASE "' + database + '" WITH (FORCE);')
        subprocess.run(["docker", "exec", container, "rm", "-f", "--", dump], check=True)


if __name__ == "__main__":
    main()
