"""Exercise the independent Authority in a generated, owned scratch database."""
import os
from pathlib import Path
import subprocess
import sys
import uuid
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]


def main():
    runtime = os.environ['RATCHET_DATABASE_DSN']
    migrator = os.environ['RATCHET_MIGRATION_DSN']
    container = subprocess.check_output(['docker', 'compose', '--env-file', '.local/core.env',
                                         '-f', 'deploy/compose/compose.yaml', 'ps', '-q', 'postgres'],
                                        cwd=ROOT, text=True).strip()
    if not container:
        raise SystemExit('Start the core development PostgreSQL first.')
    database = 'ratchet_authority_test_' + uuid.uuid4().hex

    def sql(statement):
        subprocess.run(['docker', 'exec', '-i', container, 'psql', '-X', '-U', 'postgres',
                        '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '--quiet'], input=statement,
                       text=True, check=True)

    def dsn(value):
        parts = urlsplit(value)
        return urlunsplit((parts.scheme, parts.netloc, '/' + database, parts.query, ''))

    sql('CREATE DATABASE "' + database + '" OWNER ratchet_migrator;')
    try:
        environment = os.environ.copy()
        environment['RATCHET_AUTHORITY_DSN'] = dsn(runtime)
        environment['RATCHET_AUTHORITY_MIGRATION_DSN'] = dsn(migrator)
        result = subprocess.run([sys.executable, 'scripts/core-check.py', 'go', 'test', '-race',
                                 '-p=1', '-tags=integration', './internal/authority',
                                 '-count=1', '-timeout=3m'], cwd=ROOT, env=environment)
        return result.returncode
    finally:
        # This exact generated database is the only teardown target.
        sql('DROP DATABASE "' + database + '" WITH (FORCE);')


if __name__ == '__main__':
    sys.exit(main())
