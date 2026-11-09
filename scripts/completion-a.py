"""Operate the live-Authority completion profile without resetting any ledger."""
import argparse
import json
import io
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import tarfile

os.environ['RATCHET_LOCAL_PROFILE'] = 'completion-a'
from prototype import ENV, PRIVATE, ROOT, compose, export_credentials, run


def build():
    for target, image in [('database', 'ratchet-completion-a-db:local'),
                          ('runtime', 'ratchet-completion-a:local')]:
        run(['docker', 'build', '--target', target, '-f', 'deploy/prototype.Dockerfile',
             '-t', image, '.'])


def preserve_previous_tls():
    previous = ROOT / '.local/prototype/prototype.env'
    if not previous.exists():
        return []
    command = ['docker', 'compose', '--env-file', str(previous), '-f', 'deploy/prototype.compose.yaml']
    core = subprocess.check_output([*command, 'ps', '-q', 'core'], cwd=ROOT, text=True).strip()
    files = []
    if core:
        directory = PRIVATE / 'tls-transfer'
        directory.mkdir(exist_ok=True)
        for name in ['ca.pem', 'server.pem', 'server.key']:
            path = directory / name
            run(['docker', 'cp', core + ':/data/core/' + name, str(path)], capture_output=True)
            os.chmod(path, 0o600)
            files.append(path)
    # Stop only the explicitly named previous prototype; keep every data volume.
    run([*command, 'down'])
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['setup', 'start', 'restart', 'status', 'stop', 'credentials'])
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    PRIVATE.mkdir(parents=True, exist_ok=True)
    fresh = not ENV.exists()
    if fresh:
        if args.action != 'setup':
            raise SystemExit('Use setup, complete actual passkey genesis, then start.')
        names = ['POSTGRES_PASSWORD', 'RATCHET_MIGRATOR_PASSWORD', 'RATCHET_RUNTIME_PASSWORD',
                 'RATCHET_PROJECTOR_PASSWORD', 'SIM_BROKER_TOKEN', 'AUTH_POSTGRES_PASSWORD',
                 'AUTH_MIGRATOR_PASSWORD', 'AUTH_RUNTIME_PASSWORD', 'AUTH_PROJECTOR_PASSWORD']
        ENV.write_text(''.join(name + '=' + secrets.token_hex(32) + '\n' for name in names), encoding='utf-8')
        os.chmod(ENV, 0o600)
    if args.action in ('setup', 'start', 'restart'):
        if not args.no_build:
            build()
        files = [PRIVATE / 'tls-transfer' / name for name in ['ca.pem', 'server.pem', 'server.key'] if (PRIVATE / 'tls-transfer' / name).exists()]
        if fresh and not files:
            files = preserve_previous_tls()
        if files and len(files) != 3:
            raise SystemExit('Partial TLS transfer; preserve files and review before resuming.')
        compose('up', '-d', '--wait', 'postgres', 'authority-postgres', 'nats')
        if files:
            compose('create', 'operator')
            container = compose('ps', '--all', '-q', 'operator', capture_output=True).stdout.decode().strip()
            if not container:
                raise SystemExit('Owned TLS transfer container unavailable.')
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as bundle:
                for path in files:
                    raw = path.read_bytes()
                    info = tarfile.TarInfo(path.name)
                    info.size, info.uid, info.gid, info.mode = len(raw), 65532, 65532, 0o600
                    bundle.addfile(info, io.BytesIO(raw))
            run(['docker', 'cp', '--archive', '-', container + ':/data/core'], input=archive.getvalue())
            compose('rm', '-f', 'operator')
            for path in files:
                path.unlink()
        compose('run', '--rm', '--no-deps', 'operator', 'ratchet-prototype', 'init-live',
                '--containment-costs', '/app/completion-a-costs.json')
        compose('run', '--rm', '--no-deps', 'authority-init')
        compose('up', '-d', 'authority')
        if args.action == 'setup':
            compose('stop', 'core')
            compose('up', '-d', '--wait', 'enrollment')
            result = compose('run', '--rm', '--no-deps', 'operator', 'ratchet-prototype', 'export', capture_output=True)
            json.loads(result.stdout)
            (PRIVATE / 'users.json').write_bytes(result.stdout)
            os.chmod(PRIVATE / 'users.json', 0o600)
            compose('cp', 'enrollment:/data/core/ca.pem', str(PRIVATE / 'ca.pem'))
            compose('cp', 'enrollment:/data/core/server.pem', str(PRIVATE / 'server.pem'))
            result = compose('run', '--rm', '--no-deps', 'operator', 'cat', '/data/operator/initial-policy.json', capture_output=True)
            (PRIVATE / 'initial-policy.json').write_bytes(result.stdout)
            print('Genesis enrollment: https://localhost:8444; private accounts:', PRIVATE / 'users.json')
        else:
            deadline = time.monotonic() + 25
            while True:
                try:
                    compose('run', '--rm', '--no-deps', 'operator', 'ratchet-prototype', 'finalize-live', capture_output=True)
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise SystemExit('Live genesis/quorum policy export unavailable or root pin refused; preserve volumes and review Authority state.')
                    time.sleep(1)
            compose('stop', 'enrollment', 'core', 'graph', 'connector', 'simulator')
            compose('up', '-d', '--wait', 'simulator', 'graph', 'core', 'connector')
            export_credentials()
            print('Live Authority and verified control plane: https://localhost:8444')
    elif args.action == 'stop':
        compose('down')
    elif args.action == 'status':
        compose('ps')
    else:
        export_credentials()


if __name__ == '__main__':
    main()
