"""Operate the bounded access-review demo; keep every existing trust root and ledger."""
import argparse
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import urllib.request
import urllib.error

os.environ['RATCHET_LOCAL_PROFILE'] = 'prototype'

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local' / 'demo-ready'
PROFILE = ROOT / '.local' / 'prototype'


def run(*arguments):
    return subprocess.run(arguments, cwd=ROOT, check=True)


def ready():
    core = subprocess.check_output(['docker', 'compose', '--env-file', str(PROFILE / 'prototype.env'),
                                   '-f', 'deploy/prototype.compose.yaml', 'ps', '--status', 'running', '-q', 'core'],
                                  cwd=ROOT, stderr=subprocess.PIPE, text=True).strip()
    if not core:
        raise RuntimeError('The selected prototype profile is not running. Run python scripts/demo.py start.')
    context = ssl.create_default_context(cafile=str(PROFILE / 'ca.pem'))
    with urllib.request.urlopen('https://localhost:8444/readyz', context=context, timeout=10) as response:
        result = json.load(response)
    if not result.get('ready'):
        raise RuntimeError('Prototype is not ready. Run python scripts/demo.py start.')
    return result


def probes():
    ready()
    result = {}
    for name, endpoint in [('finance_report', 'finance-report/read'), ('wallet_signing', 'wallet/sign')]:
        request = urllib.request.Request('http://127.0.0.1:58085/api/v1/business/' + endpoint,
                                         data=json.dumps({'session_id': 'session:intern-workstation-1', 'amount_usd': 100}).encode(),
                                         headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                result[name] = response.status
        except urllib.error.HTTPError as error:
            if error.code != 403:
                raise
            result[name] = error.code
    print(json.dumps(result, indent=2))


def browser(action, headed):
    ready()
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node is required for the prepared presenter browser.')
    environment = os.environ.copy()
    environment['NODE_EXTRA_CA_CERTS'] = str(PROFILE / 'ca.pem')
    environment['RATCHET_PYTHON'] = sys.executable
    environment['RATCHET_LOCAL_PROFILE'] = 'prototype'
    command = [node, 'scripts/demo-browser.mjs', action]
    if headed:
        command.append('--headed')
    run_environment = dict(cwd=ROOT, env=environment)
    subprocess.run(command, check=True, **run_environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'status', 'probe', 'prepare', 'present', 'close', 'rehearse', 'record'])
    parser.add_argument('--headed', action='store_true', help='Show rehearsal/recording browser windows.')
    args = parser.parse_args()
    PRIVATE.mkdir(parents=True, exist_ok=True)
    if args.action == 'start':
        candidate_path = PRIVATE / 'candidate.json'
        if candidate_path.exists():
            candidate = json.loads(candidate_path.read_text(encoding='utf-8'))
            for image, tag in [(candidate['runtime_image_id'], 'ratchet-prototype:local'),
                               (candidate['database_image_id'], 'ratchet-prototype-db:local')]:
                available = subprocess.run(['docker', 'image', 'inspect', image], cwd=ROOT,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if available.returncode:
                    raise RuntimeError('The frozen demo image is missing. Rebuild and revalidate before replacing the candidate.')
                run('docker', 'tag', image, tag)
        # Only the explicitly named alternate Ratchet profile is parked. Its
        # containers can be recreated with completion-a.py; volumes are retained.
        completion = ROOT / '.local/completion-a/prototype.env'
        if completion.exists():
            run(sys.executable, 'scripts/completion-a.py', 'stop')
        run(sys.executable, 'scripts/prototype.py', 'start', *(['--no-build'] if candidate_path.exists() else []))
        print('Demo ready: https://localhost:8444')
    elif args.action == 'close':
        (PRIVATE / 'presenter-stop').write_text('close\n', encoding='utf-8')
        print('Presenter close requested. Runtime services and data are preserved.')
    elif args.action == 'status':
        print(json.dumps(ready(), indent=2))
    elif args.action == 'probe':
        probes()
    else:
        browser(args.action, args.headed or args.action == 'present')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        # Command errors contain arguments/exit codes, never private file contents.
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
