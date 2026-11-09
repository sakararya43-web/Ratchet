"""Issue private one-use tickets, then exercise the actual built HTTPS console."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime
from prototype import PRIVATE, ROOT, compose


def main():
    # Four independent logins share the loopback source IP. Respect the real
    # five-attempt/minute protection when an operator repeats the whole suite.
    report = PRIVATE / 'browser-results.json'
    if report.exists():
        started = json.loads(report.read_text(encoding='utf-8')).get('stats', {}).get('startTime')
        if started:
            pause = 65 - (time.time() - datetime.fromisoformat(started.replace('Z', '+00:00')).timestamp())
            if pause > 0:
                print('Waiting for the existing login rate window before repeating acceptance.', flush=True)
                while pause > 0:
                    duration = min(30, pause)
                    time.sleep(duration)
                    pause -= duration
    config = json.loads((PRIVATE / 'users.json').read_text(encoding='utf-8'))
    tickets = {}
    for user in config['users']:
        result = compose('run', '--rm', '--no-deps', 'operator', 'ratchet-prototype',
                         'invite', '--actor', user['actor_id'], capture_output=True)
        tickets[user['actor_id']] = json.loads(result.stdout)['ticket']
    path = PRIVATE / 'browser-tickets.json'
    path.write_text(json.dumps(tickets) + '\n', encoding='utf-8')
    os.chmod(path, 0o600)
    compose('cp', 'core:/data/core/server.pem', str(PRIVATE / 'server.pem'))
    node = Path(shutil.which('node'))
    environment = os.environ.copy()
    environment['NODE_EXTRA_CA_CERTS'] = str(PRIVATE / 'ca.pem')
    environment['RATCHET_PYTHON'] = sys.executable
    result = subprocess.run([str(node), str(ROOT / 'web/node_modules/playwright/cli.js'),
                             'test', '-c', 'playwright.prototype.config.ts', 'prototype.spec.ts'],
                            cwd=ROOT / 'web', env=environment, capture_output=True, encoding='utf-8', errors='replace')
    output = result.stdout + result.stderr
    (PRIVATE / 'browser-output.txt').write_text(output, encoding='utf-8')
    authorization = PRIVATE / 'credential-authorization.json'
    if authorization.exists():
        output = output.replace(json.loads(authorization.read_text(encoding='utf-8'))['ticket'], '[redacted]')
    for secret in [*tickets.values(), *(u['password'] for u in config['users'])]:
        output = output.replace(secret, '[redacted]')
    print(output.encode('ascii', 'backslashreplace').decode('ascii'))
    if result.returncode:
        raise SystemExit(result.returncode)
    print('Browser evidence:', PRIVATE / 'browser-evidence.json')


if __name__ == '__main__':
    main()
