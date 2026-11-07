"""Issue private one-use tickets, then exercise the actual built HTTPS console."""
import json
import os
from pathlib import Path
import shutil
import subprocess
from prototype import PRIVATE, ROOT, compose


def main():
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
    result = subprocess.run([str(node), str(ROOT / 'web/node_modules/playwright/cli.js'),
                             'test', '-c', 'playwright.prototype.config.ts'],
                            cwd=ROOT / 'web', env=environment, capture_output=True, encoding='utf-8', errors='replace')
    output = result.stdout + result.stderr
    (PRIVATE / 'browser-output.txt').write_text(output, encoding='utf-8')
    for secret in [*tickets.values(), *(u['password'] for u in config['users'])]:
        output = output.replace(secret, '[redacted]')
    print(output.encode('ascii', 'backslashreplace').decode('ascii'))
    if result.returncode:
        raise SystemExit(result.returncode)
    print('Browser evidence:', PRIVATE / 'browser-evidence.json')


if __name__ == '__main__':
    main()
