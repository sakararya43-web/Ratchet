"""Run native browser governance against the explicit live-genesis profile."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

os.environ['RATCHET_LOCAL_PROFILE'] = 'completion-a'
from prototype import PRIVATE, ROOT


def main():
    environment = os.environ.copy()
    environment['NODE_EXTRA_CA_CERTS'] = str(PRIVATE / 'ca.pem')
    environment['RATCHET_PYTHON'] = sys.executable
    node = shutil.which('node')
    if not node:
        raise SystemExit('Node is required for native browser acceptance.')
    process = subprocess.run([node, str(ROOT / 'web/node_modules/playwright/cli.js'), 'test',
                              '-c', 'playwright.prototype.config.ts', 'authority.spec.ts'],
                             cwd=ROOT / 'web', env=environment, capture_output=True,
                             encoding='utf-8', errors='replace')
    output = process.stdout + process.stderr
    (PRIVATE / 'authority-browser-output.txt').write_text(output, encoding='utf-8')
    users = json.loads((PRIVATE / 'users.json').read_text(encoding='utf-8'))
    for user in users['users']:
        for field in ['password', 'enrollment_ticket']:
            if user.get(field):
                output = output.replace(user[field], '[redacted]')
    authorization = PRIVATE / 'credential-authorization.json'
    if authorization.exists():
        output = output.replace(json.loads(authorization.read_text(encoding='utf-8'))['ticket'], '[redacted]')
    devices = PRIVATE / 'virtual-authenticators.json'
    if devices.exists():
        for credentials in json.loads(devices.read_text(encoding='utf-8')).values():
            for credential in credentials:
                if credential.get('privateKey'):
                    output = output.replace(credential['privateKey'], '[redacted virtual key]')
    print(output.encode('ascii', 'backslashreplace').decode('ascii'))
    return process.returncode


if __name__ == '__main__':
    sys.exit(main())
