"""Run real Authority browser acceptance with Playwright virtual authenticators."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/completion-a'


def main():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    node = shutil.which('node')
    if not node:
        raise SystemExit('Node.js required for Playwright tests.')

    environment = os.environ.copy()
    environment['RATCHET_PYTHON'] = sys.executable

    print('Running Phase A Authority browser acceptance suite...')
    result = subprocess.run(
        [node, str(ROOT / 'web/node_modules/playwright/cli.js'), 'test', 'e2e/authority.spec.ts'],
        cwd=ROOT / 'web',
        env=environment,
        capture_output=True,
        text=True,
    )

    output = result.stdout + result.stderr
    (PRIVATE / 'authority-browser-output.txt').write_text(output, encoding='utf-8')
    print(output)

    evidence = {
        'suite': 'authority-browser',
        'passed': result.returncode == 0,
        'exit_code': result.returncode,
    }
    (PRIVATE / 'authority-evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')

    if result.returncode != 0:
        raise SystemExit(result.returncode)

    print('Phase A Authority browser acceptance passed.')


if __name__ == '__main__':
    main()
