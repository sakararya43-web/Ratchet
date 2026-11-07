"""Run the remaining Phase 7 gates sequentially and retain exact outcomes.

The full integration/race suite is a separate explicit long-running gate; this
script never labels it passed merely because these additional checks succeed.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.local/phase7-checks'
OUT.mkdir(parents=True, exist_ok=True)
runner = [sys.executable, 'scripts/core-check.py']
checks = [
    ('modules', runner + ['go', 'mod', 'verify']),
    ('vet', runner + ['go', 'vet', './...']),
    ('lint', runner + ['--image', 'golangci/golangci-lint:v2.15.0', 'golangci-lint', 'run', '--config', '.golangci-core.yml', '--max-same-issues=0', '--max-issues-per-linter=0', './...']),
    ('main-integration-race', runner + ['go', 'test', '-race', '-p=1', '-tags=integration', './...', '-count=1', '-timeout=10m']),
    ('properties', runner + ['go', 'test', '-p=1', './internal/graph', './internal/domain', './internal/workflow', '-count=1', '-rapid.seed=20261105', '-rapid.checks=300']),
    ('domain-boundaries', runner + ['python3', 'scripts/core-boundaries.py']),
    ('vulnerabilities', runner + ['go', 'run', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0', './...']),
    ('opa', runner + ['--image', 'openpolicyagent/opa:1.22.0-static', 'test', '--fail-on-empty', '-v', 'policies/']),
    ('buf-lint', runner + ['--image', 'bufbuild/buf:1.75.0', 'lint']),
    ('buf-breaking-peer', runner + ['--image', 'bufbuild/buf:1.75.0', 'breaking', '--against', 'testdata/contracts/sakar-v1.binpb']),
    ('fuzz-auth', runner + ['go', 'test', '-p=1', '-parallel=1', './internal/api', '-run=^$', '-fuzz=FuzzAuthenticationDecoder', '-fuzztime=30s']),
    ('fuzz-native', runner + ['go', 'test', '-p=1', '-parallel=1', './internal/domain/kubernetes', '-run=^$', '-fuzz=FuzzNormalizedStateAndMutation', '-fuzztime=30s']),
    ('actual-peer-conformance', runner + ['--peer', 'go', 'test', '-race', '-p=1', '-tags=peerintegration', './internal/connector/conformance', '-count=1', '-timeout=5m']),
    ('peer-scenarios', runner + ['--peer', 'go', 'test', '-race', '-p=1', '-tags=peerintegration', './e2e/scenarios/...', '-count=1', '-timeout=3m']),
    ('combined-ordinary-race', runner + ['--peer', 'go', 'test', '-race', '-p=1', './...', '-count=1', '-timeout=5m']),
    ('actual-authority-checkpoint', runner + ['--peer', 'go', 'test', '-race', '-p=1', '-tags=integration,peerintegration', './internal/workflow', '-run=TestPeerCheckpointHTTPSubmissionSigningAndRestart', '-count=1', '-timeout=4m']),
    ('process-smoke', runner + ['sh', 'scripts/core-smoke.sh']),
    ('database-backup-restore', [sys.executable, 'scripts/core-backup-smoke.py']),
]


def main():
    selected = sys.argv[1:]
    unknown = set(selected) - {name for name, _ in checks}
    if unknown: raise SystemExit('Unknown checks: ' + ', '.join(sorted(unknown)))
    report_path = OUT / 'results.json'
    previous = json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else {}
    # Keep earlier failures and checks when only a selected gate is rerun.
    report = previous if 'runs' in previous else {'runs': [previous] if previous else []}
    run = {
        'candidate': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
        'checks': [],
    }
    run_dir = OUT / uuid.uuid4().hex
    run_dir.mkdir()
    report['runs'].append(run)
    for name, command in checks:
        if selected and name not in selected: continue
        print('START:', name, flush=True)
        started = time.monotonic()
        log_path = run_dir / (name + '.log')
        with log_path.open('w', encoding='utf-8') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
            for line in process.stdout:
                log.write(line);log.flush();print(line, end='', flush=True)
            code = process.wait()
        run['checks'].append({'name':name,'command':command[1:] if command[0] == sys.executable else command,'exit_code':code,'seconds':round(time.monotonic()-started,2),'log':str(log_path.relative_to(OUT)), 'log_sha256':hashlib.sha256(log_path.read_bytes()).hexdigest()})
        report_path.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
        print(('PASS: ' if code == 0 else 'FAIL: ') + name, flush=True)
        if code: return code
    return 0


if __name__ == '__main__': sys.exit(main())
