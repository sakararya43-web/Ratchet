"""Freeze tested local demo images/source and package only allowlisted public artifacts."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.local/demo-ready'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')


def main():
    verification = json.loads((OUT / 'verification.json').read_text(encoding='utf-8'))
    if not verification['checks'] or any(c['status'] != 'passed' for c in verification['checks']):
        raise RuntimeError('Final verification contains an open or failed required demo check.')
    proof = json.loads((OUT / 'recording-evidence.json').read_text(encoding='utf-8'))
    expected = {'initial_finance_status': 403, 'initial_wallet_status': 403,
                'self_review_status': 403, 'self_approval_status': 403,
                'finance_after_owner_status': 200, 'wallet_after_one_approval_status': 403,
                'wallet_after_two_approvals_status': 200, 'sensitive_approval_events': 2,
                'wallet_after_revocation_status': 403, 'finance_after_revocation_status': 403}
    if any(proof.get(k) != v for k, v in expected.items()) or proof['browser_runtime_errors']:
        raise RuntimeError('The actual recorded journey did not satisfy the demonstration.')
    if proof['duplicate_approval_status'] == 200 or len(proof['scenes']) != 15 or proof['recording']['duration_seconds'] < 300:
        raise RuntimeError('Recording or distinct-quorum evidence is incomplete.')

    assets = ROOT / 'internal/webassets/assets'
    manifest_raw = (assets / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    for name, wanted in manifest['sources'].items():
        if digest((ROOT / 'web' / name).read_bytes().replace(b'\r\n', b'\n')) != wanted:
            raise RuntimeError('Frontend source differs from the embedded manifest: ' + name)
    for name, wanted in manifest['files'].items():
        if digest((assets / name).read_bytes()) != wanted:
            raise RuntimeError('Embedded artifact differs from its manifest: ' + name)
    tls = ssl.create_default_context(cafile=str(ROOT / '.local/prototype/ca.pem'))
    # The production SPA deliberately serves only committed public assets, not
    # its build manifest. Verify each actual served artifact against that manifest.
    for name, wanted in manifest['files'].items():
        with urllib.request.urlopen('https://localhost:8444/' + name, context=tls, timeout=10) as response:
            if digest(response.read()) != wanted:
                raise RuntimeError('Running console differs from the verified artifact: ' + name)

    compose = ['docker', 'compose', '--env-file', str(ROOT / '.local/prototype/prototype.env'),
               '-f', 'deploy/prototype.compose.yaml']
    core = command(*compose, 'ps', '-q', 'core')
    database = command(*compose, 'ps', '-q', 'postgres')
    runtime_id = command('docker', 'inspect', '--format', '{{.Image}}', core)
    database_info = json.loads(command('docker', 'inspect', database))[0]
    database_ref = database_info['Config']['Image']
    database_id = command('docker', 'image', 'inspect', '--format', '{{.Id}}', database_ref)
    # Docker Desktop's containerd store can retain a legacy .Image identifier
    # while reporting the current, correct platform manifest separately.
    descriptor = database_info['ImageManifestDescriptor']
    platform = descriptor['platform']['os'] + '/' + descriptor['platform']['architecture']
    selected = json.loads(command('docker', 'image', 'inspect', '--platform', platform, database_ref))[0]
    if selected['Descriptor']['digest'] != descriptor['digest']:
        raise RuntimeError('Selected database image does not match the running platform manifest.')
    if proof.get('runtime_image_id') != runtime_id or proof.get('embedded_manifest_sha256') != digest(manifest_raw):
        raise RuntimeError('The recording was not made against the current exact runtime/artifact.')
    for image, tag in [(runtime_id, 'ratchet-prototype:demo-ready'), (database_id, 'ratchet-prototype-db:demo-ready')]:
        subprocess.run(['docker', 'tag', image, tag], cwd=ROOT, check=True)

    names = command('git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z').split('\0')
    sources = {}
    with zipfile.ZipFile(OUT / 'source-final.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(set(filter(None, names))):
            path = ROOT / name
            if path.is_file() and not name.startswith('.local/'):
                raw = path.read_bytes()
                sources[name] = digest(raw)
                archive.writestr(name, raw)
    write_json(OUT / 'source-final-manifest.json', sources)
    candidate = {'created_at': datetime.now(timezone.utc).isoformat(),
                 'scope': 'Focused local access-review prototype; not full product acceptance',
                 'base_commit': command('git', 'rev-parse', 'HEAD'),
                 'includes_uncommitted_source': bool(command('git', 'status', '--porcelain')),
                 'runtime_image_id': runtime_id, 'database_image_id': database_id,
                 'database_platform_manifest': descriptor['digest'],
                 'runtime_tag': 'ratchet-prototype:demo-ready', 'database_tag': 'ratchet-prototype-db:demo-ready',
                 'source_archive_sha256': digest((OUT / 'source-final.zip').read_bytes()),
                 'source_manifest_sha256': digest((OUT / 'source-final-manifest.json').read_bytes()),
                 'embedded_manifest_sha256': digest(manifest_raw),
                 'recording_sha256': digest((OUT / 'ratchet-demo.webm').read_bytes()),
                 'recording_duration_seconds': proof['recording']['duration_seconds']}
    write_json(OUT / 'candidate.json', candidate)
    shutil.copyfile(ROOT / 'scripts/demo-player.html', OUT / 'index.html')
    shutil.copyfile(ROOT / 'docs/ishaan/demo-ready-walkthrough.md', OUT / 'demo-ready-walkthrough.md')
    transcript = '\n\n'.join(scene['title'] + '\n' + scene['detail'] for scene in proof['scenes'])
    (OUT / 'transcript.txt').write_text(transcript + '\n', encoding='utf-8')
    public = ['index.html', 'ratchet-demo.webm', 'recording-evidence.json', 'verification.json',
              'candidate.json', 'demo-ready-walkthrough.md', 'transcript.txt']
    public += ['screenshots/' + scene['key'] + '.png' for scene in proof['scenes']]
    hashes = {name: digest((OUT / name).read_bytes()) for name in public}
    (OUT / 'SHA256SUMS.txt').write_text(''.join(value + '  ' + name + '\n' for name, value in hashes.items()), encoding='utf-8')
    public.append('SHA256SUMS.txt')
    with zipfile.ZipFile(OUT / 'RATCHET-demo.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in public:
            archive.write(OUT / name, name)
    with zipfile.ZipFile(OUT / 'RATCHET-demo.zip') as archive:
        if set(archive.namelist()) != set(public) or archive.testzip() is not None:
            raise RuntimeError('Shareable archive verification failed.')
    write_json(OUT / 'package-receipt.json', {'archive_sha256': digest((OUT / 'RATCHET-demo.zip').read_bytes()),
                                           'files': public, 'private_runtime_artifacts_included': False})
    print('Frozen runtime:', runtime_id)
    print('Source-only candidate:', OUT / 'source-final.zip')
    print('Shareable demo:', OUT / 'RATCHET-demo.zip', '(' + str(len(public)) + ' allowlisted files)')


if __name__ == '__main__':
    main()
