"""Verify a real core image, produce an SBOM and check local OCI signatures.

Uses an owned loopback registry and disposable signing keys, never a release key.
The public evidence is retained in .local/phase7-supply; private keys are temporary.
"""
import hashlib
import json
import os
import socket
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.local/phase7-supply'
OUT.mkdir(parents=True, exist_ok=True)


def tool(image, folder, *args, check=True, capture_output=False):
    name = 'ratchet-supply-tool-' + uuid.uuid4().hex[:10]
    run('docker', 'create', '--name', name, '--user', '0', '--network', 'host', '--workdir', '/data', '--env', 'COSIGN_PASSWORD=', image, *args, stdout=subprocess.DEVNULL)
    try:
        run('docker', 'cp', str(folder) + '/.', name + ':/data')
        result = subprocess.run(['docker', 'start', '--attach', name], capture_output=capture_output, text=True)
        code = int(subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', name]))
        result.returncode = code or result.returncode
        if check and result.returncode: raise RuntimeError('supply tool failed: ' + (result.stderr or 'see output'))
        if not result.returncode: run('docker', 'cp', name + ':/data/.', str(folder))
        return result
    finally:
        run('docker', 'rm', '--force', name, stdout=subprocess.DEVNULL)


def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)


def main():
    syft = 'anchore/syft:v1.57.0@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a'
    cosign = 'ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d'
    image = 'ratchet-core:phase7'
    inspect = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
    if inspect['Config']['User'] != '65532:65532':
        raise RuntimeError('core image must run as nonroot')
    # Exercise the image as configured, read-only and without Linux capabilities.
    invocation = subprocess.run(['docker', 'run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', image], capture_output=True, text=True)
    if invocation.returncode != 1 or 'usage: ratchetd' not in invocation.stderr:
        raise RuntimeError('core image did not execute expected binary')
    with tempfile.TemporaryDirectory(prefix='ratchet-supply-') as directory:
        private = Path(directory)
        archive = private / 'core-image.tar'
        run('docker', 'save', '--output', str(archive), image)
        tool(syft, private, 'docker-archive:/data/core-image.tar', '-o', 'spdx-json=/data/core.spdx.json')
        (OUT / 'core.spdx.json').write_bytes((private / 'core.spdx.json').read_bytes())
        sbom = json.loads((OUT / 'core.spdx.json').read_text(encoding='utf-8'))
        if not sbom.get('packages') or not any('Ratchet' in p['name'] for p in sbom['packages']):
            raise RuntimeError('SBOM omitted actual core Go modules')
        registry = 'ratchet-signature-' + uuid.uuid4().hex[:10]
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        mapping = f'127.0.0.1:{port}'
        run('docker', 'run', '--detach', '--name', registry, '--network', 'host', '--env', 'REGISTRY_HTTP_ADDR=' + mapping, 'registry:3@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c', stdout=subprocess.DEVNULL)
        try:
            for attempt in range(40):
                probe = subprocess.run(['docker','exec',registry,'wget','-q','--spider',f'http://{mapping}/v2/'], capture_output=True)
                if probe.returncode == 0:
                    break
                if attempt == 39: raise RuntimeError('owned local registry did not become ready')
                time.sleep(.25)
            reference = mapping + '/ratchet-core:phase7'
            run('docker', 'tag', image, reference)
            run('docker', 'push', reference, stdout=subprocess.DEVNULL)
            digest = json.loads(subprocess.check_output(['docker', 'inspect', reference]))[0]['RepoDigests']
            pinned = next(d for d in digest if d.startswith(mapping + '/'))
            keys = private / 'keys'
            keys.mkdir()
            for prefix in ('signer', 'wrong'):
                tool(cosign, keys, 'generate-key-pair', '--output-key-prefix', '/data/' + prefix)
            tool(cosign, keys, 'signing-config', 'create', '--no-default-fulcio', '--no-default-oidc', '--no-default-rekor', '--no-default-tsa', '--out', '/data/local-signing.json')
            sbom_hash = hashlib.sha256((OUT / 'core.spdx.json').read_bytes()).hexdigest()
            tool(cosign, keys, 'sign', '--yes', '--key', '/data/signer.key', '--signing-config', '/data/local-signing.json', '--allow-insecure-registry', '-a', 'sbom-sha256=' + sbom_hash, pinned)
            verification = tool(cosign, keys, 'verify', '--key', '/data/signer.pub', '--insecure-ignore-tlog', '--allow-insecure-registry', '-a', 'sbom-sha256=' + sbom_hash, pinned, capture_output=True)
            wrong = tool(cosign, keys, 'verify', '--key', '/data/wrong.pub', '--insecure-ignore-tlog', '--allow-insecure-registry', pinned, check=False, capture_output=True)
            if wrong.returncode == 0: raise RuntimeError('wrong image signing key accepted')
            wrong_sbom = tool(cosign, keys, 'verify', '--key', '/data/signer.pub', '--insecure-ignore-tlog', '--allow-insecure-registry', '-a', 'sbom-sha256=' + '0'*64, pinned, check=False, capture_output=True)
            if wrong_sbom.returncode == 0: raise RuntimeError('wrong SBOM commitment accepted')
            (OUT / 'image-verification.json').write_text(verification.stdout, encoding='utf-8')
            (OUT / 'signer.pub').write_bytes((keys / 'signer.pub').read_bytes())
            (OUT / 'summary.json').write_text(json.dumps({'image': pinned, 'local_image_id': inspect['Id'], 'user': inspect['Config']['User'], 'size': inspect['Size'], 'sbom_packages': len(sbom['packages']), 'sbom_sha256': sbom_hash, 'image_signature_verified': True, 'wrong_key_rejected': True, 'wrong_sbom_rejected': True, 'transparency': 'local disposable signing key; no public log or production identity claim'}, indent=2) + '\n', encoding='utf-8')
            print('PASS: real nonroot image, SBOM and OCI signature; wrong key refused')
        finally:
            run('docker', 'rm', '--force', registry, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
