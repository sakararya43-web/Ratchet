"""Build the real peer-derived console and bind embedded files to their source."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
web = root / 'web'
# Normalize before Vite computes HTML transformation offsets. Normalizing only
# its output can leave a lone CR introduced while transforming CRLF input.
entry = web / 'index.html'
entry.write_bytes(entry.read_bytes().replace(b'\r\n', b'\n').replace(b'\r', b'\n'))
npm = [shutil.which('npm')]
if os.name == 'nt':
    node = Path(shutil.which('node'))
    npm = [str(node), str(node.parent / 'node_modules/npm/bin/npm-cli.js')]
for command in (['ci'], ['test'], ['run', 'build'], ['audit', '--audit-level=low']):
    subprocess.run([*npm, *command], cwd=web, check=True)
target = root / 'internal/webassets/assets'
target.mkdir(parents=True, exist_ok=True)
# Remove only old generated regular files in the fixed artifact directory.
for path in target.rglob('*'):
    if path.is_file():
        path.unlink()
shutil.copytree(web / 'dist', target, dirs_exist_ok=True)
# Vite preserves the checkout's HTML newlines. Embed the same bytes on Windows
# and Linux so the integrity manifest is reproducible across release builders.
index = target / 'index.html'
index.write_bytes(index.read_bytes().replace(b'\r\n', b'\n'))
sources = {str(p.relative_to(web)).replace('\\', '/'): hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
           for p in web.rglob('*') if p.is_file() and not {'node_modules', 'dist'} & set(p.relative_to(web).parts)}
files = {str(p.relative_to(target)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in target.rglob('*') if p.is_file()}
(target / 'manifest.json').write_text(json.dumps({'upstream': 'd823a106bb4a64b0fe54e366c41029ccbd8dfda8', 'sources': sources, 'files': files}, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
print('Built and recorded actual web assets:', len(files))
