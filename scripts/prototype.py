"""Build/start the real local prototype without host Go or drive bind mounts."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/prototype'
ENV = PRIVATE / 'prototype.env'

def run(arguments, **kwargs):
    return subprocess.run(arguments, cwd=ROOT, check=True, **kwargs)

def compose(*args, **kwargs):
    return run(['docker', 'compose', '--env-file', str(ENV), '-f', 'deploy/prototype.compose.yaml', *args], **kwargs)

def build():
    # The client sends this context; it does not require a Docker drive bind.
    # .dockerignore excludes local credentials, worktrees and generated binaries.
    for target,image in [('database','ratchet-prototype-db:local'),('runtime','ratchet-prototype:local')]:
        run(['docker','build','--target',target,'-f','deploy/prototype.Dockerfile','-t',image,'.'])

def export_credentials():
    result=compose('run','--rm','--no-deps','operator','ratchet-prototype','export',capture_output=True)
    json.loads(result.stdout)
    path=PRIVATE/'users.json';path.write_bytes(result.stdout);os.chmod(path,0o600)
    compose('cp','core:/data/core/ca.pem',str(PRIVATE/'ca.pem'))
    print('Private operator credentials:',path)
    print('Local public CA:',PRIVATE/'ca.pem')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['start','stop','restart','status','credentials','invite','renew-tls'])
    parser.add_argument('--no-build',action='store_true')
    parser.add_argument('--actor')
    parser.add_argument('--operation',choices=['enroll','revoke'],default='enroll')
    parser.add_argument('--credential',default='')
    args=parser.parse_args()
    PRIVATE.mkdir(parents=True,exist_ok=True)
    if not ENV.exists():
        if args.action not in ('start','restart'):raise SystemExit('Start the prototype first.')
        names=['POSTGRES_PASSWORD','RATCHET_MIGRATOR_PASSWORD','RATCHET_RUNTIME_PASSWORD','RATCHET_PROJECTOR_PASSWORD','SIM_BROKER_TOKEN']
        ENV.write_text(''.join(name+'='+secrets.token_hex(32)+'\n' for name in names),encoding='utf-8');os.chmod(ENV,0o600)
    if args.action in ('start','restart'):
        if args.action=='restart':compose('stop','connector','core','graph','simulator')
        if not args.no_build:build()
        compose('up','-d','--wait','postgres','nats')
        compose('run','--rm','--no-deps','operator','ratchet-prototype','init')
        compose('up','-d','--wait','simulator','graph','core','connector')
        export_credentials()
        print('Prototype: https://localhost:8444')
    elif args.action=='renew-tls':
        compose('stop','core','graph')
        compose('run','--rm','--no-deps','operator','ratchet-prototype','renew-tls')
        compose('up','-d','--wait','core','graph')
        export_credentials()
    elif args.action=='stop':compose('down')
    elif args.action=='status':compose('ps')
    elif args.action=='credentials':export_credentials()
    else:
        if not args.actor:raise SystemExit('--actor is required')
        result=compose('run','--rm','--no-deps','operator','ratchet-prototype','invite','--actor',args.actor,'--operation',args.operation,'--credential',args.credential,capture_output=True)
        value=json.loads(result.stdout)
        path=PRIVATE/'credential-authorization.json';path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');os.chmod(path,0o600)
        print('Private one-use authorization:',path)

if __name__=='__main__':main()
