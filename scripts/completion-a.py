"""Isolated Phase A Authority setup and lifecycle management."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/completion-a'
ENV = PRIVATE / 'completion-a.env'


def run(cmd, **kwargs):
    return subprocess.run(cmd, cwd=ROOT, check=True, **kwargs)


def compose(*args, **kwargs):
    return run(['docker', 'compose', '-f', 'deploy/completion-a.compose.yaml', *args], **kwargs)


def main():
    parser = argparse.ArgumentParser(description="Manage Phase A Authority environment")
    parser.add_argument('action', choices=['setup', 'start', 'stop', 'restart', 'status'])
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()

    PRIVATE.mkdir(parents=True, exist_ok=True)

    if args.action == 'setup':
        print('Setting up isolated Authority test environment...')
        compose('up', '-d', '--wait', 'postgres')
        print('PostgreSQL ready for Authority migrations.')
    elif args.action in ('start', 'restart'):
        if args.action == 'restart':
            compose('stop', 'authority')
        build_flags = [] if args.no_build else ['--build']
        compose('up', '-d', '--wait', *build_flags, 'postgres', 'authority')
        print('Authority service running at http://127.0.0.1:8445')
    elif args.action == 'stop':
        compose('down')
    elif args.action == 'status':
        compose('ps')


if __name__ == '__main__':
    main()
