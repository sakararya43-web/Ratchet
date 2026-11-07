"""Run one core check in Linux without relying on Docker Desktop drive mounts.

Copies tracked and non-ignored worktree files; private .local files and Git
credentials are excluded. Database/broker credentials pass only as environment.
The uniquely named container is always removed, leaving shared dependencies alone.
"""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import uuid


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: python scripts/core-check.py COMMAND [ARG ...]")
    root = Path(__file__).resolve().parents[1]
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    ).decode().split("\0")
    name = "ratchet-core-check-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="ratchet-check-") as directory:
        archive = Path(directory) / "source.tar"
        with tarfile.open(archive, "w") as bundle:
            for relative in sorted(set(files)):
                path = root / relative
                if relative and not relative.startswith(".local/") and path.is_file():
                    bundle.add(path, arcname=relative, recursive=False)
        command = [
            "docker", "create", "--name", name, "--network", "host",
            "--mount", "type=volume,source=ratchet-go-modules,target=/go/pkg/mod",
            "--mount", "type=volume,source=ratchet-go-cache,target=/root/.cache/go-build",
            "--workdir", "/src",
        ]
        for key in ("RATCHET_DATABASE_DSN", "RATCHET_MIGRATION_DSN", "RATCHET_PROJECTOR_DSN", "RATCHET_NATS_URL"):
            if key in os.environ:
                command += ["--env", key]
        command += ["golang:1.27.3-bookworm", "sh", "-c",
                    'tar -xf /tmp/ratchet-source.tar -C /src && exec "$@"', "core-check", *sys.argv[1:]]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        try:
            subprocess.run(["docker", "cp", str(archive), name + ":/tmp/ratchet-source.tar"], check=True)
            result = subprocess.run(["docker", "start", "--attach", name])
            state = subprocess.check_output(["docker", "inspect", "--format", "{{.State.ExitCode}}", name])
            return result.returncode or int(state)
        finally:
            subprocess.run(["docker", "rm", "--force", name], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
