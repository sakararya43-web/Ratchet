"""Run one core check in Linux without relying on Docker Desktop drive mounts.

Copies tracked and non-ignored worktree files; private .local files and Git
credentials are excluded. Database/broker credentials pass only as environment.
The uniquely named container is always removed, leaving shared dependencies alone.
"""
import os
import io
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
    arguments = sys.argv[1:]
    peer = False
    update_modules = False
    update_generated = False
    image = "golang:1.27.3-bookworm"
    while arguments and arguments[0] in ("--peer", "--update-modules", "--update-generated", "--image"):
        if arguments[0] == "--image":
            if len(arguments)<2: raise SystemExit("--image requires a pinned tool image")
            image,arguments=arguments[1],arguments[2:]
            continue
        peer |= arguments[0] == "--peer"
        update_modules |= arguments[0] == "--update-modules"
        update_generated |= arguments[0] == "--update-generated"
        arguments = arguments[1:]
    if not arguments or peer and (update_modules or update_generated):
        raise SystemExit("select a check command; peer overlays cannot update main's modules")
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    ).decode().split("\0")
    name = "ratchet-core-check-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="ratchet-check-") as directory:
        archive = Path(directory) / "source.tar"
        with tarfile.open(archive, "w") as bundle:
            if peer:
                # Read-only pinned source overlay; no checkout, merge or branch mutation.
                pinned = "d823a106bb4a64b0fe54e366c41029ccbd8dfda8"
                exported = subprocess.check_output(["git", "archive", "--format=tar", pinned], cwd=root)
                with tarfile.open(fileobj=io.BytesIO(exported)) as source:
                    for member in source:
                        bundle.addfile(member, source.extractfile(member) if member.isfile() else None)
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
        command += [image, *arguments]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        try:
            with archive.open("rb") as source:
                subprocess.run(["docker", "cp", "-", name + ":/src"], stdin=source, check=True)
            result = subprocess.run(["docker", "start", "--attach", name])
            state = subprocess.check_output(["docker", "inspect", "--format", "{{.State.ExitCode}}", name])
            if update_modules and not result.returncode and not int(state):
                for filename in ("go.mod", "go.sum"):
                    subprocess.run(["docker", "cp", name + ":/src/" + filename, str(root / filename)], check=True)
            if update_generated and not result.returncode and not int(state):
                for filename in ("db.go", "models.go", "queries.sql.go"):
                    path = "internal/eventstore/storedb/" + filename
                    subprocess.run(["docker", "cp", name + ":/src/" + path, str(root / path)], check=True)
            return result.returncode or int(state)
        finally:
            subprocess.run(["docker", "rm", "--force", name], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
