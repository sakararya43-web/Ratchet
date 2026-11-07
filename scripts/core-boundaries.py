"""Reject direct I/O and outward implementation dependencies in pure domain code."""
import json
import subprocess

raw = subprocess.check_output(["go", "list", "-json", "./internal/domain/..."], text=True)
decoder = json.JSONDecoder()
allowed_std = {"bytes", "cmp", "context", "crypto", "encoding", "errors", "fmt", "maps", "math", "reflect", "regexp", "slices", "sort", "strconv", "strings", "time", "unicode"}
allowed_project = {"github.com/sakararya43-web/Ratchet/internal/ports", "github.com/sakararya43-web/Ratchet/internal/canon", "github.com/google/uuid"}
while raw.strip():
    package, end = decoder.raw_decode(raw.lstrip())
    raw = raw.lstrip()[end:]
    for dependency in package.get("Imports", []):
        if dependency in allowed_project or dependency.startswith("github.com/sakararya43-web/Ratchet/internal/domain"):
            continue
        if dependency.split("/")[0] in allowed_std and "." not in dependency.split("/")[0]:
            continue
        raise SystemExit("domain I/O/outward dependency refused: " + package["ImportPath"] + " -> " + dependency)
print("PASS: domain packages contain no direct I/O or outward implementation dependencies")
