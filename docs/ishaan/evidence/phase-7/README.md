# Phase 7 public evidence

Executable source: `7ddc8a9da7f8deac9c8b58fa846a916f393ba979`.
Peer source: `d823a106bb4a64b0fe54e366c41029ccbd8dfda8`, reused read-only.
[Successful hosted run](https://github.com/sakararya43-web/Ratchet/actions/runs/42387565655).
[Scope, check matrix and open release gates](../../phase-7-completion.md).

`verification.json` indexes the actual CI metadata, native results, source-tree
identity and SHA-256 commitments of these files. Directory attributes preserve
artifact bytes across Windows/Linux checkouts. The verification index excludes
itself from its file hashes.

- `performance.json` and `benign-replay.json` are exact hosted outputs, with
  workload composition, denominators, tails and scope.
- `actual-kind.json` is the final native test's exact output. Admission/drift
  correctness took 788.48 seconds; comparison took 106.34 seconds. These tests
  use no race instrumentation; the separate Linux main/peer suites use `-race`.
- `backup-restore.json` is the real local isolated restore result. No private
  dump or table contents are retained.
- `core.spdx.json`, `signer.pub`, `image-verification.json` and `summary.json`
  are exact public image-check outputs downloaded from the successful CI run.
  The SBOM hash and OCI digest match the verified claims. Signing used a
  disposable local test key and registry, which were removed. Verification
  output is not a standalone signature bundle or production release identity.
- `checkpoint-cli/` translates the existing signed public checkpoint handoff
  fixture into the peer CLI's agreed JSON representation, as the conformance
  suite already does. It creates no signatures or new event commitments. The
  valid case verifies seven events and two checkpoints; the altered first
  payload returns `valid=false` and process exit 3. Commands and reports are
  retained. Zero approval records means this is not complete browser evidence.

Reproduce core checks with real Compose dependencies, sequentially:

```powershell
. ./scripts/core-env-load.ps1
python scripts/core-acceptance.py
python scripts/core-web-build.py
docker build -f deploy/core.Dockerfile -t ratchet-core:phase7 .
python scripts/core-supply-chain.py
```

The acceptance runner's peer profile requires the exact pinned Git object to be
available (`git fetch --no-tags origin d823a106bb4a64b0fe54e366c41029ccbd8dfda8`).
It never checks out, merges or writes the peer branch. Restore requires quiescent
writers and deletes only its own scratch database/dump. Actual kind setup and
commands are in [the native procedure](../../phase-6-kind.md). On Windows with
slow native module loading, compile the real test executable in the source-copy
runner:

```powershell
python scripts/core-check.py --peer --test-binary workflow sh -c 'mkdir -p .local && GOOS=windows CGO_ENABLED=0 go test -c -tags=integration,peerintegration,kindintegration -o .local/workflow.test.exe ./internal/workflow'
```

Then execute `.local/phase7-kind-tests/workflow.test.exe`
from `internal/workflow`, with the documented environment and a 25-minute test
process timeout for both native tests. This changes no test assertion or adapter.

To rerun a CLI case while keeping branches separate, use `scripts/core-check.py
--peer sh -c` to build the actual `./cmd/ratchetctl` and execute the arguments in
`checkpoint-cli/results.json`. The negative case must produce the recorded
integrity error and nonzero exit; a parser failure is not a passing tamper test.
Original hosted artifacts have seven-day retention; the public outputs here are
retained with the repository. Full product sign-off is explicitly false.
