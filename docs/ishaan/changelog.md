# Ishaan implementation changelog

## Working rules

- Work on `main` only; implement phases sequentially.
- Commit useful increments without Codex/ChatGPT co-author trailers.
- Preserve Sakar-owned code and `SAKAR_IMPLEMENTATION_PLAN.md`.
- Shared contracts require peer agreement; a compiled proposal is not a frozen contract.
- Never claim phase completion without its real integration and security evidence.
- This file is separate from Sakar's root `CHANGELOG.md` to avoid Windows filename collisions.

## Phase 2 — in progress (2026-11-04)

The user explicitly authorized the next phase after Phase 1's core handoff.
Phase 1's joint acceptance remains pending. No Phase 3 work has started.

- Added a pure event-producing change state machine covering submission,
  assessment, approval, holds/reassessment, rejection, execution, failure, expiry
  and verified revocation. Distinct-human/credential counting, context invalidation
  and read-back-only completion have deterministic regression coverage.
- Only explicitly supported typed intents validate. Personal context is represented
  by a private record reference/digest, never copied into permanent public facts.
- Read `origin/sakar` at unchanged `9662c46`: its passkey factory ignores SessionAPI
  and mounts `/assert/simulate`; its verifier omits RP-ID/origin checks and uses
  PKIX keys where actual WebAuthn enrollment returns COSE keys. These are peer
  handoff gates. Unsafe passkey handlers will not be copied or mounted.
- Reuse only exact production trust/store/verifier dependencies and the passkey
  store/verifier needed for actual conformance checks. No seed-key helpers or
  simulated-assertion handler is imported into the core runtime.
- Added real OPA 1.22 prepared change/authorization queries. Only the peer's
  BundleVerifier can admit modules/data, against an explicitly pinned genesis.
  Unsupported registry epochs are refused until verified history is available.
  Network, random and wall-clock builtins are unavailable to policy compilation.
  Real signed-bundle tests verify owner approval, two security leads, safeguard
  rejection, authorized reduction, permission denial and invalid replacement.
- Reused byte-identical trust production files and passkey store/verifier from
  `9662c46`; no peer-owned file was rewritten and no seed-key runtime was imported.

## Phase 1 — core implemented; joint acceptance pending (2026-11-04)

The user explicitly authorized starting the next phase after the Phase 0 handoff.
This supersedes the instruction to wait before starting Phase 1; it does not
constitute Sakar's approval or resolve the recorded peer audit test failure.
Only Phase 1 work is authorized by this execution record. No later phase has started.

### Scope and live integration observations

- Implement core relay, authenticated ingest, immutable graph, graph/impact APIs,
  connector conformance, golden impact data and reproducible first benchmarks.
- `origin/sakar` remains at `9662c46`. Its connector executable only logs messages;
  the adapter's graph conversion emits dangling permission targets and omits
  session/provenance data. These are peer-owned integration issues, not reasons
  to silently discard edges or invent a successful connector sync.
- Core graph code rejects malformed/unsupported semantics and keeps simulation
  isolated from shared state. Joint fixture/contract review stays explicit.

### Immutable graph analysis

- Added typed, validated forward/reverse CSR snapshots with stable edge identity,
  copied provenance and isolated proposed views. Versioned registry publication
  is atomic; invalidated/stale generations are never returned as current.
- Reach/control analysis handles membership, role inheritance, transitive
  takeover, role administration and resource-action denies. Impact compares
  every identity's powers and critical routes; protective-rule removal is
  classified as weakening even without a new currently reachable resource.
- Cyclic-control, indirect self-grant, multi-beneficiary impact, simulation
  isolation, malformed input, concurrent simulations and stale-read tests pass.
- Simple path enumeration has explicit bounds; an incomplete impact is an error.

### Durable source state and outbox delivery

- Added schema version 2 for source revisions, immutable ingest receipts,
  durable resync quarantine and retry timing. Event append can now participate
  in the same PostgreSQL transaction as source state updates.
- Complete snapshots and exact-base deltas are validated before publication.
  Public authority facts are replayable from the hash chain; display data is
  encrypted separately. Conflicting source ownership and reused message IDs
  are refused. Source merges are atomic across connectors.
- Outbox delivery holds a per-tenant lock through durable broker acknowledgement,
  keeps stable event IDs, persists bounded backoff and exposes backlog statistics.
- PostgreSQL/NATS integration verifies atomic ingest, privacy, replay, persistent
  gap quarantine, duplicate repair delivery and recovery from a lost publish ACK.

### Authenticated JetStream transport

- Added actual JetStream file-backed streams, durable explicit-ack consumption,
  persistent source deduplication, stable publish IDs and retry/backlog handling.
- Additive `SignedGraphSync` binds schema, tenant, connector, message/correlation
  IDs, revision and complete snapshot/delta to a pinned Ed25519 key. Signing uses
  domain-separated shared canonicalization; arbitrary identity headers are not
  trusted. Malformed or unauthenticated inputs never become published graphs.
- Added action-level reach/impact fields, path edge IDs and explicit neighborhood
  truncation to the existing schemas. Buf lint/FILE compatibility remain green.

### Graph correctness and shared impact candidates

- Independent fixed-point reference checks passed 200 generated cyclic graphs
  with seed 20261104. Added regressions for wildcard narrowing, revoked sessions,
  metadata versus secret possession and declared safeguard parameter changes.
- Withdrawal thresholds/check counts are explicit semantics; unknown edits fail
  analysis. Security parameters remain in replayable public facts while display
  metadata stays encrypted. Signature/correlation digests are bound to receipts.
- Reused the peer seed/change fixtures unchanged. Added candidate Rahul-admin
  impact and ordinary/service-overgrant/safeguard/revocation policy fact inputs.
  The peer ordinary fixture references a missing `user:finance-intern`, so the
  additional core scenario uses the existing finance assistant explicitly.
- First 100k-edge benchmark is recorded with hardware, command and dataset in
  `phase-1-benchmark.txt`: approximately 1.38 s/op and 220 MB/op on one CPU
  after complete removed-authority reporting (initial baseline was 0.98 s/op).
  The eventual 100 ms impact target is not achieved; optimization is still due.

### Recovery and complete affected-identity reporting

- Revalidating the same durable graph version restores availability after a
  transient database read failure, without accepting version regression.
- Healthy same-revision snapshots with a new message ID now persist a dedup
  receipt without producing a new graph event/version or outbox publication.
- Action-only revocations report removed powers/control even if resource counts
  stay constant. Partial denies against wildcard grants require explicit action
  expansion; analysis refuses an authority set it cannot represent exactly.
- Added regression coverage for these cases, valid ordered deltas, persisted
  JetStream acknowledgement cursors and metadata-before-possession traversal.
- Neighborhoods cap returned edges at 10,000 with explicit truncation.

### Authenticated graph and simulation runtime

- Added real Connect Graph/Impact handlers over immutable snapshots: node
  provenance, focused neighborhoods, paged reach/paths and exact draft impact.
- Verified client TLS certificates map to server-configured actor/tenant bindings.
  Cursor HMACs bind query scope, tenant and graph version. Header impersonation,
  tenant crossover, tampered cursors and stale-context pagination are refused.
- Added `ratchetd graph-serve`: PostgreSQL source recovery, authenticated connector
  ingestion, durable relay, refresh/invalidation and HTTPS service lifecycle.
  Private configuration supplies keys, connector pins and certificates; remote
  NATS requires TLS/credentials. Metrics expose the authenticated reader's tenant.
- Readiness remains unavailable for escalation until the later policy dependency
  actually exists. Graph/simulation do real work without mounting empty services.
- Native TLS tests and Linux `go test -race -tags=integration ./...` passed with
  real PostgreSQL 17/NATS 2.11. The runtime harness proves signed ingestion through
  live APIs and unchanged graph version after simulation; it is not a substitute
  for the peer's actual connector acceptance gate.

### Deliverable transport limits

- Canonical ledger entries must fit the 1 MiB durable broker limit before their
  event/outbox transaction commits. Envelope overhead cannot strand a tenant's
  ordered outbox behind an oversized event. A real PostgreSQL regression proves
  failed oversized appends leave no event, outbox item or consumed chain position.

### Executable peer conformance

- Added a reusable snapshot/model validator and a separate `peerintegration`
  suite that boots the actual peer simulator and calls its actual HTTP adapter.
  Default core tests do not require importing unavailable peer implementations.
- The isolated combined run against `origin/sakar` at `9662c46` fails five
  genuine acceptance checks: completeness/envelope, declared safeguard semantics,
  dangling permission targets (`policy`, `audit`, `iam`), all three omitted target
  sessions and missing grant identities. No expected-failure assertion hides this.
- Peer-owned CLI transport still logs sync messages instead of publishing them.
  Live connector-to-core D3 acceptance and joint fixture review remain pending.
- Updated policy-fact candidates to include removed powers on role revocation.
  Fixture updates still require joint review; no policy decision is hardcoded.

### CI and final checks

- Extended core CI to vet all present packages, lint graph/bus/conformance,
  run the full real-dependency race suite and fix the independent reference seed.
  Actual adapter conformance runs when the peer simulator source is integrated.
- Marked directly imported NATS and Rapid dependencies correctly; retained the
  peer's existing dependency set for the combined build.
- Final real-dependency Linux race suite passes. Scoped lint reports zero issues;
  module verification and the new-process append/retry/read/chain/readiness smoke
  pass. Contract compatibility and regeneration checks pass without generated diff.
- The corrected combined-source race run passes core and peer packages except
  the same four previously reproduced peer historical-credential audit failures.
  Tagged actual-adapter conformance fails separately and remains an explicit gate.
- Updated the implementation checklist and [Phase 1 handoff](phase-1-handoff.md)
  with runtime configuration, signing bytes, supported semantics, bounds, measured
  performance and exact peer fixes. Shared approval and live D3 are still open;
  no subsequent phase or Sakar-owned implementation was started or changed.

## Phase 0 — implemented; joint acceptance pending (2026-11-04)

### Dependency provenance

Initially imported the following files byte-for-byte from `origin/sakar` at
`9662c46`: `go.mod`, `go.sum`, `buf.yaml`, `proto/ratchet/v1/`,
`internal/ports/ports.go`, `internal/canon/`, and `testdata/canon/`.
No peer-owned implementation was rewritten and the branches remain separate.
Subsequent contract additions must preserve these field numbers and RPC names.
Core dependency additions were later made to the root Go module; original peer
dependencies were retained and exercised in the combined build.
The user confirmed dependency reuse with separate branches. The reused canonical
golden tests pass on Go 1.27.3; `internal/ports` compiles unchanged.

### Required completion evidence

- [ ] Eight core service contracts and connector envelopes agreed with Sakar.
- [x] Approval envelope, authenticated caller boundaries, ledger bytes and replay facts specified.
- [x] Real PostgreSQL migration and sqlc/pgx repository.
- [x] Atomic event/outbox/idempotency writes and serialized per-tenant chain.
- [x] Separate personal data and least-privilege database roles.
- [x] Restart persistence, rollback, concurrent-chain, duplicate-command and SQL tamper-denial evidence.
- [x] Real persisted `ratchetd` operation and honest readiness.
- [x] Local PostgreSQL/NATS Compose, core CI workflow, Buf baseline and local compatibility/check commands.
- [ ] Hosted GitHub Actions verdict after an authorized push.
- [ ] Peer audit fixture correction and a fully green combined candidate.

### Contract increment

- Added the eight core service definitions inherited from the peer, with additive
  typed kinds/states/decisions, mutation context, graph bounds, watch cursors,
  approval envelope, multi-identity impact and connector evidence metadata.
- Recorded authenticated caller rules, privacy, errors, five fixed subjects,
  approval/replay facts and byte-level audit-v1 chain encoding in
  `phase-0-contracts.md`. Peer agreement is still outstanding.
- Captured the original peer descriptors at `testdata/contracts/sakar-v1.binpb`.
  Buf 1.75.0 lint and FILE compatibility against that baseline pass. The existing
  DecisionRequest/Response names have a file-scoped naming-rule exception.

### Durable storage schema

- Added the real goose migration, sqlc queries and generated pgx/v5 bindings for
  tenant heads, events, command receipts, encrypted private records and outbox.
- Added runtime/projector/migration roles, forced tenant RLS and append-only
  mutation triggers. Runtime cannot update outbox payloads.
- Started real PostgreSQL 17 and JetStream-enabled NATS 2.11 using Compose.
  PostgreSQL uses configurable localhost port 55434 because 55432 belongs to an
  unrelated project. Local credentials were generated outside Git.
- The explicit migration command successfully applied schema version 1 using
  the non-superuser migration role. Integration evidence is recorded below.

### Canonical chain and private records

- Implemented the peer-compatible SHA-256 predecessor/canonical-content chain,
  strict UTC microsecond timestamps and the JCS safe-integer limit.
- Added AES-256-GCM private records with random nonces and tenant/record-bound
  associated data; neither plaintext nor encryption keys enter the ledger.
- Hash tampering, peer-format compatibility, invalid timestamp/sequence and
  ciphertext/key/tenant/record binding tests pass.

### Atomic repository and database evidence

- Implemented append/load, verified chain reads, exact-intent command receipts,
  optimistic stream versions, private-record retention and atomic outbox writes.
- Added explicit goose migration and database/schema/least-privilege probes.
- Real PostgreSQL acceptance passed: 32 concurrent streams form one continuous
  chain; 16 racing identical commands create one event/outbox/receipt; conflicting
  intents and stale stream versions are refused.
- A trigger-injected failure after partial writes rolls back all five tables;
  retry starts at sequence 1. New pool reads survive restart, private-record
  deletion preserves immutable bytes, and outbox bytes match the event.
- SQL UPDATE/DELETE/TRUNCATE and trigger-disabling attempts are denied. Forced
  RLS prevents cross-tenant reads/writes; elevated migration credentials fail
  the runtime role check. A test cleanup-order deadlock was fixed before rerun.

### Replay input validation

- Reject unsafe JSON integers before canonicalization can round them; require
  object-shaped replay facts, bounded identifiers/content and known personal
  fields in encrypted records. Regression tests pass.

### Executable core operation

- `ratchetd` now performs real migrate, record-core-evidence, load-stream and
  verify-chain operations. Its health listener exposes only implemented probes.
- The process smoke passed: a PRD-file digest was stored, retried with one effect,
  read and chain-verified by separate processes. Liveness and storage readiness
  returned 200; overall decision readiness returned 503 because no graph or
  verified bundle has been initialized. Unimplemented API paths remain absent.

### Generated clients and full race run

- Generated Go Protobuf and Connect bindings from the actual v1 schemas using
  local generators (Protobuf 1.36.12 / Connect 1.19.1). No RPC is mounted by
  generation alone.
- Reused the peer root `.gitignore` unchanged and isolated development artifacts
  behind `.local/.gitignore`, avoiding a competing root ignore file on merge.
- Full Linux `go test -race -tags=integration -count=1 ./...` passed against the
  real Compose PostgreSQL instance; canonical vectors and all core tests passed.

### Scope gates

Phase 1 has not started. Shared contract review remains a joint gate.
Full-outage revocation (R6/FR-X6) remains the documented peer-owned P2 limitation.

### CI and integration handoff

- Core vet, lint (zero issues), module verification, generated-file consistency,
  Buf lint and compatibility checks pass. CI jobs are `core-contracts` and
  `core-tests`; workflow syntax was validated with actionlint 1.7.12.
- Linux process smoke also passed. Credential env generation now writes LF so
  the same Windows-created private file can be consumed in Linux containers.
- Restored the unchanged Authority/Passkey/Overview proto sources byte-for-byte
  from the peer to avoid unnecessary formatting conflicts.
- An isolated combined race run compiled all peer/core packages. All tests passed
  except four subtests in the peer's `internal/audit` suite. The exact failures
  also reproduce on untouched `origin/sakar`: `time.Now()-12h` enrollment is later
  than the fixed 2026-11-03 approval event. Peer code was not changed.
- Proposed agreement, tested merge resolution and the peer-owned fixture action
  are recorded in `phase-0-handoff.md`. Shared review, the inherited test failure
  and hosted CI remain explicit acceptance gates; no later phase is started.
- The isolated combined frontend passes TypeScript checking, Vite production
  build and all 15 canonicalization tests. No frontend source was changed.
- Direct core module dependencies are annotated accurately; existing peer-only
  requirements are retained. `go list -mod=readonly ./...` passes.
