# Phase 0 handoff and proposed agreement

Prepared 2026-11-04. Ishaan's code is on `main`; Sakar's branch remains untouched
at `9662c4692d583332a669d34ccf6eb23afee6df80`.

Status: core implementation and local acceptance evidence are delivered.
**Joint contract approval is outstanding. Phase 0 is not signed off, and Phase 1
has not started.** This file proposes the agreement; it does not represent
Sakar's approval.

## Proposed shared agreement

1. Preserve all existing RPC/message names and protobuf field numbers from the
   peer baseline. Main's additional fields/enums/watch methods are additive.
   `testdata/contracts/sakar-v1.binpb` is the original peer descriptor snapshot.
2. Use the real peer `internal/canon` and canonical vectors unchanged. The
   shared Go ports are also unchanged. No alternate digester or trust verifier
   exists in the core.
3. Adopt `phase-0-contracts.md` for authenticated actor/tenant boundaries, typed
   failures, approval envelope, replay inputs, identifiers, pagination and graph
   version semantics. The legacy caller-ID request fields are never identity
   proof. Agree the typed session adapter before passkey mounting in Phase 2.
4. Preserve the five PRD connector subjects. Adopt the additive schema-version,
   connector/message/correlation identity, target preconditions, approved digest
   and read-back evidence fields. Sakar owns corresponding connector Go structs,
   serialization and transport changes; the core must not rewrite them.
5. Use the peer-compatible audit-v1 hash encoding specified in the contract.
   Assertions/envelopes must be inside the hashed payload. Confirm historical
   key/registry evidence with the offline verifier before Phase 4 acceptance.
6. Shared changes remain subject to peer review. The user's `main`-only work
   instruction overrides the earlier topic-branch procedure, not the need for
   agreement about shared behavior.

## Working handoff

| Artifact | Delivered behavior |
| --- | --- |
| Eight core schemas | Change, Impact, Graph, Containment, Incident, Audit, Overview, Decision; real generated Go/Connect consumers |
| `internal/eventstore` | pgx/sqlc/goose; append/load/restart, expected versions, command deduplication, atomic outbox, per-tenant locked chain |
| `internal/ledger` | Canonical bytes, contiguous tenant sequence, predecessor hash, peer-format verification |
| Private records | AES-256-GCM, external key references, tenant/record binding, retention without rewriting the chain |
| Database roles | Separate migration/runtime/projector roles; runtime cannot mutate history, own tables or bypass RLS |
| `ratchetd` | Explicit migrate, record-core-evidence, load-stream, verify-chain and health listener; no future RPC mounted |
| Health | Liveness, storage readiness and full readiness; missing graph/bundle means full readiness 503 |
| CI jobs | `core-contracts`, `core-tests`; compatibility, generation, vet, race, lint, real Compose integration and process smoke |

Typed error examples for the first durable operation are
`eventstore.ErrInvalid`, `ErrVersionConflict`, `ErrIdempotencyConflict` and
`ErrIntegrity`, usable through `errors.Is`. No request can use the evidence
command to execute an IAM grant. No unsigned policy or fake approval is loaded.

## Local evidence

- Go 1.27.3 on Windows; Linux race checks in `golang:1.27.3-bookworm`.
- Real PostgreSQL 17 and NATS 2.11/JetStream from digest-pinned Compose images.
- Shared canonical-vector tests pass. Hash and encrypted-record tampering are
  rejected. Unsafe canonical integers and known personal fields are refused.
- PostgreSQL acceptance passes for restart read, private-record deletion,
  identical event/outbox bytes, 32 concurrent streams, 16 racing retries,
  optimistic-version races and rollback after partial event/outbox writes.
- Runtime SQL mutation/DDL and cross-tenant attempts are denied. Overprivileged
  credentials are refused by the runtime role probe.
- Full core `go test -race -tags=integration -count=1 ./...`, `go vet ./...`,
  golangci-lint 2.15.0 (zero issues), module verification, Buf lint/FILE
  compatibility and deterministic generation pass.
- Windows and Linux process smokes pass for append, retry, load, verification and
  honest readiness. Generated private env files use cross-platform LF encoding.
  GitHub workflow validation passes locally; hosted Actions have not
  been run because these commits have not been pushed.

## Merge rehearsal and owner action

A read-only `git merge-tree` rehearsal identifies add/add conflicts in shared
files because both branches introduced them after the common document-only
base. This is a Git history conflict, not a reason to replace peer implementations.

Resolve `go.mod`/`go.sum` to main's tested superset and retain all peer modules.
Resolve changed core/connector protobufs to main's additive schema, retain the
original unchanged Authority/Passkey/Overview schemas, and use main's Buf config
plus generation config. Keep the peer `.github/workflows/ci.yml` alongside core's
`.github/workflows/core.yml`. Keep Sakar's root `CHANGELOG.md` and Ishaan's
`docs/ishaan/changelog.md`. Both implementation plans stay separate.

An isolated combined directory was built from the exact peer tree plus main's
core/shared changes. All Go packages compile; the race test run passes except
the peer's `internal/audit.TestOfflineVerifier_Comprehensive`. Its four failures
also reproduce on the **untouched peer tree**, with the original dependency
versions, using `go test -race -count=1 ./internal/audit`.

The isolated combined frontend also passes `npm ci`, TypeScript checking,
Vite production build and all 15 TypeScript canonicalization tests. This is
compilation/vector evidence; end-to-end browser approval is a later-phase gate.

The cause is time-dependent fixture enrollment:
`internal/audit/audit_test.go:47` enrolls at `time.Now().Add(-12*time.Hour)` while
line 53 fixes events at 2026-11-03 10:00 UTC. On 2026-11-04 enrollment is after
the historical approval. Suggested peer correction: define a fixed fixture base
time before creating credentials and derive enrollment, event, signing and
export times from it. Do not relax the verifier's historical enrollment check.
HappyPathFullVerification fails first; TamperedEventData, TruncationDetection and
BrokenPreviousEventHashLink then report the same earlier credential failure.

This owner action and joint review remain unresolved. A clean integration verdict
must not be claimed until the corrected peer tests and combined candidate pass.
No Sakar code, plan or branch ref was changed during the rehearsal.

## Next gate

Obtain peer agreement on the contracts above and the inherited audit-fixture
correction, then rerun the combined checks and record the exact accepted commits.
Only then sign off Phase 0 and begin Phase 1. R6's outage-independent revocation
mechanism remains the pre-existing P2 limitation; it is not implemented here.
