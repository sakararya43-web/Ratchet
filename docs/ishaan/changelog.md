# Ishaan implementation changelog

## Working rules

- Work on `main` only; implement phases sequentially.
- Commit useful increments without Codex/ChatGPT co-author trailers.
- Preserve Sakar-owned code and `SAKAR_IMPLEMENTATION_PLAN.md`.
- Shared contracts require peer agreement; a compiled proposal is not a frozen contract.
- Never claim phase completion without its real integration and security evidence.
- This file is separate from Sakar's root `CHANGELOG.md` to avoid Windows filename collisions.

## Phase 0 — in progress (2026-11-04)

### Dependency provenance

Reused the following files byte-for-byte from `origin/sakar` at
`9662c46`: `go.mod`, `go.sum`, `buf.yaml`, `proto/ratchet/v1/`,
`internal/ports/ports.go`, `internal/canon/`, and `testdata/canon/`.
No peer-owned implementation was rewritten and the branches remain separate.
Subsequent contract additions must preserve these field numbers and RPC names.
The user confirmed dependency reuse with separate branches. The reused canonical
golden tests pass on Go 1.27.3; `internal/ports` compiles unchanged.

### Required completion evidence

- [ ] Eight core service contracts and connector envelopes agreed with Sakar.
- [ ] Approval envelope, authenticated caller boundaries, ledger bytes and replay facts specified.
- [ ] Real PostgreSQL migration and sqlc/pgx repository.
- [ ] Atomic event/outbox/idempotency writes and serialized per-tenant chain.
- [ ] Separate personal data and least-privilege database roles.
- [ ] Restart persistence, rollback, concurrent-chain, duplicate-command and SQL tamper-denial evidence.
- [ ] Real persisted `ratchetd` operation and honest readiness.
- [ ] Local PostgreSQL/NATS Compose, actual core CI, Buf baseline and compatibility checks.

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
  the non-superuser migration role. Integration checks are still in progress.

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

### Scope gates

Phase 1 has not started. Shared contract review remains a joint gate.
Full-outage revocation (R6/FR-X6) remains the documented peer-owned P2 limitation.
