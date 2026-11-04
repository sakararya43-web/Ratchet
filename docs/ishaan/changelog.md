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

### Scope gates

Phase 1 has not started. Shared contract review remains a joint gate.
Full-outage revocation (R6/FR-X6) remains the documented peer-owned P2 limitation.
