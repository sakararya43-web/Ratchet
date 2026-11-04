# Phase 0 core development

This is a real PostgreSQL-backed evidence operation. It does not grant access or
expose the future change/graph services. Their schemas are declarations only.
All work stays on `main`. See `changelog.md` before continuing the next phase.

## Local acceptance on Windows

Install Go 1.27.3 and Docker Engine/Compose. Tools can live outside the repository;
no global package installation or paid service is required. From the repo root:

```powershell
./scripts/core-env.ps1
docker compose --env-file .local/core.env -f deploy/compose/compose.yaml up -d --wait
. ./scripts/core-env-load.ps1
go run ./cmd/ratchetd migrate
go test ./...
go test -tags=integration -count=1 ./internal/eventstore/...
./scripts/core-smoke.ps1
```

The generated `.local/core.env` is private, ignored and must stay with the volume.
Existing credentials are never overwritten. The default PostgreSQL port is 55434;
set `RATCHET_POSTGRES_PORT` in that file before starting if it is occupied.
NATS listens on localhost port 54222 with JetStream and a persistent data volume.
This Phase 0 bus is local infrastructure only; it accepts no target credentials
and provides no production tenant-authenticated transport yet.

`ratchet_migrator` owns core schema objects but is neither superuser nor a
BYPASSRLS role. `ratchet_runtime` cannot rewrite/truncate events, receipts or
outbox payloads and cannot own/alter schema objects. `ratchet_projector` can read
tenant-scoped events and has no grant to any other core table. Future read-model
tables require only their own narrowly scoped write grants. SQL RLS uses the
transaction-local authenticated tenant. It is defense in depth, not a replacement
for server authentication: a stolen runtime SQL credential must not be treated
as a tenant-authenticated network session.

Run migrations as an explicit administrative command with
`RATCHET_MIGRATION_DSN`. Serving and evidence commands use only
`RATCHET_DATABASE_DSN`; they never auto-migrate. Nonadministrative commands reject
elevated database roles. No credentials are command-line arguments.

`scripts/core-smoke.ps1` records the actual PRD file's SHA-256 in one durable,
hash-chained event, retries in a new process, reads it from another process and
verifies the chain. This proves the first durable core slice without an invented
business decision. It also probes `/livez`, `/readyz/storage` and `/readyz`.
Storage readiness may succeed; decision readiness returns 503 until real graph
and verified policy dependencies exist. Missing routes return 404.

## Contract and generated SQL checks

```powershell
docker run --rm --mount "type=bind,source=${PWD},target=/src" -w /src bufbuild/buf:1.75.0 lint
docker run --rm --mount "type=bind,source=${PWD},target=/src" -w /src bufbuild/buf:1.75.0 breaking --against testdata/contracts/sakar-v1.binpb
docker run --rm --mount "type=bind,source=${PWD},target=/src" -w /src sqlc/sqlc:1.31.1 generate
```

Generated SQL uses pgx/v5. Migrations are embedded and executed by goose 3.29.0.
The migration is intentionally irreversible because an automatic down migration
would erase evidence. Restore a separately retained verified backup if needed.

The integration-tag suite refuses to skip when PostgreSQL credentials are absent.
It uses the real runtime/migration roles, fault injection after partial writes,
concurrent cross-stream appends, duplicate races, stream conflicts, RLS and SQL
mutation-denial checks. Database owners can still tamper; the chain verifier
detects inconsistent evidence. Public fact schemas must continue to minimize data;
the guard against known personal field names is only defense in depth.

## Integration boundaries

Dependency files came from `origin/sakar` at `9662c46`; no Sakar branch ref or
implementation was changed. Contract additions are proposed in
`phase-0-contracts.md` and remain subject to peer agreement. The checked-in
`sakar-v1.binpb` is the original peer descriptor baseline, not a rebuilt copy of
the new schema. CI must compare future changes to both that baseline and the
previous main revision.

Peer transport additions and offline-verifier hardening belong in the handoff.
The Phase 0 append format places authoritative evidence inside hashed payloads,
including future approval envelopes/assertions. The core will not rely on any
unhashed approval field or unsigned bundle. Phase 1 cannot be declared started
until all Phase 0 exit evidence and shared review are accounted for.
