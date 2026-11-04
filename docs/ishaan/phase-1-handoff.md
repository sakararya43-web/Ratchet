# Phase 1 core handoff

Prepared 2026-11-04. Work is committed on `main` only. The core implementation
and its local checks are delivered; **joint acceptance remains pending**. No
Phase 2 implementation had started at this checkpoint; the subsequent authorized
Phase 2 work is recorded in [its handoff](phase-2-handoff.md). The user explicitly authorized Phase 1
after the Phase 0 handoff; this does not constitute peer contract approval.

## Delivered operations

| Component | Actual behavior |
| --- | --- |
| Event store | Source revisions, immutable message receipts, encrypted display records and graph authority facts committed atomically with ledger/outbox |
| Outbox relay | File-backed JetStream PubAck, stable event UUID, ordered per-tenant delivery, persisted retry backoff and backlog metrics |
| Ingest | Pinned Ed25519 connector authentication, complete snapshots, exact-base deltas, durable deduplication, source quarantine and full-snapshot repair |
| Graph | Typed immutable forward/reverse CSR, isolated validated overlays, atomic generation publication and bounded minimum-version waits |
| Analysis | Reach, transitive control, group/role inheritance, role self-grant, action powers, safeguards and all affected identities including removed authority |
| Connect API | Graph node details, focused neighborhoods, paged reach/critical paths and draft impact; certificate-bound tenant/actor identity |
| Conformance | Core protocol coverage plus executable tests of the actual peer simulator/adapter in a combined checkout |

No future workflow, policy, approval or execution service is mounted. Simulation
does not write a request, dispatch a command, alter the source graph or advance
its version. Production paths never serve fixture-backed organization data.
The protocol harness, seed compiler and reference traversal exist only in tests.

## Run the actual graph service

Start the existing local Compose dependencies, load runtime credentials and run
explicit migrations as described in [core development](core-development.md).
Supply a private JSON configuration file outside tracked source, then run:

```powershell
. ./scripts/core-env-load.ps1
go run ./cmd/ratchetd migrate
go run ./cmd/ratchetd graph-serve --config .local/graph.json
```

There is no default identity, encryption/signing key, certificate or organization.
The configuration accepts these exact fields:

| Field | Required value |
| --- | --- |
| `graph_key_hex` | 32-byte AES key encoded as 64 hex characters; retain for encrypted display recovery |
| `cursor_key_hex` | Independent 32-byte HMAC key encoded as 64 hex characters |
| `nats_url` | Actual JetStream URL; local Compose uses `nats://127.0.0.1:54222` |
| `nats_credentials` | NATS credentials-file path; required together with TLS for a remote broker |
| `server_cert`, `server_key` | PEM paths for the HTTPS server certificate and private key |
| `client_ca` | PEM path for the CA authorized to issue client certificates |
| `readers` | Object mapping verified certificate CommonName to `{tenant_id, actor_id}` |
| `connectors` | Array of `{tenant_id, connector_id, public_key_hex}` pinned Ed25519 keys |

Each reader's tenant must have a configured connector. Invalid/missing keys,
certificate configuration, runtime privileges or migrations prevent startup.
Client TLS certificates are required; unrecognized readers cannot use APIs or
metrics. Human login and finer policy authorization are Phase 2 work; current
readers are explicitly provisioned service identities with tenant-wide graph
read/simulation access. User-supplied headers are never an identity boundary.

The default listener is `127.0.0.1:8443`. Generated Connect clients use the HTTPS
origin plus `/api`. Only GraphService and ImpactService handlers are installed.
`GET /metrics` reports pending outbox count, oldest pending age and retry attempts
for the authenticated reader's tenant. `/livez` and `/readyz/storage` check their
real dependencies. `/readyz` remains 503 while the verified policy dependency is
absent, even when graph reads are working.

## Connector agreement proposed for review

The five PRD subject names are preserved. Input is published on
`ratchet.<tenant>.ingest.sync`; core evidence is relayed on
`ratchet.<tenant>.changes.events`. A tenant gets file-backed EVENTS/INGEST streams
with 24-hour retention and a two-minute broker deduplication window. Database
receipts provide durable business deduplication beyond that broker window.

Use the additive protobuf `SignedGraphSync` with an outer `ConnectorEnvelope`,
one snapshot/delta payload and Ed25519 signature. Schema version is 1. The outer
envelope carries tenant, connector, stable message UUID, correlation UUID and
source revision. Inner tenant/connector/revision must match; if an inner envelope
is present it must equal the outer one. Snapshot `complete` must be true.

Signing is precisely `internal/bus.SyncSigningDigest`:

1. Clone the protobuf and clear `signature`.
2. Marshal with protojson `UseProtoNames=true`, `EmitDefaultValues=true`.
3. Canonicalize those bytes using the real shared `internal/canon` digester.
4. Digest the object with `domain="RATCHET_GRAPH_SYNC_V1"` and
   `canonical_proto_json` containing those canonical bytes as standard base64.
5. Sign the resulting 32-byte SHA-256 digest using the pinned Ed25519 key.

Publish with the stable message UUID as NATS MsgId. Do not advance connector
cursor state until durable publication acknowledgement. The core acknowledges
consumption only after database commit. A message UUID reused with changed
content is rejected. A healthy same-revision identical authority snapshot with
a new UUID receives a dedup receipt without graph-version churn.

An unknown base, gap, rollback or delta against a quarantined source durably
records `GraphResyncRequired` and makes the tenant graph unavailable. The relay
publishes that evidence; the connector must react with a complete fresh snapshot.
Malformed/authentication failures terminate that broker delivery; transient
storage failures are retried. An old gap-message replay after repair cannot
invalidate the repaired durable source. A temporary database read failure also
invalidates availability; a successful same-version reload restores it.

The current message and canonical event transport limit is 1 MiB. Oversized
canonical events fail before commit, including when envelope overhead causes
the excess. Chunked snapshot transport is not implemented or advertised. The
100k-edge analysis benchmark below constructs its graph directly in memory.

## Model semantics and API limits

Nodes cover Human, ServiceAccount, Group, Role, Permission, Resource, Safeguard,
Session and Credential. Edges support membership/assignment, grants, takeover,
role/group/safeguard modification, approval, protection and explicit resource
action denies. Missing endpoints and unsupported relations are errors. Stable
grant IDs and provenance properties survive analysis/API reads; security facts
are public replay data while names/display metadata remain separately encrypted.
Multiple source graphs may share identical nodes; conflicting ownership is an
error rather than last-writer-wins data loss.

Using a live session/credential can inherit its takeover edges; inspecting its
metadata cannot. Disabled sessions/credentials do not inherit. Partial action
denies combined with wildcard authority require explicit action expansion by
the source: the analyzer refuses this unrepresentable combination. It never
silently reports the wildcard as unaffected or removes all access instead.

The declared safeguard `guard_kind=withdrawal_threshold_v1` requires positive
integer `required_checks` and `threshold_usd` values within the canonical safe
integer range. Fewer checks or a higher threshold weakens the guard. Removing
DENIES, PROTECTED_BY or REQUIRES_APPROVAL is also weakening. Unknown parameter
edits cannot become a claimed reduction. Draft simulation supports role assign,
role revoke, declared safeguard parameter edits and explicit protection removal;
unsupported change kinds fail with InvalidArgument.

Results carry the immutable generation's applied tenant event position. Page
sizes default to 50 and allow 1-200. HMAC cursors bind tenant, query and graph
version; changed context requires pagination restart. Node details refuse over
1,000 incident edges. Neighborhoods allow depth 0-4, at most 1,000 nodes/10,000
edges and signal truncation. Neighborhood edges are returned on their source
node's page, so consumers accumulate pages before rendering all endpoints.
Critical paths have at most 64 nodes, 1,000 routes and a bounded work budget;
incomplete path reads signal truncation and incomplete impact analysis errors.
Connect request/response limits are 1/8 MiB. Minimum-version waits are bounded
at 500 ms in the runtime. Typed errors distinguish invalid input, missing nodes,
unavailable/stale graph, changed pagination context and exhausted analysis bounds.

## Local verification evidence

- Go 1.27.3, PostgreSQL 17, NATS 2.11; real dependencies run through existing
  digest-pinned Compose services. Native unit/integration checks pass.
- Linux `go test -race -tags=integration -count=1 -timeout=3m ./...` passes,
  including durable ingest, private-data separation, replay, quarantine/repair,
  puback-loss redelivery, durable consumer restart and live mutual-TLS APIs.
- `go test ./internal/graph -count=1 '-rapid.seed=20261104' '-rapid.checks=200'`
  compares CSR/control results with an independent edge-scanning fixed point
  on generated cyclic organizations. Deterministic tests cover indirect role
  administration, session state, multi-beneficiary impact and concurrent overlays.
- Buf lint, FILE compatibility with original peer descriptors and Phase 0
  `fa0621f`, generated protobuf/sqlc reproducibility, vet, module verification,
  scoped lint and actionlint are checked locally. Hosted CI is not claimed.
- [Benchmark output](phase-1-benchmark.txt): Windows amd64, i7-1260P,
  `GOMAXPROCS=1`, three measured iterations, about **1.38 seconds/op, 220 MB/op**.
  Command: `go test ./internal/graph -run '^$' -bench '^BenchmarkImpact100kEdges$'
  -benchtime=3x -benchmem`. Dataset: fixed sequential IDs, two humans, one role,
  100,000 tier-2 resources/grants; draft assigns the role to the second human.
  Build/loading is excluded; overlay construction and full impact are included.
  This first baseline does **not** meet the 100 ms target. Phase 5 retains
  optimization/tail-latency work; this result is not representative of a large
  multi-principal, tier-0-heavy organization.

## Outstanding acceptance and merge gates

Read-only dependency baseline: `origin/sakar` at
`9662c4692d583332a669d34ccf6eb23afee6df80`. An isolated combined source tree
overlays core-owned/shared proposals on a peer archive; neither branch is merged
or changed by that rehearsal. All Go packages compile together. The combined
normal race suite passes except the previously reproduced peer audit time-fixture
failure in four `TestOfflineVerifier_Comprehensive` subtests. Its historical
credential is not valid at the fixed 2026-11-03 event time; Phase 0 records the
untouched-peer reproduction. That test remains a real failure.

`go test -tags=peerintegration -run TestPeerSimulatorSnapshotConformance
./internal/connector/conformance` boots the real simulator and calls the actual
adapter. It currently fails these five checks:

| Check | Observed peer defect / required handoff |
| --- | --- |
| complete-envelope | No complete marker or agreed signed envelope; adopt complete snapshots, stable IDs, pinned signing and revision binding |
| graph-semantics | Withdrawal parameters have no declared guard kind; agree explicit authority semantics |
| all-edge-endpoints-exist | Grants target nonexistent `policy`, `audit`, `iam`; adapter must represent logical permissions and their actual effects |
| session-state-retained | All three seeded sessions are omitted; preserve session/revocation relationships |
| grant-provenance-retained | Seeded assignments omit grant identity; retain target grant IDs/provenance |

The peer connector executable additionally uses a logging publisher which
returns success without NATS delivery. Sakar owns replacing it with real
acknowledged publishing, reconnect/cursor handling and resync consumption.
These are explicit handoff items, not code changed in the peer branch.

Shared fixture review is outstanding. The exact peer seed/change files were
reused unchanged. The ordinary fixture refers to nonexistent
`user:finance-intern`; the additional core policy-fact case explicitly uses
existing `user:rahul-assistant`. The test-only seed compiler proposes conservative
`iam:all` effects and logical permission nodes; these are **review candidates**,
not a runtime adapter or claimed agreed target semantics. Review
`testdata/impact/rahul-admin-v1.json` and
`testdata/policies/phase1-impact-facts.json` together with the additive schemas.

The signed protocol runtime harness verifies a wallet path and unchanged graph
reads. It does not establish the actual peer connector D3 gate or unchanged IAM
through a live connector session. Do not sign off Phase 1 until that route works
with reviewed fixtures. The CI conformance step runs when peer sources are
present and fails normally until these defects are resolved.

For the eventual merge, preserve the peer-owned implementations, canonicalizer,
ports and seed inputs; retain core-owned packages and resolve shared additions
using the tested combined schemas/generated bindings, both dependency sets and
both CI portions. Independent add/add files still require deliberate resolution
as recorded in [Phase 0](phase-0-handoff.md). Successful compilation and additive
schema checks do not prove approval or guarantee a conflict-free future merge.
Do not alter `SAKAR_IMPLEMENTATION_PLAN.md` or silently accept a failing gate.
