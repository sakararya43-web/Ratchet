# Phase 2 core handoff and outstanding acceptance gates

Prepared 2026-11-04. All changes are on `main`. Phase 2 remains **in progress**:
the independently testable core is implemented, but the required real D1/D2
approval and target-execution evidence is unavailable. Phase 3 has not started.
Read this document and [the changelog](changelog.md) before continuing.

## Delivered behavior

| Area | Implemented operation |
| --- | --- |
| Login | Explicitly provisioned accounts, Argon2id password verification, durable expiring sessions, logout and password-rotation revocation |
| Session boundary | Server-derived tenant/actor, HTTPS Secure/HttpOnly/SameSite cookies, exact Origin and CSRF checks, bounded password concurrency and login buckets |
| Domain | Pure event-producing transitions, explicit supported-intent validation, holds/context updates, distinct-human approvals, verified completion/refusal, expiry and revocation transitions |
| Policy | Actual OPA 1.22 prepared queries loaded only through the peer BundleVerifier and a pinned epoch-1 genesis; structured decisions and default-deny authorization required |
| Demo rules | One independent common resource owner for ordinary access, two security leads for new tier-0 authority, rejection of tier-0 safeguard weakening, authorized computed reduction eligibility |
| Durability | Tenant-serialized events, encrypted private context, immutable receipts, projections, policy history, execution attempts and River job insertion in the same transaction |
| Assessment | Public graph authority facts, complete impact, signed policy hash, exact canonical envelope, recorded evaluator/facts, bounded approval lifetime |
| Approval orchestration | Peer verifier boundary, requester/control/beneficiary checks on current and proposed graph, group eligibility and distinct humans/credentials |
| Dispatch guard | Current graph/version/impact/policy/eligibility/envelope recheck, signed connector capability and target preconditions; changed context invalidates approvals |
| Result processing | Signed command-bound independent read-back; write acknowledgement alone cannot complete a request; signed unchanged-state refusal can record Failed |
| Recovery | Durable delayed read-only reconciliation, successor probes for lost replies, terminal-state stopping, no blind write retry |
| API | Real session-authenticated Change and Overview operations, bounded signed list cursors, Graph and draft Impact authorization |
| Runtime | HTTPS `console-serve`, explicit administrative `provision-users`, actual PostgreSQL/River/JetStream, graph recovery/refresh, relay and result consumers |

`ROLE_ASSIGN`, `ROLE_REVOKE` and `MODIFY_SAFEGUARD` are the supported assessment
intents. Unknown kinds return a typed error. The proposed execution transport
currently supports role assignment/removal; safeguard execution is unavailable.
No future service handlers or placeholder webpage are mounted. The UI remains
peer-owned; these endpoints can be used by the actual console when integrated.

Temporary/emergency grants are validated and held until the durable expiry work
in Phase 5. The current envelope expires after 15 minutes and dispatch refuses
expired proof. Configurable expiry/revocation jobs are not claimed here.
Reduction eligibility does not provide the later Phase 4 containment fast path.
All dispatch still requires passkey-confirmed authorization.

## Run and provision

Use [core development](core-development.md) to start the real local services and
load private runtime/migration DSNs. Stop older console workers before upgrading
to schema version 5: it moves existing workflow jobs from the former shared queue
to deterministic tenant queues. Run `ratchetd migrate` with the migration DSN;
serving does not migrate. The migration is irreversible to preserve evidence.

Provision account credentials in a private, ignored JSON array. Each object has
`tenant_id`, `actor_id` and `password`. Use the real graph's human actor ID.
Passwords must be 16-256 bytes. There is no shipped default account/password.

```powershell
. ./scripts/core-env-load.ps1
go run ./cmd/ratchetd migrate
go run ./cmd/ratchetd provision-users --config .local/accounts.json
go run ./cmd/ratchetd console-serve --config .local/console.json
```

The console configuration is one strict JSON object with these fields:

| Field | Required source |
| --- | --- |
| `origin` | Exact HTTPS browser origin, without a trailing slash |
| `session_key_hex` | Independent 32-byte CSRF HMAC key, hex encoded |
| `graph_key_hex` | Existing 32-byte graph/private-data encryption key, hex encoded |
| `cursor_key_hex` | Independent 32-byte list/graph cursor HMAC key, hex encoded |
| `server_cert`, `server_key` | Actual PEM TLS certificate and private-key paths |
| `nats_url` | Real JetStream URL; local Compose is `nats://127.0.0.1:54222` |
| `nats_credentials` | Credentials-file path; required with TLS for remote NATS |
| `tenants` | Array of tenant policy configuration objects described below |

Each tenant object has `tenant_id`, `authority_file`, `genesis_digest` and
optional `bundle_file`. Supply the actual peer Authority store and independently
pinned genesis SHA-256 hex digest. An optional bundle file is a real signed
candidate. A refused candidate retains the persisted last valid policy; absence
of any valid policy makes decisions unavailable. Restore re-verifies the durable
artifact and enforces its version floor. Epochs beyond 1 refuse activation until
verified rotation-history support is delivered in Phase 3.

The default listener is `127.0.0.1:8444`. Login is `POST /api/auth/login` with
`tenant_id`, `actor_id`, `password` JSON and the exact Origin header. The response
sets the secure session cookie and returns `csrf_token`. Use that cookie, Origin
and `X-CSRF-Token` for all API POSTs, including Connect reads. `GET /api/auth/me`
returns the current server-derived identity and CSRF token; `POST /api/auth/logout`
revokes the cookie's durable session. Unrecognized caller identity headers have
no authentication effect. Provisioning an account again revokes prior sessions.

Generated Connect clients use the HTTPS origin plus `/api`. The authoritative
approval bytes are `canonical_approval_envelope_json`; hash those exact bytes
with the shared canonicalizer rather than reconstructing a descriptive display
message. Approval submission bytes follow `ports.ApprovalSubmission` JSON
(byte slices use standard base64). Shared UI wire agreement remains a peer gate.

Graph recovery occurs before workers start. An incorrect decryption key for an
existing graph refuses startup. Missing/quarantined graph context stays
unavailable. Workers poll only explicitly configured tenant queues. Queue names
are `r_` plus the first 24 bytes of SHA-256(UTF-8 tenant ID), hex encoded.

Liveness and storage readiness report actual dependencies. Full readiness stays
503 while the workflow's required verified dependencies are absent. The console
does not mount the unsafe peer passkey factory, and no flag bypasses this gate.
Requests remain pending/held; there is no automatic approval or simulated write.

## Proposed execution evidence contract

The executable specification is `internal/workflow/execution.go`. It remains a
proposal requiring the peer's implementation/agreement; the current peer adapter
does not claim this protocol. It preserves existing PRD NATS subjects:
`ratchet.<tenant>.exec.<connector>` and `ratchet.<tenant>.exec.results`.

The connector's pinned Ed25519 public key verifies a capability binding tenant,
connector, protocol `RATCHET_EXEC_V1`, expiration, bound commands, atomic target
preconditions, durable deduplication and independent read-back. Capabilities must
be valid at dispatch and expire within 24 hours. No runtime switch asserts these
capabilities on behalf of a connector.

Commands bind schema version, message/command/request/correlation IDs, tenant,
connector, exact approved envelope/digest, assertions, expected source revision,
before/expected role sets, dispatch time and deadline. Core signs them with its
Ed25519 key. A signed VERIFY_ONLY command retains the original command ID and
uses a new stable message ID; it must never perform an IAM write.

Results are signed by the configured connector and bind the same IDs and digest.
Independent read-back includes tenant, target, sorted roles, source revision,
observation time/digest and actual application time. Success requires the exact
expected role set and revision `base + 1`; application must be within the original
dispatch/deadline interval. Delayed observation can prove timely application.
A verified refusal requires unchanged roles/revision and no application time.
Uncertain application stays Executing with signed evidence and another probe.

Signing clears `signature` to nil, computes the shared canonical digest of
`{"domain": <domain>, "body": <typed value>}`, then signs its 32 bytes.
Domains are `RATCHET_EXEC_CAPABILITY_V1`, `RATCHET_EXEC_COMMAND_V1` and
`RATCHET_EXEC_RESULT_V1`. Go JSON digest arrays remain numeric 32-byte arrays,
byte slices use standard base64, and times use UTC RFC3339 with Go's precision.
Observation digest is the canonical digest of the typed object with fields
`Tenant`, `Target`, `Roles`, `Revision`, `At`. These exact encodings require peer
review before transport interoperability can be claimed.

## Verification and peer gates

Core checks pass using real PostgreSQL 17, JetStream, TLS, River and cryptography:

Hosted [CI for the runtime candidate `4e9727f`](https://github.com/sakararya43-web/Ratchet/actions/runs/41858014416)
passes both core-contracts and core-tests, including the real dependency suite.

- Full Linux `go test -race -tags=integration -count=1 -timeout=3m ./...`.
- Additional affected workflow/API/console race acceptance after recovery and
  login-bound fixes; native integration acceptance for the same components.
- Scoped lint, Buf lint, compatibility against the original peer descriptor and
  Phase 1 main, plus reproducible generated protobuf/SQL bindings.
- Real command receipts/rollback tests, worker tenant isolation, policy rejection,
  concurrent submit deduplication, private-data separation and projection rebuild.
- Fresh-worker recovery of an existing uncertain execution, preserving exactly
  one original write command while publishing read-only probes.
- Module verification, vet, actionlint and real new-process persistence/readiness
  smoke. The full combined core/peer race run compiles both halves but fails four
  inherited `internal/audit` fixture cases, as recorded in the earlier handoff.

The execution library tests use ephemeral real keys and the actual peer verifier
with a PKIX-key fixture. They are **not** browser enrollment, a normal COSE-key
assertion, or proof of an actual peer IAM grant. D1/D2 remain unpassed.

Read-only rehearsal against unchanged `origin/sakar` commit `9662c46` reproduces:

| Peer gate | Actual result / required correction |
| --- | --- |
| Passkey origin, RP and ceremony | Invalid origin, RP-ID hash and ceremony type are accepted; validate the complete WebAuthn context |
| Real enrolled key | The verifier expects PKIX while enrollment stores COSE; normal COSE key verification fails |
| Session-bound factory | Unauthenticated credential list returns 200; use the agreed server-derived session identity for every ceremony/credential operation |
| Unsafe ceremony route | The factory exposes `/assert/simulate`; it must not be a production approval path |
| Atomic target precondition | An actual stale-revision role grant succeeds and changes persisted IAM; propagate and atomically enforce the expected revision |
| Bound transport | Implement the agreed authenticated command, capability and read-back evidence; the existing log-only publisher is not a completed transport |
| Snapshot context | Complete/signed envelope, declared safeguard semantics, three dangling resource endpoints, sessions and grant provenance remain unresolved from Phase 1 |

Actual adapter duplicate delivery, missing-role read-back refusal and persistent
target recovery after a lost acknowledgement pass their component cases. Those
successes do not waive the failed atomic-precondition or passkey cases.

Executable peer regression entry points are:

```text
go test -race -tags=peerintegration -count=1 ./internal/connector/conformance
```

Run that in a combined reviewed checkout containing the actual peer packages;
the main-only checkout intentionally does not include peer handlers/simulator.
The shared CI enables it when the real simulator package exists. Do not weaken
these tests or modify Sakar-owned implementations to make this handoff green.
The verifier boundary must also agree how persisted assertion evidence is
revalidated at dispatch without creating or replaying a fresh approval ceremony.

Both branches remain separate. A read-only merge-tree rehearsal reports add/add
conflicts in Buf configuration, Go module/checksum files and eight shared proto
sources. The additive schema passes Buf compatibility, but a raw GitHub merge
still requires reviewed shared-file resolution. Neither branch is rewritten by
the rehearsal. Existing peer audit-fixture failures remain a separate Phase 0
gate. A fully green merged branch cannot be promised with these known failures.

Phase 2 can be signed off only after a genuine enrolled owner approval executes
and reads back ordinary access, two independent security leads satisfy D2,
self-approval and bad read-back cannot grant access, all transitions remain
hash-chained, and the integrated candidate passes the tests above. This handoff
does not substitute core-only tests for that exit evidence.
