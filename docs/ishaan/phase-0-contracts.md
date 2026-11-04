# Phase 0 integration contract

Status: proposed additions for joint review, based on Sakar commit `9662c46`.
Existing protobuf field numbers, service names, ports and canonicalization are retained.
Schema declaration does not register an HTTP route or implement an RPC.

## Identity, errors and versions

The authenticated transport supplies actor, tenant and connector identity. Request
fields such as `requested_by`, `approver_id` and `responder_id` are compatibility
fields, never authentication. Handlers must reject a mismatch and pass only the
server-derived identity into verifiers. A credential belonging to a different
tenant is invalid even when its public key verifies. The `SessionAPI any` port is
not sufficient for production mounting: agree a typed adapter with the peer before
Phase 2. No untyped identity fallback is permitted.

Tenant identifiers are opaque nonempty strings (the existing seed uses named IDs,
so a UUID-only network contract would break integration). Durable event, command,
actor-reference and private-record identifiers are UUIDs. Graph and stream
revisions are nonnegative signed 64-bit integers; ledger values hashed through JCS
must be within 0..9007199254740991. Zero enum values mean unspecified and are
rejected for commands. Unknown semantics fail closed.

Typed errors map to Connect invalid_argument, unauthenticated, permission_denied,
not_found, already_exists (idempotency-key reuse with different intent), aborted
(expected-version conflict), failed_precondition (context changed),
resource_exhausted, deadline_exceeded and unavailable. Never disclose stored
credentials, assertion bytes or private data in an error message. A shared
`ErrorDetail` adds a machine-readable reason and revision information.

List operations order by a stable `(tenant_sequence, entity_id)` pair; opaque
cursors bind tenant, filters and snapshot position and are validated server-side.
Default page size 50, maximum 200. Graph path traversal is bounded; truncation is
explicit. `min_graph_version` waits at most the caller deadline and configured
maximum, then returns unavailable with the actual version. A watch cursor resumes
after its last delivered committed event; an expired cursor requires a fresh list.

## Approval and replay

The approval envelope includes its format version, tenant, request/revision,
authenticated requester, exact typed intent and target, incident link, graph
version, impact digest, policy bundle hash and UTC expiration. Changes to any
element invalidate prior approval evidence. Justification is an encrypted private
record; bind its opaque reference and digest, never copy the text into the chain.
Digest bytes come only from `ports.Digester` implemented by `internal/canon`.
The browser must digest the same envelope, not a separate display projection.

`ApprovalVerifier` validates enrolled credential, tenant/actor binding, exact
challenge, RP ID, origin, nonce, user verification and credential validity. Core
workflow separately verifies independent distinct humans, allowed group, no
self-benefit, expiry and quorum, both when approving and before execution.
`BundleVerifier` failure cannot activate a bundle; no valid initial bundle means
escalation unavailable. Root/registry history, monotonic bundle versions and
validity must be established before execution. A verified signature alone is
not workflow authorization.

Replay fact sheets record evaluator/schema version, exact input facts, graph
revision, policy hash, authenticated pseudonymous actor reference, decision time
as an input, decision/reasons and required approvals. Policy evaluation cannot
read wall-clock time or the network. Personal display data stays separately
encrypted. The ledger preserves non-personal facts needed to reproduce decisions.

## Connector transport

These five subjects remain unchanged:

```
ratchet.<tenant>.ingest.sync
ratchet.<tenant>.ingest.audit
ratchet.<tenant>.exec.<connector>
ratchet.<tenant>.contain.<connector>
ratchet.<tenant>.exec.results
```

The authenticated NATS account and connector permissions must agree with every
message's tenant/connector. Subject tokens cannot contain `.`, `*`, `>` or spaces.
Envelope schema version starts at 1; correlation and stable message IDs survive
redelivery. Snapshots identify an atomic completed source revision; deltas apply
only to their exact base revision. Gaps require resync. Repeated identical IDs have
one effect; conflicting content under an ID is rejected.

Execution binds command/request IDs, connector, tenant, approved envelope digest,
graph/policy version, deadline and exact target preconditions. Connector read-back
evidence includes target revision, observation time and state digest. A write ACK
is not verification. An `is_reduction` flag is never proof: core computes the
reduction and the priority consumer must validate the authorized command. Changes
to peer connector Go structs/transport remain peer-owned and require handoff.

## Hash chain, version 1

The content object matches the peer's `internal/audit.ComputeEventDigest` keys:
`action`, `actor_id`, `event_type`, `payload`, `previous_event_hash`, `sequence`,
`target_identity`, `tenant_id`, `timestamp`. All keys are present, including empty
action/target strings. `actor_id` is a pseudonymous UUID reference, not a name.
Timestamp is UTC RFC3339Nano at PostgreSQL microsecond precision. Sequence is an
integer starting at 1, contiguous per tenant in **commit order**. Genesis is 32
zero bytes; `previous_event_hash` inside content is lowercase 64-character hex.

```
canonical_bytes = real_peer_digester.Canonicalize(content)
event_hash = SHA256(previous_hash_raw_32_bytes || canonical_bytes)
```

`event_hash` is excluded from content. Store exact canonical bytes as `bytea`,
not a JSONB reserialization. `payload` carries `format_version: 1`, event UUID,
stream ID/version, command UUID, public facts, and optional private record ref.
Assertions/envelopes, when introduced, belong inside these hashed facts; an
unhashed top-level assertion must never be authoritative. The existing audit
protobuf hash comment has the opposite concatenation order; its clarification
must match the peer's executable implementation and this spec.

A tenant chain-head row is created then locked `FOR UPDATE` for the complete
append transaction. Sequence allocation, stream conflict checks, command receipts,
events, encrypted private rows, outbox and chain-head update commit together.
Postgres sequence generators cannot define chain ordering. Idempotent retries
compare a canonical command digest and return the original receipt; a changed
intent using the same ID is an error. Crash/rollback creates no committed gap.

Runtime does not own tables, create objects, bypass RLS, or have superuser rights.
It cannot update/delete/truncate events or receipts; it can update the chain head
and delivery bookkeeping. Migrations run separately as an owner role. A DB owner
or superuser remains capable of tampering: chain verification and later signed
checkpoints detect it; SQL grants do not make that impossible. Retention deletes
encrypted private records/keys without rewriting canonical event bytes.

## Outstanding peer agreement

Confirm approval envelope/canonical vectors, typed session binding, additive
connector fields/Go transport, the chain encoding above and historical evidence
required by the offline CLI. Do not label the contract frozen until reviewed.
