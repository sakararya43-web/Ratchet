# Authenticated drift decisions and incidents

The core consumes `SignedDriftReport` protobuf JSON on
`ratchet.<tenant>.drift.reports` through a file-backed JetStream stream and durable
explicit-ack consumer. It acknowledges only after the PostgreSQL transaction
commits. This is a contract for the real connector publisher; the current pinned
peer CLI does not yet implement this publisher.

The wrapper adds an Ed25519 signature to the existing `DriftReport`. The pinned
execution connector key verifies `DriftSigningDigest`, using domain
`RATCHET_DRIFT_REPORT_V1`, canonical protobuf JSON with an empty signature and
the existing canonical digester. Tenant, connector, message/correlation/operation
IDs, source revision, timestamps and any nested envelope must agree. Severity and
the report's claim that a change is a reduction never authorize execution.

Each audit operation has an immutable tenant/connector-scoped receipt. Transport
redelivery with a new message or drift ID returns that receipt; changed semantic
content under an existing operation/drift ID conflicts. The raw signed report is
encrypted separately; public evidence retains opaque provenance and digests.

The synchronized source must reach the observation revision and be free of a
resynchronization quarantine. An observation ahead of the source retries; an old
observation is recorded as stale. Exact approved-command correlation checks the
command ID, correlation, target, action, roles, revision and timing. It prevents
read-back delay from creating an incident without treating an audit report as
independent execution verification. A copied correlation cannot excuse another
write. Corrective-command observations follow the same checks, preventing loops.

An unauthorized observation opens one durable incident. Automatic correction is
limited to removing the exact observed unauthorized role assignment. The core
requires retained authenticated source evidence for the original grant ID and
protection metadata, a current monotonic-reduction proof, current responder
authorization, a current policy ALLOW with zero quorum, and a signed connector
capability with `proven_reductions=true`. Missing/erased source security evidence,
protected grants, unsafe inverses and other operation types stay in review. The
core never restores a removed permission automatically.

The corrective change, incident, receipt, evidence, reconciliation job and signed
command/outbox commit atomically. Purpose `DRIFT_REDUCTION` binds the source drift,
incident and reduction digest to the exact role operation, expected revision and
roles. An old connector capability cannot opt in accidentally. The actual peer
target must adopt this contract, atomically enforce its precondition, deduplicate
the command and publish signed independent read-back evidence.

Staging and write acknowledgements do not become verified actions in IncidentService.
After the existing result verifier accepts exact independent target evidence, the
incident records the verified correction and a durable job waits for graph sync.
Only matching observed roles plus complete zero-residual-tier-0-path analysis
mark the incident CONTAINED. Residual paths or later target changes reopen review
without issuing another write. Restoration creates a new ordinary access request
with fresh independent approval; corrective authority is never reused.

Configure a real eligible security-lead identity as tenant `drift_responder`.
Identity membership and current signed policy are checked for every observation.
Absent execution dependencies remain unavailable; no fixture-backed production
publisher, verifier or target replaces them.

Actual PostgreSQL/River and JetStream tests cover concurrent delivery, semantic
deduplication, copied correlation, normal read-back delay, forged signatures,
protected/erased source evidence, transaction rollback, graph lag, verified
correction, containment timing, feedback prevention and fresh restoration review.
These protocol fixtures prove the core boundary, not peer publisher adoption.
