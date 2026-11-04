# Phase 4 implementation checkpoint

Prepared 2026-11-05. **Phase 4 is in progress.** Phase 3's core implementation,
adversarial checks and [handoff](phase-3-handoff.md) were committed before this
phase began. Earlier actual-peer integration gates remain open. Phase 5 has not
started. Read this page and the changelog before resuming; unchecked tasks in the
implementation plan remain required.

## Delivered containment planning

The graph now proves `IsMonotonicReduction` for all identities and preserves
structural safeguards. Removing denies, approval requirements, protective
memberships or protected edges is not a reduction. Critical assets cannot be
deleted/relabelled to manufacture zero reach. Unknown property changes refuse
the fast path. Account restriction and known safeguard strengthening retain their
explicit semantics.

Executable transformations cover complete role revocation, original service
permission removal, session termination and account restriction. A role action
removes all matching bindings. Service permissions require `grant_id` provenance
and remove all graph effects of that original grant. A derived reachability edge
is not a target operation. Protected/non-removable operations are excluded.

The planner builds a weighted flow network with a super-source for explicitly
listed compromised identities and a super-sink for tier-0 assets. Shared service
grants cost once. Linear membership/role/resource topologies have a minimum-cut
proof within the executable catalog. Other semantics use bounded catalog search;
every candidate is simulated through the actual graph and all-identity reduction
proof. A bounded result advertises `minimum_proved=false` and
`algorithm=verified-bounded-alternative`. No unproved global optimum is claimed.

The production planning call permits 2,048 candidate checks. Search/cancellation
limits fail explicitly if no verified safe result is found. Returned plans prove
zero remaining tier-0 authority for their listed origins under the proposed
actions, and report affected/preserved non-critical activities for all identities.
These are graph proofs of a proposal, not target read-back or an execution result.
Already-stolen identities/tokens must be represented by the incident's explicit
compromised-origin set; the planner does not invent historical possession.

Schema 7 persists the canonical proposal, its digest, immutable command meaning
and ledger position atomically. The proposal binds tenant, requester/correlation,
graph, policy/registry, catalog, actions, proof, costs and a five-minute validity
window. Concurrent retries return one proposal; changed input conflicts. Planning
does not publish an execution command, create an execution attempt or alter graph.

## Configure and use the actual endpoint

Run migrations before starting the console. Add explicit integer operator costs
to the existing private console configuration as `containment_costs`. Allowed keys
are `ROLE_REVOKE`, `REMOVE_SERVICE_PERMISSION`, `TERMINATE_SESSION` and
`RESTRICT_ACCOUNT`; values must be 1 through 1,000,000,000. Missing kinds are not
offered. The program supplies no default business/risk weights. Optimality refers
to these configured costs and executable catalog, not a learned disruption score.

With costs configured, the real Connect `ContainmentService.PlanContainment`
operation is mounted. Supply tenant, compromised identity, optional minimum graph
version and a `MutationContext` with stable idempotency/correlation UUIDs and
expected revision zero. The normal session cookie, Origin, CSRF and current signed
`containment_plan` authorization are required. The demo rule permits security leads.

The response includes exact `canonical_plan_json` bytes; their shared SHA-256
digest is `plan_digest`. It also returns minimum-proof scope, cost, algorithm,
proposed-zero-tier-0 proof and activity changes. Check `route_count_complete`
before treating captured path counts as exhaustive. The canonical body includes
the registry context and expiry; do not rebuild approval bytes from display fields.

ExecuteContainment and RestoreAccess are currently unmounted. No success-returning
handler or unsafe passkey path stands in for their unfinished orchestration.

## Audit export and checkpoint primitives

Schema 8 adds tenant-isolated audit projections and actor/time, request, incident
and resource indexes. Each event updates its display projection in the same
transaction. Missing projections rebuild from a verified contiguous ledger
prefix; known request-resource context is carried across lifecycle records.

`AuditService.QueryAuditEvents` applies actor/resource/request/incident/time
filters with current signed `audit_query` authorization. Page cursors bind tenant,
normalized filters and a fixed end position. The default page size is 50, maximum
200. Results contain only display metadata, without raw assertions, canonical
bytes or decrypted justification. Display state is checked against canonical
source events; read models are rebuildable and are not offline chain proofs.

The real `AuditService.ExportHashChain` operation is mounted with signed
`audit_export` authorization; the demo rule permits security leads. It returns
exact canonical events and original IDs/stream positions/hash links with profile
`RATCHET_LEDGER_CHAIN_V1`. It never decrypts private requester context.

Pagination binds the tenant, requested range, fixed captured tip and predecessor
hash using a purpose-separated HMAC cursor. Continue with the same request range
and returned token. The default page size is 25, maximum 100; actual canonical
bytes are capped at 4 MiB per page. Appending events during a download does not
change its captured end. A range beginning after genesis needs its independently
verified predecessor/coverage evidence; an internally consistent range alone is
not a witnessed full-chain proof.

`ledger.BuildCheckpoint` constructs a candidate with profile
`RATCHET_LEDGER_CHECKPOINT_V1`: ordered final event-hash leaves, binary SHA-256
parents and duplicate-last odd handling, matching the actual peer Merkle routine.
It verifies the supplied sequence range and predecessor before construction.
Subsequent ranges require a prior checkpoint reference.

`policy.Registry.VerifyCheckpoint` verifies the signed return against a root-verified
historical registry. It calls the actual peer SignCheckpoint method for **each**
signature, then checks quorum. The peer VerifyCheckpointSignatures method only
counts entries and is insufficient by itself. No private signing key exists in
these core primitives, and an unsigned candidate is never reported as signed.

## Evidence and remaining work

Passing focused checks cover surgical two-asset cuts, finance-report preservation,
shared grants, protected catalogs, cancellation, nonlinear bounded optimality,
takeover counterexamples and seeded exhaustive-catalog comparisons. PostgreSQL/TLS
checks cover authorized/idempotent planning, unchanged live state, canonical bytes,
ordinary-user refusal, raw-chain verification, fixed-tip pagination and cursor tamper.
Checkpoint tests cover valid real signatures and altered/duplicate/missing evidence.

The full core Linux `go test -race -tags=integration -count=1 -timeout=3m ./...`
suite passes at this checkpoint, as do vet, zero-issue scoped lint, Buf lint and
breaking checks against the peer and Phase 3 baselines, and reproducible SQL/proto
generation. These checks cover the delivered operations; they do not mark the
remaining Phase 4 tasks complete.

Required Phase 4 work still includes passkey-confirmed responder execution on the
priority transport, target read-back/recovery and incident projections, restoration
through a new independently reviewed increase,
the complete offline evidence package (including historical approval keys), and
candidate submission/signed-checkpoint acceptance-reference orchestration.
Five-second D6 and actual business-continuity D7 measurements remain unpassed.
The core planner's simulated report preservation is not that target measurement.

The known peer passkey/session, target precondition, transport and snapshot gates
remain as recorded in Phase 3. No Sakar-owned source, plan or branch was changed.
