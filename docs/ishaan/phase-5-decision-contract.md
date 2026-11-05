# Phase 5 inline decisions

`DecisionService.Decide` is mounted behind the console's authenticated HTTPS
session and CSRF checks. Tenant and requester must match that session. The same
database graph, verified policy/registry floor, impact analysis and independent
eligibility checks govern this endpoint and normal workflow execution. Ordinary
requesters receive redacted reasons; policy detail requires investigator access.

Every valid new admission records `InlineDecisionRecorded` in the immutable tenant
chain before returning. It binds admission ID, authenticated actor, exact intent,
object digest, target revision, approved request, graph/policy/registry versions,
database decision time and deadline. PostgreSQL tenant serialization makes
consumption atomic across callers and replacement processes. Persistence failure
returns an error; no allow may be released before commit.

`outcome` alone never authorizes a write. `execution_authorized` is true only for
an already-staged, independently approved simulator command that passes current
checks. `approved_request_id` identifies the Executing request;
`admission_request_id` must equal its command ID. `target_revision` is the exact
decimal command precondition. For simulator intents, `exact_object_digest` is the
canonical core `domain.Intent` digest, including all optional scope, duration and
incident fields as encoded by the canonicalizer. It is not a digest of arbitrary
unparsed JSON or Kubernetes objects. Unknown context/mappings are refused.

The consuming caller must bind the response to that exact admission, object,
target revision and deadline, enforce the command's durable deduplication and
atomic target precondition, and independently report read-back. An allow cannot
be used for another object, command or revision. Repeating the same admission
after consumption returns HOLD without another execution authorization. Changing
its inputs returns an idempotency conflict. A lost response is reconciled through
the original command rather than granting again. The endpoint does not submit a
request, enqueue a second write or mark an execution verified.

Without the exact approved command, the policy's REQUIRE_APPROVAL/HOLD/REJECT
result is durable. A policy-only ALLOW for a reduction is downgraded to HOLD until
the normal guard authorizes a command. External Kubernetes object mapping and
admission identity are Phase 6 work; this endpoint does not claim that parity.

Core PostgreSQL tests cover simultaneous callers (exactly one allow), restart,
changed object/revision, unapproved tier-0 requests and preservation of Executing
until read-back. The real TLS test covers session authentication, redaction and
requester impersonation. Peer connector consumption is still a joint acceptance
gate; its branch and source remain unchanged.
