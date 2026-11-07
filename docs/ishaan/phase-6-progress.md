# Phase 6 implementation and acceptance record

Phase 6's five Ishaan core tasks are implemented and the selected real-kind
acceptance passes on `main` (2026-11-06). Phase 7 has not started. This is not
whole-project release acceptance or a claim of full Kubernetes D1-D8 parity.
The user confirmed
that `origin/sakar` at `d823a10` is the peer's final implementation; a newer peer
delivery is not expected. The user then explicitly authorized fixing the
Kubernetes connector on `main`. The branches remain separate; Sakar's branch
and implementation plan are unchanged.

## Completed core work

- Pure normalized RBAC rules, identity/group roster, discovery scope, role and
  binding models, aggregation and exact UID/resource-version mutation checks.
- Resource/subresource, wildcard, resource-name and non-resource URL matching;
  namespace restrictions, service-account groups and bounded rule-coverage proof.
- Proposal isolation, missing-role binding behavior and aggregation-cycle tests.
- Live kind RBAC oracle: 17 SubjectAccessReview queries across 9 actual
  configurations pass. See [reproduction and scope](phase-6-kind.md).
- Immutable graph projection with bounded combined privilege closure: token
  takeover, separate user/group impersonation, system:masters, bind plus binding
  write, and edit/create plus escalate. Fresh-name witnesses cover unobserved
  roles; common permission witnesses distinguish wildcard expansion/reduction.
  Tests include name collisions, immutable binding roleRefs, aggregation labels
  and nonrequester beneficiaries. Analysis limits return errors, never safe results.
- Exact native admission context, observed actor/UID/group/preimage checks and
  connector-pinned Ed25519 authentication with bounded lifetime and detached
  verified evidence. [Contract and remaining adoption](phase-6-admission-contract.md).
- Authenticated normalized snapshot ingestion through actual PostgreSQL/JetStream,
  encrypted source context, non-personal replay, revision conflict protection,
  cluster ownership and resync quarantine. Whole-organization proposal analysis
  retains external controllers and unrelated business access.
  [Native ingestion contract](phase-6-native-ingest.md).
- Native submission, policy/independent approval, anonymous assessment replay,
  guarded command staging, authenticated DecisionService one-use permits and
  exact signed independent read-back are implemented. Concurrent consumption,
  restart, mismatch, HTTPS and private-deletion checks pass against PostgreSQL.
  CREATE/UPDATE/DELETE read-back tests check opaque versions and recreated UIDs.
  See [the workflow contract](phase-6-native-workflow.md).
- Signed native drift evidence validates committed baselines and current source
  cuts, computes whole-organization impact and current policy, correlates exact
  consumed admissions and atomically opens unapproved-change incidents. Get,
  list and watch retain anonymous evidence after private report deletion. See
  [the native drift contract](phase-6-native-drift.md).

## Actual exit evidence

The authorized connector corrections on main replace in-memory source data and
local intent grants with real API inventory, complete signed source cuts,
mutually authenticated API-server admission, guarded signed commands, a TLS core
RPC, encrypted pending context and independent signed target read-back. Only
the API server applies the submitted object; reconciliation never writes.

The isolated real-kind acceptance passed in 446.27 seconds. It proves a real
independent cryptographic approval, durable JetStream command/result transport,
exact one-use admission, actual API creation, independently observed EXECUTED
state, refusal of an unapproved binding and refusal/absence of a sensitive
binding while the core HTTPS service is stopped. The approved sample took
1,201.2869 ms in the webhook and 1,547.2038 ms for the API write. These are single
sample measurements, not percentile or load claims; the admission deadline
remains three seconds. [Machine-readable evidence](evidence/phase-6/actual-kind.json).

The same run ingests actual signed post-write cuts and publishes authenticated
native observations through the implemented drift boundary. The approved write
receives CORRELATED_APPROVED_COMMAND. A second actual out-of-band binding receives
HELD_FOR_REVIEW with complete impact and an incident visible through get, list
and the paginated contiguous event stream. The test removes only its own webhook
to inject this bypass; production exposes no exception or second grant route.
This proves core support for actual RBAC evidence, not an automatic cluster-wide
watch collector or audit attribution service.

All six historical interface/live-inventory assertions now pass on main. A full
real source cut (6,736 nodes, 36,752 edges) stores in a 509,422-byte immutable
event and replays exactly after private-source deletion. The RBAC matcher agrees
with all 17 actual authorizer queries across 9 live configurations.

## Validation and scope

The full serialized Linux race/integration suite passes against PostgreSQL and
JetStream (workflow: 311.459 seconds). Focused native ingest/workflow/connector
regressions, zero-issue core lint, tagged vet including kind acceptance, module
verification and 300-case properties at seed 20261105 pass. Contract checks,
generation and process-smoke checks are also enforced by the existing main CI.
Reproduction commands are in [the kind guide](phase-6-kind.md).

All five Phase 6 tasks retain their original requirements. Native automatic
rollback, an always-running drift/watch collector, live containment continuity,
financial safeguards, external authorizers and the real browser passkey ceremony
are not demonstrated native mappings. The [D1-D8 matrix](phase-6-peer-gates.md)
records these explicitly; full simulator/release acceptance and earlier joint
gates remain open. Ambiguous writes remain held for review. No inferred inverse,
invented timestamp, fake target state or approval bypass completes this phase.
