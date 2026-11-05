# Phase 6 implementation and acceptance record

Phase 6 is in progress on `main`. Phase 7 has not started. The user confirmed
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

## Remaining work and gates

- Real peer adapter admission, outage, approved execution/read-back and latency
  acceptance on kind. Matcher tests alone do not satisfy this gate.
- Actual connector adoption of native normalized input, identity directory facts,
  signed capability/commands, admission permits, target CAS, independent read-back
  and drift watch. Native automatic correction/live continuity remain unresolved
  D6/D7 mappings; no unproved inverse or blind rollback is implemented.

The final peer branch uses in-memory cluster state and local intent matching.
Under the connector-fix authorization, main now has actual Kubernetes API
inventory, complete signed normalized cuts, exact native admission normalization,
signed command staging, a TLS DecisionService client, encrypted durable pending
context and independent API read-back with durable signed results. The native
runtime requires API-server mutual TLS and has no local intent-registration
route. No target write occurs in reconciliation.

On 2026-11-06, all six previously reported interface/live-inventory assertions
pass against these changes. The actual full kind graph also fits a 648,370-byte
immutable event and replays exactly after private-source deletion. Domain tests
still match 17 real authorizer queries across 9 configurations. These results
do not complete real API-server approved-write/outage/latency acceptance or
native drift watch publication. See [historical peer failures and D1–D8 scope](phase-6-peer-gates.md).

## Validation

Passing local checks include the full serialized Linux race/integration suite
against actual PostgreSQL/JetStream (workflow: 202.669 seconds), native-source
privacy/replay/resync tests, 300-case properties at seed `20261105`, integration
vet, module verification, Buf lint and breaking checks against both the peer
baseline and preceding `main`, and reproducible protobuf generation. Core lint
reports zero issues. A final aggregation work bound and detached rule-result
regression also pass the domain/graph/bus/eventstore integration/race suites.

The real kind authorizer comparison passes independently of the peer adapter.
The actual peer assertions in the gate report remain failing. Phase 6 is not
signed off and no claim of 100% integrated success is made. Native core workflow,
DecisionService, command/read-back and drift/incident implementation now exist;
the new candidate's full checks are being rerun. Peer adoption and the real kind
exit evidence remain required, and are not silently deferred or cut. Phase 7
cannot be called complete while the selected Phase 6 acceptance is failing.
