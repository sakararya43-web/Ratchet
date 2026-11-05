# Phase 6 implementation and acceptance record

Phase 6 is in progress on `main`. Phase 7 has not started. The user confirmed
that `origin/sakar` at `d823a10` is the peer's final implementation; a newer peer
delivery is not expected. The branches remain separate, and peer-owned source
and implementation plans are unchanged.

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

## Remaining work and gates

- Adopt normalized graph projection and retained source context in policy/workflow
  and DecisionService. Authenticated native ingestion is implemented.
- Authenticate native admission identity and exact context; correlate approved
  commands through DecisionService, independently observed target state and
  durable execution records. Pure context/authentication checks are implemented;
  they do not constitute an execution permit or complete this task.
- Native drift/read-model evidence and explicit supported/unsupported D1–D8 scope.
- Real peer adapter admission, outage, approved execution/read-back and latency
  acceptance on kind. Matcher tests alone do not satisfy this gate.

The final peer source still uses an in-memory cluster state and local intent
matching. Its webhook does not call the core DecisionService. Peer completion
checkboxes therefore do not prove the integrated exit requirements. No runtime
substitute or trust bypass is authorized to conceal those gaps.
Actual combined-source tests reproduce five failed acceptance assertions; see
[final peer gates and D1–D8 scope](phase-6-peer-gates.md).

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
signed off and no claim of 100% integrated success is made. Native policy,
approval/DecisionService, command/observation and drift/incident adoption are
still required core work; those are not attributed to the peer or silently cut.
