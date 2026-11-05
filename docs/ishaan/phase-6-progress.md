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

## Remaining work and gates

- Adopt normalized graph projection in authenticated ingestion and policy/workflow.
- Authenticate native admission identity and exact context; correlate approved
  commands, independently observed target state and durable execution records.
- Native drift/read-model evidence and explicit supported/unsupported D1–D8 scope.
- Real peer adapter admission, outage, approved execution/read-back and latency
  acceptance on kind. Matcher tests alone do not satisfy this gate.

The final peer source still uses an in-memory cluster state and local intent
matching. Its webhook does not call the core DecisionService. Peer completion
checkboxes therefore do not prove the integrated exit requirements. No runtime
substitute or trust bypass is authorized to conceal those gaps.

## Validation

The pure domain suite and Linux race tests for domain/graph pass. The real kind
authorizer comparison passes independently of the peer adapter. Phase 6 is not
signed off and no claim of 100% integrated success is made.
