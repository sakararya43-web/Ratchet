# Final peer acceptance evidence for Phase 6

Peer source: `origin/sakar d823a106bb4a64b0fe54e366c41029ccbd8dfda8`.
The user confirmed this is final. No newer peer delivery is assumed. The peer's
plan checkboxes are marked complete, but integrated acceptance is not established.

On 2026-11-05 the unmodified peer code was archived into an ignored combined
checkout with current core files, and the following real assertions failed:

| Acceptance assertion | Actual result |
|---|---|
| Observe a uniquely named ClusterRole just created in real kind | Snapshot omits the live role; adapter returns its in-memory baseline |
| Reject a custom sensitive RoleBinding without core evaluation | Allowed; only special role names are recognized |
| Refuse a local intent for another tenant/actor/object context | Allowed based on operation and metadata.name |
| Hold a deletion without exact old-object/context evidence | Allowed unconditionally |
| Emit the required authenticated complete snapshot | Complete marker is missing |

The unapproved `cluster-admin` RoleBinding check passes. It does not compensate
for these failures. The tests assert the required successful behavior directly;
they do not invert failures into passing expected-failure tests.

Reproduce in an isolated combined checkout, never by merging or modifying the
peer branch:

```powershell
$env:RATCHET_KIND_KUBECONFIG = (Resolve-Path .local/phase6-tools/kubeconfig).Path
go -C .local/phase6-combined test -tags='peerintegration,kindintegration' ./internal/connector/conformance -run 'TestPeerKubernetes' -v -count=1
```

`kubernetes_peer_test.go` needs the actual peer source (`peerintegration`);
`kubernetes_kind_peer_test.go` additionally needs the explicit private kind
kubeconfig (`kindintegration`). Ordinary core checks do not synthesize a missing
peer package or silently claim these assertions passed.

The final webhook has no DecisionService call or verified signed command
consumption. Its executable exposes local intent registration. A kind deployment
of that implementation cannot prove the planned approved-object correlation or
core-outage behavior. Fixes belong to the connector owner; core work does not
replace the adapter, API parsing, webhook or target watch.

## D1–D8 scope

| Scenario | Core semantics available | Remaining native acceptance |
|---|---|---|
| D1 ordinary access | Normalized role/binding matching and exact mutation validation | Real request, approval, target write and independent read-back |
| D2 sensitive access | Wildcards, token creation, bind/escalate/impersonation closure | Policy/DecisionService integration and actual webhook decision |
| D3 impact | Namespaced/aggregated roles, other beneficiaries and common-basis graph impact | Native ingestion, UI and target comparison |
| D4 independent review | Existing core reviewer controls; technical token takeover and separate human impersonation semantics | Trusted core/native identity association and native approval/execution tests |
| D5 critical rule | RBAC changes are modeled; simulator withdrawal safeguards are not Kubernetes RBAC rules | Admission configuration, webhook removal, external authorizers and financial safeguards are unsupported native mappings |
| D6 containment | Pure reduction/expansion analysis | Native drift publisher, durable decision/incident and verified correction |
| D7 continuity | Namespace separation and reduced-authority comparisons | Live application continuity during actual native containment |
| D8 audit | Existing core append-only decisions and signed-boundary primitives | Native decision/observation events and actual peer offline verification |

This is selected RBAC scope. It does not claim coverage of every Kubernetes
authorizer, external identity provider, constrained impersonation extension,
credential mechanism, admission-policy mutation or workload escape. Unsupported
and unavailable context must stay held; no fake full Kubernetes parity is claimed.
