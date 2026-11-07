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

The final peer-branch webhook has no DecisionService call or verified signed command
consumption. Its executable exposes local intent registration. A kind deployment
of that implementation cannot prove the planned approved-object correlation or
core-outage behavior. The user subsequently authorized connector fixes on main;
those changes do not modify the peer branch or claim its acceptance retrospectively.

## Authorized corrections verified on main (2026-11-06)

All six historical interface/live-inventory assertions now pass. The main adapter
uses actual API discovery/inventory, signed complete cuts and strict exact native
admission. The local intent route is forbidden. A separate actual API-server
acceptance proves mutual TLS, independent cryptographic approval, guarded durable
command delivery, exactly one consumed permit, actual write/read-back/EXECUTED
state and refusal/absence during a real core outage. Actual approved and
out-of-band RBAC changes also produce the required drift correlation and incident
get/list/paginated-stream evidence. [Results and metrics](phase-6-progress.md).

Reproduce corrected interface/inventory/storage acceptance on main sequentially:

```powershell
. ./scripts/core-env-load.ps1
$env:RATCHET_NATS_URL = 'nats://127.0.0.1:54222'
$env:RATCHET_KIND_KUBECONFIG = (Resolve-Path .local/phase6-tools/kubeconfig).Path
go test -p=1 -tags='integration,peerintegration,kindintegration' internal/connector/conformance/kubernetes_peer_test.go internal/connector/conformance/kubernetes_kind_peer_test.go internal/connector/conformance/kubernetes_storage_kind_test.go -run 'TestPeerKubernetes|TestActualKind' -v -count=1 -timeout=4m
```

The complete unchanged peer simulator is not merged. Its full conformance tests
still require the actual combined source; main does not substitute a fake server.

## D1–D8 scope

| Scenario | Core semantics available | Remaining native acceptance |
|---|---|---|
| D1 ordinary access | Normalized role/binding matching; actual native submission, independent cryptographic approval, API write and exact independent read-back pass | Browser/UI demonstration and broader native scenario coverage |
| D2 sensitive access | Wildcards, token creation, bind/escalate/impersonation closure, signed policy/DecisionService one-use native enforcement; actual unapproved and core-outage API writes refused | Full sensitive native scenario portfolio, beyond the selected live acceptance |
| D3 impact | Actual signed full API source, namespaced/aggregated roles, external controllers, other beneficiaries and common-basis graph impact; actual drift evidence | Peer UI demonstration and broader target comparisons |
| D4 independent review | Signed-policy core/native identity association, mapped-beneficiary independence, real approval cryptography, native admission and independent cluster observation | Actual browser passkey ceremony remains joint integration, not replaced by cryptographic protocol tests |
| D5 critical rule | RBAC changes are modeled; simulator withdrawal safeguards are not Kubernetes RBAC rules | Admission configuration, webhook removal, external authorizers and financial safeguards are unsupported native mappings |
| D6 containment | Actual signed API cuts/observations, committed transition verification, durable impact/policy/incident evidence, get/list/stream and exact approved correlation pass | Automatic watch/audit collector, native reverter, proven inverse, verified correction and residual containment; automatic native rollback is unsupported |
| D7 continuity | Namespace separation and reduced-authority comparisons | Live application continuity during actual native containment |
| D8 audit | Actual connector publication/read-back/drift events, encrypted raw context, full-cut exact replay and retained incident evidence after erasure | Native offline peer verifier/UI demonstration remains joint acceptance |

This is selected RBAC scope. It does not claim coverage of every Kubernetes
authorizer, external identity provider, constrained impersonation extension,
credential mechanism, admission-policy mutation or workload escape. Unsupported
and unavailable context must stay held; no fake full Kubernetes parity is claimed.
