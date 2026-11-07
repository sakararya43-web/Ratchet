# Reproducing the Phase 6 RBAC oracle

This suite compares core rule semantics to the **actual Kubernetes authorizer**.
It does not exercise the peer adapter, webhook, approval UI or execution path.

Use an isolated kind cluster named `ratchet-phase6`, with a private kubeconfig;
do not modify the user's global Kubernetes context. The tested local versions
were kind `v0.33.0` (official executable checksum verified) and Kubernetes
`v1.37.0` (`kindest/node:v1.37.0`). Docker must already be running.

```powershell
kind create cluster --name ratchet-phase6 --kubeconfig .local/phase6-tools/kubeconfig --wait 90s
$env:RATCHET_KIND_KUBECONFIG = (Resolve-Path .local/phase6-tools/kubeconfig).Path
go test -tags=kindintegration ./internal/domain/kubernetes -run TestKubernetesRulesAgainstActualKindAuthorizer -count=1 -v
```

The kubeconfig must be an explicit absolute path. Every invocation pins
`kind-ratchet-phase6`; credentials are neither committed nor printed. The test
creates uniquely named namespaces and roles and deletes only its own resources.
A witness permission waits for the real RBAC watch cache before assertions.

Validated on 2026-11-05: **17 queries across 9 live RBAC configurations**, all
passing. Cases include namespace isolation, subresources, named TokenRequest,
top-level create with resourceNames, namespaced bind on ClusterRoles, named
escalate, impersonation, non-resource prefixes and namespaced URL denial.
Assertions use SubjectAccessReview responses, not parsed `can-i` text.

Role/ClusterRole API parsing and webhook operation remain connector-owned.
Selected semantics follow the [Kubernetes RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
and [resource matching implementation](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/apis/rbac/v1/evaluation_helpers.go).
Actual-cluster comparison guards against relying solely on documentation.

## Actual admission, approval, outage and drift acceptance

The matcher is a separate oracle. Run the following larger acceptance on main
after real local PostgreSQL/JetStream are ready. It creates and cleans up its own
randomly named kind cluster; it does not change the oracle or global context.
The kind executable path must be absolute and verified before use.

```powershell
. ./scripts/core-env-load.ps1
$env:RATCHET_NATS_URL = 'nats://127.0.0.1:54222'
$env:RATCHET_KIND_BINARY = (Resolve-Path .local/phase6-tools/kind.exe).Path
$env:RATCHET_EVALUATION_DIR = Join-Path $PWD '.local/phase6-evaluation'
go test -p=1 -tags='integration,kindintegration' ./internal/workflow -run TestNativeActualKindAdmissionApprovalReadBackAndOutage -count=1 -v -timeout=20m
```

The real API server presents a dedicated trusted client certificate to the
webhook. The suite uses actual core approval verification, PostgreSQL, JetStream
command/result delivery, exact one-use admission and independent target reads.
Stopping the core HTTPS listener causes a real sensitive write to fail; the
logged connection refusal is intentional. Actual post-write signed cuts and
connector-authenticated drift observations prove approved correlation and an
out-of-band incident in get/list/paginated-stream read models. Only the test's
own webhook is removed for that last fault injection. The runtime has no bypass.

Passing run on 2026-11-06: 446.27 seconds, webhook 1,201.2869 ms and API write
1,547.2038 ms for the approved sample. These are single-sample timings, not p95.
The production core call deadline remains three seconds. The ten-minute suite
timeout used for that historical run includes real cluster creation, full graph assessment and drift analysis;
it does not extend admission's deadline. [Captured result](evidence/phase-6/actual-kind.json).

Phase 7 on Windows reproduced the approved write, independent read-back, outage
refusal and approved-drift correlation, then exhausted the old seven-minute test
context while ingesting the second complete source cut. The correctness test now
allows fifteen minutes after cluster creation (twenty minutes for the process),
without removing assertions or changing production deadlines. Its final result
and elapsed time belong in the Phase 7 record; the historical measurement above
does not establish performance for the new candidate.

Run this suite, the interface/storage suite in [the gate report](phase-6-peer-gates.md)
and the matcher sequentially. The complete real snapshot currently stores as a
509,422-byte immutable event and replays after private source deletion. A snapshot
or matcher pass by itself is not admission or end-to-end drift evidence.
