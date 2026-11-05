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
