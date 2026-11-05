# Core native admission evidence contract

This is an implemented core validation/authentication boundary and a proposed
connector handoff, not a frozen joint contract or an enabled execution route.
DecisionService adoption, staged native commands and independent native read-back
remain open in [the progress record](phase-6-progress.md).

`kubernetes.Admission` binds tenant, Kubernetes-assigned admission UID, full
userInfo, GVK/GVR, object name/namespace, dry-run status, source resourceVersion,
graph floor, core approved request/command IDs and exact normalized mutation.
Mutation binds before/after, opaque object UID/resourceVersion and both raw
object digests. Kubernetes admission UID and core command ID are independent.
CREATE has no assigned target UID/resourceVersion; UPDATE retains the exact
preimage UID/resourceVersion; DELETE requires the observed preimage. RoleRef is
immutable. Only RBAC v1 Role/ClusterRole/RoleBinding/ClusterRoleBinding is selected.

`bus.SignedKubernetesAdmission` authenticates that entire structure with
Ed25519 and the real shared canonical digester, signature domain
`RATCHET_KUBERNETES_ADMISSION_V1`. Tenant/connector/cluster/public-key pins come
from trusted configuration, never from the message. Lifetime is at most 30
seconds with strict issued/expiry checks. A verified result is detached from
the input's maps, slices and object pointers.

`Admission.PrincipalIn` checks a complete retained normalized source observation:
the source cut, canonical service-account username, observed user/account UID,
exact group set and exact current target preimage must agree. Group order is
irrelevant for membership comparison but the complete signed context remains
bound. Recreated service accounts cannot reuse an old UID. Unmodeled userInfo
extras, anonymous identities, subresources and other API versions stay unsupported.

Authentication and context matching **do not authorize an execution**. The
eventual DecisionService path must also recheck current policy, graph/registry
floors, independent current passkeys/quorum, approved object/context, deadline,
target revision and the durable one-use command claim. A dry-run must not consume
or create an actual-write permit. Retrying an already consumed admission must
reconcile the original command rather than return a second grant. An ACK is not
independent target observation or verified execution.

Native object parsing, verifying Kubernetes webhook callers, attesting that raw
digests correspond to normalized facts, admission TLS/configuration, target CAS,
the actual write and target watch remain connector-owned. A signed caller claim
does not replace any of those responsibilities.

The core unit suites cover signature tampering across all context dimensions,
wrong pins, expiry, deep-copy isolation, stale source/object revisions, groups,
identity UID, same-name/different-namespace targets and unsupported input.
Existing simulator wire/signature formats are unchanged.
