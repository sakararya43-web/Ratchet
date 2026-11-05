# Native RBAC workflow and one-use admission

Native changes use `ChangeService.SubmitChange.kubernetes`, containing the strict
normalized mutation JSON defined by `internal/domain/kubernetes`. The server
encrypts the exact mutation and justification. Immutable history retains their
digests, opaque object/source keys and anonymous before/after graph projections.
Resource owners receive raw context only through current detailed-review access.
Anonymous assessment replay and chain verification survive private-record deletion.

The Authority-signed policy data `kubernetes_identity_bindings` maps opaque
`graph.KubernetesNodeID(cluster,"identity",principal.ID)` keys to existing core
human IDs. Every native human must have an explicit mapping; an empty value
attests that there is no core identity. Missing mappings hold assessment. Core
humans control their mapped technical identities, so native beneficiaries cannot
self-approve; Kubernetes user impersonation does not imply control of a human's
passkey. The map is signed policy data, never supplied by the admission caller.

Normal assessment, independent passkey approval and execution guard apply. A
connector must sign `native_rbac:true` in its `RATCHET_EXEC_CAPABILITY_V1`
capability. An old capability cannot enable native execution. Staged commands
contain only commitments and opaque preconditions, and use the existing execution
attempt/outbox path. They correlate a real API admission; they do not provide a
separate raw-object write API.

`/api/ratchet.v1.DecisionService/DecideKubernetes` is a TLS-only connector route.
`signed_admission_json` is authenticated with a tenant/connector/cluster-pinned
Ed25519 key. Console configuration accepts `kubernetes_connectors` entries with
`connector_id`, `cluster_id` and `public_key_hex` under each tenant. Browser
session/CSRF rules remain on the existing simulator and console routes.

The core checks exact native actor UID/groups, source resourceVersion, target
preimage, mutation and raw object digests, current Authority context, graph floor,
approved request, independent approvals, staged command and deadline. Kubernetes
admission UID is independent of the core command ID. Dry-run never consumes a
permit. A durable unique command/admission claim permits one exact request across
concurrent calls and restart. Repeated calls return HOLD without a permit. The
response includes a signed `RATCHET_KUBERNETES_DECISION_V1` commitment binding the
context, command and admission UID, valid for at most five seconds. Policy ALLOW
alone does not authorize execution. Request errors, authentication failures,
policy refusals and unavailable dependencies remain distinct.

Native execution results extend the existing signed result with `kubernetes`.
Independent read-back must match the consumed admission/context, exact approved
security object and API-assigned UID/resourceVersion, or exact deleted UID.
Kubernetes resourceVersion is opaque and is never incremented arithmetically.
Acknowledgements stay EXECUTING with durable verify-only reconciliation probes.
Raw results are encrypted; retained facts contain hashes and non-personal status.

These are implemented core boundaries, tested with PostgreSQL, real signing and
passkey cryptography and an HTTPS Connect client. They do not claim that the final
peer calls the RPC, writes a live object or supplies independent cluster read-back.
Its unresolved acceptance failures remain in [the gate report](phase-6-peer-gates.md).
