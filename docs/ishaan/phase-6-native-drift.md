# Native drift and incident evidence

The existing drift transport accepts the additive exclusive
`SignedKubernetesDriftReport.signed_kubernetes_drift_json` envelope. It contains
`workflow.SignedKubernetesDrift`, signed with the pinned native connector key
under `RATCHET_KUBERNETES_DRIFT_V1`. Mixed native/legacy envelopes are rejected.
Native parsing, API watch/audit collection and publication remain connector-owned.

The core verifies the signed report's tenant, connector, cluster and identifiers;
the complete baseline must match a normalized source digest in a verified prior
graph event. The observed revision must have reached core ingestion. Source lag
is a retryable dependency failure, later source cuts are labeled stale, and a
fabricated baseline is rejected without side effects.

Exact transitions compare the submitted mutation with its API-assigned observed
object/UID/resourceVersion, or deleted UID, and the current complete source cut.
Additional simultaneous changes prevent an exact transition proof and require
review. A proved transition receives whole-organization graph impact analysis and
a current signed-policy decision. Reported command IDs alone do not establish
approval: correlation requires the exact durably consumed admission UID, context,
mutation, baseline, requester lifecycle and application deadline. Correlation
never marks a target write independently verified.

Uncorrelated changes atomically open an ordinary incident with anonymous native
impact, source/graph commitments, policy/registry digests and replay facts.
Get/list/watch read models expose these through `native_drift_evidence_json`.
Raw native objects, identities and the signed report are encrypted separately.
Duplicate observations retain the original receipt/incident, including with a
new transport drift ID. Retained incident evidence and chain verification survive
private report deletion. Missing current graph nodes produce explicitly
incomplete route evidence, not a fabricated zero-residual result.

This selected native scope provides assessment, exact approved correlation and
investigation. It does not auto-revert an arbitrary Kubernetes object. A native
reverter, target CAS and watch recovery require connector adoption; an inverse
that could remove unrelated authority or weaken safeguards must not be guessed.
Reviewed native changes use the ordinary approval/guard/admission path. Native
automatic containment and live continuity are unresolved D6/D7 acceptance gates,
as recorded in [the scope matrix](phase-6-peer-gates.md).

PostgreSQL tests exercise committed baselines, real signing, policy/impact,
incident get/list/watch, deduplication, privacy deletion, source lag and exact
consumed-command correlation. Real-kind acceptance now also ingests actual signed
post-write API cuts and uses the adapter's `PublishDrift` method to authenticate
actual observations through the production core drift boundary. The approved
write correlates, and an actual out-of-band write opens an incident visible in
get/list and the complete paginated stream. This verifies core drift/incident
support with real RBAC facts. It does not implement or claim an automatic
connector watch/audit collector; that remains explicit native scope in the matrix.
