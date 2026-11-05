# Authenticated normalized Kubernetes source ingestion

`SignedGraphSync` now has an additive `kubernetes` payload containing tenant,
connector, numeric source revision and `normalized_state_json`. The last field
is the core's normalized `domain/kubernetes.State`, not raw Kubernetes API JSON.
Only the connector parses API objects and attests their mapping. No caller graph
edges are accepted alongside this payload.

The existing pinned-key sync authentication and real shared canonical signing
digest cover the new payload bytes and source envelope. Existing simulator
payloads and signature formats are unchanged. The new field is optional; an old
consumer that does not understand the selected payload cannot treat it as a
valid snapshot/delta.

The core strictly decodes the normalized model, requires complete observations,
compiles its own authority graph and commits source state, receipt, graph facts
and outbox atomically through the existing PostgreSQL ingestion transaction.
The outer numeric revision orders connector deliveries; Kubernetes collection
and object resourceVersions remain opaque strings. They are never interchangeable.

Complete actor/group/object facts are stored only inside the encrypted private
graph-source record. Retained public graph data contains anonymous authority and
an opaque source-key/state-digest mapping. That digest also binds source cuts,
UIDs and target revisions when the authority graph itself has not changed.
Reusing the same delivery revision with different preimage facts is a conflict.
Only one connector can own a native cluster in the merged organization graph.

This selected protocol requires complete native cuts. A generic graph-edge
delta against a native source durably quarantines it until a complete snapshot
repairs the source. It cannot leave a ready graph with stale RBAC preimages.

After private-record deletion, retained graph replay and ledger verification
continue to work. `Snapshot.KubernetesState` returns unavailable because hashes
and reachable powers cannot reconstruct exact actor/object context. Fresh native
decisions must hold until authenticated observations are available again.

`Snapshot.KubernetesProposal` computes both common-basis views within the entire
organization graph. It retains external controllers and unrelated business
grants, rejects mismatched native projections and refuses dangling external
references. Equality of projected authority is not itself a target-freshness
proof: callers must also check the retained source cut and exact preimage.

Real PostgreSQL/JetStream tests cover signed delivery, duplicate receipts,
database/cache reload, immutable private/public snapshots, same-revision preimage
conflicts, privacy deletion, replay, tenant/connector metadata, malformed/partial
facts, conflicting native source ownership and full-cut resync recovery.

Remaining Phase 6 work includes native policy/approval/DecisionService adoption,
staged command consumption, observed native execution and drift/incident wiring.
The peer's final adapter does not emit this normalized protocol; its actual
conformance failures remain open. This ingestion path does not replace it.
