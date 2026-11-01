# RATCHET — System Architecture & Technology Decisions

**Companion to:** `RATCHET_Full_Idea_Document.md`
**Constraint set:** zero budget (only free / open-source software and free hosting), must scale without a redesign, the backend must stay simple enough for a small team to build.

---

## 0. Decisions at a glance

| Concern | Decision | One-line reason |
|---|---|---|
| Backend language | **Go** | The language that Vault, OPA, Teleport, SpiceDB, NATS and Kubernetes are written in. It gives fast in-memory graph work, single static binaries for connectors, and a small memory footprint on free hosting. |
| Frontend language | **TypeScript** (React + Vite SPA) | Needed for the browser anyway. Types are shared with the backend through Protobuf. |
| API contract | **Protobuf + ConnectRPC** (`buf`) | One schema produces typed Go and TS clients. Works from the browser over plain HTTP and as gRPC between services. Breaking changes are caught in CI. |
| System of record | **Event-sourced, append-only log in PostgreSQL**, with CQRS read models | Explained in §3. Postgres is the storage engine here, not the architecture. |
| Event backbone | **NATS JetStream**, fed by a transactional outbox | A single ~20 MB binary that provides streams, KV and fan-out. Its leaf nodes let connectors run inside customer networks with outbound-only connections. |
| Authorization graph | **Custom in-memory graph engine in Go** (CSR + copy-on-write overlay) | Blast radius, impact diffs and min-cut containment run in milliseconds. The graph is a projection of the log, so we don't need a graph database. |
| Policy engine | **OPA / Rego, embedded as a Go library**, with signed policy bundles | Deterministic, testable, CNCF-graduated. It returns structured decisions (ALLOW / REQUIRE_APPROVAL{quorum} / HOLD / REJECT + reasons). |
| Durable workflows & timers | **River** (Go job queue on Postgres) + explicit state machine | Jobs are enqueued in the same transaction as the state change. Scheduled jobs handle approval timeouts and auto-expiring emergency access. |
| Approvals | **WebAuthn passkeys that sign the digest of the change** | A stolen session cookie cannot approve anything. Every approval is a verifiable cryptographic signature. |
| Independent authority | **Separate service, separate database, separate admins.** Policies require **M-of-N passkey signatures** | Implements §8.1 and §22.2 of the concept doc in code, not just in process. |
| Audit | **Hash-chained ledger + periodic signed checkpoints** anchored to an external witness | Tamper-evident even against a database administrator. |
| Scale-out model | **Stateless API tier → partitioned graph replicas → cell-based architecture** | Each cell is a full independent stack for a set of tenants, so RATCHET limits its own blast radius. |
| Hosting (free) | **Oracle Cloud Always Free ARM VM** (4 cores / 24 GB) running everything, the web console **embedded in the Go binary** (same origin), HTTPS via Cloudflare Tunnel or Caddy, `docker compose` | Everything runs on one free VM today. One origin keeps cookies and passkeys simple and works in customer VPCs and on-prem. The same containers move to k3s or Kubernetes later. |

**Footprint:** 4 Go binaries + 1 static web app + 2 infrastructure processes (Postgres, NATS). `docker compose up` starts all of it.

---

## 1. What RATCHET really is, technically

Stripped of business language, RATCHET is five systems:

1. **An authorization-graph analyser.** It models who can reach and control what, including indirect control (if X can reset Y's password, X can become Y). It answers *"what new power does this change create?"* by diffing the graph before and after the change. This is the core of §8.3 and §13.4.
2. **A policy decision point (PDP)** for change requests. It decides Allow / Require independent approval / Hold / Reject (§14).
3. **A durable approval workflow engine** with separation of duties, quorum, timeouts, and time-bound emergency grants (§12, §15).
4. **An enforcement and containment layer.** It executes approved changes, blocks unapproved ones, reverts drift, and revokes access fast (§8.4, §9).
5. **A tamper-evident ledger** of every decision (§13.7, §15.4).

Wrapped around these is a **separately governed trust root** (the "Independent Security Authority"), which the rest of the system cannot override.

### 1.1 Invariants the architecture must guarantee

Design choices below are justified against these invariants. They are also tested as properties (§13).

| # | Invariant | Where enforced |
|---|---|---|
| I1 | A principal can never be the deciding approver of a change that expands its own reach, **or the reach of anyone it can control**. | Approval service + graph "control set" check (§5.4) |
| I2 | Whether a change is a "reduction" is **computed from the graph diff**, never trusted from the request's label. Removing a deny-rule or a safeguard is an escalation. | Graph engine monotonicity check (§5.1) |
| I3 | An approval is bound to the exact change **and the graph version it was assessed against**. If the world changed before execution, the change is re-assessed. This prevents TOCTOU. | Execution guard (§5.3) |
| I4 | Policies and approver sets change only with M-of-N signatures from the Authority's quorum. | Authority service (§5.5) |
| I5 | Every state transition is an append-only event in a hash chain. Nothing is updated in place. | Event store + ledger (§5.8) |
| I6 | When RATCHET is unavailable, escalations **fail closed**. Reductions stay possible through a sealed break-glass path. | Enforcement modes (§5.6) |
| I7 | Decisions are deterministic. The same inputs and the same policy version always give the same output, so a past decision can be replayed. | Pure domain core + OPA + versioned inputs |

### 1.2 Where "scale" actually bites

This shapes everything. Privilege-change **requests are low-volume**: even a large bank produces thousands per day, not thousands per second. Scale pressure comes from three other places:

- **Graph size.** Large enterprises have 10⁵–10⁶ identities and 10⁶–10⁷ permission edges.
- **Ingestion volume.** Connector syncs and drift-detection audit streams (cloud audit logs, IdP system logs) can be millions of events per day.
- **Availability.** If RATCHET gates escalations, its downtime blocks the business.

So the design puts its effort into the graph engine, the ingestion pipeline, and HA of the decision path. It does not spend effort on request QPS.

---

## 2. Language decision: Go vs Python vs TypeScript

### 2.1 Scored against what RATCHET needs

| Requirement | Go | Python | TypeScript (Node) |
|---|---|---|---|
| CPU-bound graph traversal (BFS, path finding, max-flow over 10⁶–10⁷ edges) | ✅ Compiled, cache-friendly slices, real parallelism across cores | ❌ GIL. `networkx` is 10–100× slower; you'd end up writing C extensions | ⚠️ A single-threaded event loop blocks during traversals; you'd need worker threads and serialization |
| Security-ecosystem fit (OPA, NATS, WebAuthn, Kubernetes client, cloud and IdP SDKs) | ✅ OPA embeds natively; first-class K8s/AWS/GCP/Azure/Okta SDKs | ⚠️ OPA only via HTTP sidecar | ⚠️ OPA only via WASM or sidecar |
| Shipping connectors into customer networks | ✅ One static binary, any OS/arch (`GOARCH=arm64`), no runtime | ❌ Interpreter + venv + native wheels | ❌ Node runtime + `node_modules` |
| Supply-chain risk (critical for a *security* product) | ✅ Small stdlib-heavy dependency trees, checksum DB, `govulncheck` | ⚠️ Medium | ❌ npm has the largest transitive-dependency attack surface |
| Memory on free-tier VMs | ✅ ~20–60 MB per service | ⚠️ ~100–300 MB | ⚠️ ~80–200 MB |
| Correctness tooling | ✅ Static types, explicit errors, race detector, native fuzzing, property testing | ⚠️ Optional types (mypy), runtime surprises | ✅ Good types, but erased at runtime |
| Developer velocity | ✅ Small language, fast compiles, learnable in weeks | ✅ Fastest to prototype | ✅ Fast, same language as the UI |
| Concurrency (connectors, streams, timers) | ✅ Goroutines and channels are the native model | ⚠️ asyncio complexity | ✅ Good for I/O, poor for CPU |

### 2.2 Verdict

**Go for every backend component. TypeScript for the web console only. Python nowhere in the core.**

Python's strengths are ML and data science, and the concept doc says RATCHET is not an AI product. It may still be useful later for offline analysis scripts or notebooks.

A note on "accuracy": no language makes decisions accurate on its own. In RATCHET, accuracy comes from three things:

- **Precise graph semantics:** what "can reach" and "can control" mean (§5.1).
- **A deterministic policy engine:** OPA.
- **Property-based tests of the invariants** (§13).

Go helps because it has static types, no implicit coercions, explicit error paths, and a pure, I/O-free domain core that is easy to test exhaustively.

Rust was considered and rejected. It offers no meaningful correctness gain over Go for this workload, it is much slower to build in, and its ecosystem fit is weaker (OPA and NATS are Go-native).

---

## 3. About PostgreSQL

The brief asked for "not a mid-level architecture with SQLite/PostgreSQL". I've kept Postgres on purpose, and the reason matters.

A design is mid-level when it **treats the database as a mutable CRUD bucket**: `UPDATE requests SET status='approved'`, business logic in controllers, history lost on every write. Which storage engine sits underneath doesn't change that. Here, Postgres plays four specific roles, and each is a deliberate system-design pattern:

1. **An append-only event store.** It is the single source of truth for every state transition (event sourcing). The app's database role is denied `UPDATE` and `DELETE` on the event and ledger tables.
2. **A transactional outbox.** It feeds NATS JetStream with exactly-once effect, so there are no dual-write bugs.
3. **A transactional job queue (River).** Approval timeouts and auto-expiry of emergency access commit atomically with the state change that schedules them.
4. **CQRS read models.** Denormalised tables for the UI, rebuilt from the event log at any time.

The alternatives are all worse for this system:

- **Kafka + a separate DB** adds a JVM cluster and solves a throughput problem RATCHET doesn't have (§1.2).
- **MongoDB** has weaker transactional ordering guarantees for an event store.
- **Neo4j as the primary store** puts a network hop and a GPL/commercial license on the hottest path, for a graph that fits in RAM anyway (§5.1).
- **CockroachDB or YugabyteDB** (Postgres-compatible distributed SQL) are possible, but they buy multi-region writes at the cost of `LISTEN/NOTIFY`, some locking semantics and simplicity.

RATCHET scales by **cells** (§8), not by distributing one database. All persistence sits behind Go interfaces (ports), so a later move to distributed SQL is an adapter change, not a rewrite.

The sophistication is in the architecture around Postgres. Stores that look more impressive would add cost and fragility without adding capability.

---

## 4. Architecture overview

### 4.1 Trust domains

The concept doc's most important requirement is **independence** (§7.1, §8.1, §22.2). So the architecture is first split into trust domains, and only then into services.

```
┌────────────────────────── TRUST DOMAIN A: RATCHET AUTHORITY (root of trust) ──────────────────────────┐
│  ratchet-authority (Go)            authority-db (separate Postgres DB, separate credentials)           │
│  • signed policy bundles (M-of-N passkey signatures)   • approver registry & quorum definitions        │
│  • ledger checkpoint signing                           • genesis / recovery procedure                  │
│  Admins: security leadership only, passkey-only login, no shared credentials with Domain B             │
└───────────────▲───────────────────────────────────────────────────────────────────────▲───────────────┘
                │ pulls signed bundles (read-only, verifies signatures locally)         │ checkpoint hashes
┌───────────────┴────────────────── TRUST DOMAIN B: RATCHET CONTROL PLANE ──────────────┴───────────────┐
│                                                                                                        │
│   Web console (React SPA, embedded) ──ConnectRPC/HTTPS──► ratchetd  (one Go binary, roles via flags)  │
│                                                         ┌──────────────────────────────────────────┐   │
│                                                         │ api        : ConnectRPC, authn, PDP      │   │
│                                                         │ graph      : in-memory graph replicas    │   │
│                                                         │ workflow   : state machine + River jobs  │   │
│                                                         │ projector  : read models, notifications  │   │
│                                                         │ relay      : outbox → JetStream          │   │
│                                                         └──────────────────────────────────────────┘   │
│                    PostgreSQL (events, outbox, jobs, read models)      NATS JetStream (streams, KV)    │
└─────────────────────────────────────────────────────────▲──────────────────────────────────────────────┘
                                                          │ outbound-only (NATS leaf node / gRPC), mTLS
┌──────────────────────────────── TRUST DOMAIN C: CUSTOMER ENVIRONMENT ─────┴────────────────────────────┐
│  ratchet-connector (Go static binary)                                                                  │
│  • syncs identities/roles/permissions → graph     • inline decision hooks (admission webhooks etc.)    │
│  • executes approved changes with RATCHET-held credentials   • watches audit logs, reverts drift       │
│  Targets: ratchet-sim (simulated crypto exchange) · Kubernetes RBAC · later: IdPs, cloud IAM, GitHub   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Why this split:**

- A compromised production admin in Domain C cannot change policy, because policy lives in Domain A and is verified by signature.
- A compromised RATCHET operator in Domain B also cannot change policy. Domain B holds no signing keys; it only *verifies*.
- Compromising Domain A's server alone isn't enough either. Bundles need M-of-N signatures from humans' hardware-backed passkeys, and the server never holds those private keys.

### 4.2 Modular monolith, not microservices

`ratchetd` is **one binary with hard internal module boundaries**. Each module talks to the others only through interfaces and events. The process's roles are chosen at startup:

```
ratchetd --roles=api,graph,workflow,projector,relay   # free tier: everything in one process
ratchetd --roles=api,graph                            # at scale: N stateless replicas behind a load balancer
ratchetd --roles=workflow                             # at scale: separately scaled workers
```

This keeps v1 as easy to run as a single app, while the scale path needs **zero code changes**. It also avoids the "distributed monolith" failure mode, where a small team splits code into 12 services on day one and spends its time on network glue.

The **Authority**, **Connector** and **Simulator** are separate binaries because they must be: they belong to different trust domains.

---

## 5. Components in depth

### 5.1 Authorization Graph Engine (the heart of RATCHET)

**Model.** A typed, directed multigraph.

| Node types | Edge types (selected) | Escalation semantics |
|---|---|---|
| `Human`, `ServiceAccount`, `Group`, `Role`, `Permission`, `Resource` (with criticality tier 0–3), `Safeguard` (security controls are first-class nodes, per §3.2), `Session`, `Credential` | `MEMBER_OF`, `ASSIGNED`, `GRANTS(action)`, `CAN_ASSUME`, `CAN_ADMINISTER(identity)`, `CAN_MODIFY(role\|policy\|safeguard)`, `CAN_APPROVE(workflow)`, `PROTECTED_BY` | `CAN_ADMINISTER(Y)` means **takeover**: X inherits Y's entire reach. `CAN_MODIFY(Role R)` means X can grant R to itself, so X reaches R's grants. `CAN_MODIFY(Safeguard S)` means every resource `PROTECTED_BY` S is weakened. |

These semantics are how RATCHET judges **consequences, not labels** (§3.3, §7.3). A "minor" `CAN_MODIFY` on an obscure role can open a path to the wallet-signing service, and the traversal will find it.

**Core queries.**

| Query | Algorithm | Used by |
|---|---|---|
| `Reach(identity)`: everything an identity can access or control | BFS with escalation-edge expansion (takeover edges re-enter BFS from the taken-over identity) | Blast radius, Infrastructure Map |
| `ImpactDiff(change)`: `Reach_after − Reach_before` for every affected identity | Run Reach on the base graph and on base + proposed overlay, then set-difference | Change Review, Impact Simulator |
| `PathsTo(identity, tier0)`: concrete routes to crown jewels | BFS with parent pointers, k-shortest paths for display | "Does this create a route to a critical resource?" |
| `ControlSet(identity)`: identities it can take over | BFS over takeover edges only | Independence check (I1) |
| `IsMonotonicReduction(change)` | Check `Reach_after ⊆ Reach_before` for all identities **and** no safeguard weakened | Asymmetric fast path (I2) |
| `MinimalContainmentCut(identity)` | Min s-t cut (Dinic's max-flow). Source = compromised identity, sink = super-node over tier-0 resources, edge capacity = business-disruption cost, non-removable edges = ∞ | Surgical containment (§7.6, §5.7) |

The last query turns "minimum disruption" from a slogan into an algorithm. Instead of disabling Rahul's account, RATCHET can say: *"Removing these 2 grants severs every route from this identity to tier-0 assets. 14 of Rahul's other activities are unaffected."*

**Data structure.**

- **Base snapshot:** immutable Compressed Sparse Row (CSR) arrays, forward and reverse, with dense `uint32` node IDs. That is roughly 25–50 bytes per edge including indexes, so 10 M edges ≈ 0.25–0.5 GB, and BFS over 10⁶ edges runs in single-digit milliseconds.
- **Delta overlay:** a small mutable add/remove set on top of the snapshot. Proposed changes are evaluated as a *temporary* overlay that never touches shared state, so simulation is free and safe to run concurrently.
- **Compaction:** when the delta grows past a threshold, a background goroutine builds a new base snapshot, and readers switch over through an `atomic.Pointer` swap. Readers never take a lock.
- **Versioning:** graph version = the sequence number of the last applied event. Every answer carries the version it was computed at (needed for I3).

**Why no graph database?** The graph is a **projection** of the event log, rebuilt or snapshotted on demand. An in-process traversal avoids the network round-trips, query-language overhead and licensing of Neo4j or Memgraph. It also lets us implement escalation semantics and max-flow exactly as specified, rather than approximating them in Cypher.

**Replication.** Every `graph`-role replica tails the tenant's graph event stream on JetStream and applies the deltas. Cold start loads the latest snapshot from storage and then replays the tail. For read-your-writes, a caller can pass `min_version`; the replica waits, with a bound, until it has caught up.

### 5.2 Policy Decision Engine

**OPA (Rego v1), embedded via the Go SDK**, using prepared queries for roughly 1 ms evaluations.

The policy input is a **fact sheet**, not a score. The concept doc rejects "threat scores" (§5, §13.1), and opaque scores can't be explained to a reviewer or an auditor:

```json
{
  "request":   { "kind": "ROLE_ASSIGN", "target": "user:rahul", "role": "role:exchange-admin",
                 "justification": "...", "requested_by": "user:rahul", "emergency": false },
  "requester": { "id": "user:rahul", "type": "Human", "department": "finance",
                 "session": { "mfa_age_s": 4200, "new_device": true } },
  "impact":    { "monotonic_reduction": false,
                 "new_resources": [{ "id": "svc:wallet-signer", "tier": 0 }],
                 "new_tier0_paths": 3, "new_controlled_identities": 41,
                 "safeguards_weakened": [], "blast_radius_delta": { "tier0": 3, "tier1": 12 } },
  "graph_version": 18234
}
```

```rego
package ratchet.change
import rego.v1

decision := reject("would weaken a tier-0 safeguard; must go through the Authority") if {
    some s in input.impact.safeguards_weakened
    s.tier == 0
} else := allow("verified reduction of access") if {
    input.impact.monotonic_reduction
} else := require(2, ["security-leads"], "creates new route(s) to tier-0 assets") if {
    input.impact.new_tier0_paths > 0
} else := require(1, ["resource-owner"], "standard access request")

allow(r)          := {"outcome": "ALLOW", "reasons": [r]}
reject(r)         := {"outcome": "REJECT", "reasons": [r]}
require(n, gs, r) := {"outcome": "REQUIRE_APPROVAL", "quorum": n, "approver_groups": gs, "reasons": [r]}
```

- Policies live in Git, are unit-tested with `opa test`, and are **compiled into a bundle signed by the Authority quorum**. `ratchetd` refuses to load an unsigned or wrongly signed bundle, and it records the bundle hash in every decision event (needed for I7).
- RATCHET's *own* authorization (who may view, approve, or contain) is a separate Rego package in the same engine. One engine and one mental model.

### 5.3 Change lifecycle (state machine + durable jobs)

```
                ┌──────────┐ policy=ALLOW ─────────────────────────────┐
  SUBMITTED ──► │ ASSESSED │ policy=REJECT ──► REJECTED                │
                └────┬─────┘ policy=HOLD   ──► HELD ──(info added)──► re-ASSESSED
                     │ policy=REQUIRE_APPROVAL                         ▼
                     ▼                                             APPROVED ──► EXECUTING ──► EXECUTED
              AWAITING_APPROVAL ──(quorum met)──────────────────────►  ▲             │            │
                     │ (timeout job) ──► EXPIRED                       │       (verify fails)  (temporary grant)
                     │ (any approver rejects) ──► REJECTED             │             ▼            ▼
                     └─────────────────────────────────────────────────┘          FAILED     expiry job ──► REVOKED
```

- The domain core is a **pure Go function**: `(state, command) → (events, error)`. It does no I/O, which makes it fully deterministic and exhaustively testable.
- The command handler loads the request's events, applies the command, and appends the new events with **optimistic concurrency** (`expected_version`). It writes outbox rows and **enqueues River jobs in the same transaction**. Either all of it happens or none of it does.
- **Idempotency:** every command carries an idempotency key. Duplicate deliveries from connectors or retries are absorbed.
- **TOCTOU guard (I3):** before execution, the executor re-runs `ImpactDiff` at the current graph version. If the result differs from what the approvers signed (for example, someone added a group membership in between), the request returns to `ASSESSED` with a "context changed" reason.
- **Execution is verified:** after the connector applies the change, it reads back the target system's state. `EXECUTED` is recorded only when the observed state matches what was intended.

### 5.4 Approvals: a passkey signature bound to the exact change

The concept doc's central attack is a stolen session approving its own escalation (§10). Cookies and session tokens are exactly what attackers steal, so approval cannot rest on them.

1. The change request (plus the graph version and impact digest) is canonicalised with RFC 8785 JSON Canonicalization and hashed with SHA-256, giving `change_digest`.
2. The approver's browser **recomputes the digest from the diff it is displaying** ("what you see is what you sign") and passes it to WebAuthn as the challenge.
3. The approver's passkey, held in their device's secure hardware, produces a signature. A stolen cookie can't produce one; only the physical approver can.
4. The server verifies the assertion and then checks **independence (I1)**:
   - approver ≠ requester;
   - approver ∉ `ControlSet(requester)`. If the requester can reset the approver's credentials, the approver isn't independent. This is computed from the graph;
   - approver belongs to a group allowed by the policy decision, and the quorum is distinct people.
5. The raw assertion (authenticator data, client data and signature) is stored in the event, so **any auditor can re-verify every approval offline**, years later.

Login can use the customer's SSO (OIDC). **Approvals and containment always need a RATCHET-enrolled passkey.** The customer's IdP is one of the things that might be compromised, so it can't be the only proof of identity.

Library: `go-webauthn/webauthn` (free, MIT).

### 5.5 Independent Security Authority

- **A separate binary, database, deployment and admin set.** It has no network path from Domain C, and Domain B can only *read* signed artifacts from it.
- **TUF-style root of trust.** At install (genesis), N security leaders enroll passkeys and a threshold M is set. After that, every policy bundle, approver-registry change and threshold change needs **M-of-N signatures over the bundle digest**. Changing the quorum itself requires the current quorum to sign.
- **Domain B holds no root signing keys.** It verifies signatures against the registry, so compromising the control plane doesn't let anyone rewrite the rules (§22.2).
- **Ledger checkpoints:** the Authority periodically signs the Merkle root of the control plane's audit ledger (§5.8).
- **Recovery:** a documented offline procedure using sealed recovery passkeys or keys (§22.2, "recovery arrangements").

### 5.6 Enforcement modes and connectors

The concept doc warns: *"If an important system can be changed without passing through RATCHET, an attacker may bypass it"* (§22.1). No single enforcement mode covers every system, so RATCHET supports three, strongest first:

| Mode | How it works | Strength | Example target |
|---|---|---|---|
| **Broker** (preventive) | Only RATCHET's connector holds credentials that can change IAM in the target. Humans and services request; RATCHET executes after a decision. | Strongest. No bypass unless someone holds the RATCHET credentials. | Simulated exchange, IdP admin APIs, cloud IAM |
| **Inline hook** (preventive) | The target asks RATCHET's PDP before applying a change (p99 budget < 50 ms). Escalations fail closed if RATCHET is unreachable (I6). | Strong; native to the platform. | **Kubernetes `ValidatingAdmissionWebhook`** on RBAC objects, IdP inline hooks, CI policy gates |
| **Detect & revert** (corrective) | The connector watches the target's audit stream. An escalation without a matching approved request is **automatically reverted**. Reverting is a reduction, so it is fast by §9. Every such event raises an incident. | Covers routes nobody gated; the exposure window is seconds. | Cloud audit logs, IdP system logs, GitHub org audit log |

The connector is one static Go binary with a plugin interface (`Sync`, `Execute`, `Verify`, `Watch`). It connects **outbound only** to the control plane (as a NATS leaf node or over gRPC with mTLS), so customers open no inbound firewall ports. That matters a lot to banks and exchanges.

**Real, free targets for v1:**

- `ratchet-sim`, the simulated crypto exchange (§19 of the concept doc).
- **Kubernetes RBAC on a local `kind` cluster.** Kubernetes has real privilege-escalation primitives (`bind`, `escalate`, `impersonate`, ServiceAccount token creation) and a real admission webhook. This shows RATCHET preventing escalation on real infrastructure at zero cost.

### 5.7 Containment: fast path and surgical cuts

- **Fast path (§9).** Containment commands such as revoke, disable, or end session are classified by `IsMonotonicReduction`. Reductions requested by an authorized responder (passkey-verified) skip the approval queue. They go to a **priority JetStream subject** that connectors consume ahead of normal work. The target is under 5 seconds from click to verified revocation.
- **Surgical plan (§7.6).** `MinimalContainmentCut` proposes the smallest-disruption set of revocations that separates the compromised identity from critical assets, and shows which business activities each cut affects. The responder can choose this plan or a full lockout.
- **Restoration (§12, Journey D).** Restoring access is an *increase*, so it goes through normal review, with the incident linked as context.
- **Break-glass (I6).** Sealed emergency credentials, released only by Authority quorum, guarantee reductions remain possible even if the control plane is down.

### 5.8 Tamper-evident audit ledger

- Every event row stores `hash = SHA-256(prev_hash ‖ canonical(event))`, one chain per tenant.
- The application's database role has `INSERT`-only rights on the ledger tables. Triggers reject `UPDATE` and `DELETE`, even for table owners other than an offline migration role.
- **Checkpoints:** every N minutes, the Merkle root of new entries is signed by the Authority. The signed root is published to an **external witness**: a free public transparency log such as Sigstore Rekor, OpenTimestamps, or a separate write-once bucket.
- To tamper with history undetected, an attacker would need the database, the Authority quorum, and the external witness at the same time.
- An `AuditService.Verify` endpoint (and a CLI) re-walks the chain and re-verifies every approval signature. This is what auditors use (§13.7, §15).
- **Privacy (§16):** personal data lives in a separate, encryptable column store referenced by ID, so retention can be enforced through **crypto-shredding** (delete the per-subject key) without breaking the hash chain.

### 5.9 Event backbone: outbox → NATS JetStream

```
command tx ──► events + outbox + jobs (one Postgres transaction)
                     │
              relay (polls outbox, publishes with Nats-Msg-Id = event_id → JetStream dedup)
                     ▼
JetStream streams (subjects are tenant-scoped):
  ratchet.<tenant>.graph.>      → graph replicas
  ratchet.<tenant>.changes.>    → projector (read models), notifier, UI live updates
  ratchet.<tenant>.contain.>    → connectors (priority consumer)
  ratchet.<tenant>.ingest.>     ← connectors (sync batches, audit-stream events, with backpressure)
NATS KV: rate limits, short-lived caches, leader election for singleton jobs
```

- **Exactly-once effect** comes from the outbox plus JetStream message-ID deduplication plus idempotent consumers. No distributed transactions are needed.
- **Tenant isolation at the bus:** each tenant is a separate NATS *account*, so tenants cannot even subscribe to each other's subjects.
- **No Redis.** NATS KV covers what Redis would have done here, so there is one less stateful system.

### 5.10 Web console

| Concern | Choice | Why |
|---|---|---|
| Framework | React 19 + Vite + TypeScript, **SPA** | A logged-in security console doesn't need SSR or Next.js. The static build is embedded into `ratchetd` with Go's `embed` and served from the same origin as the API. That means no CORS, normal secure cookies, passkeys bound to RATCHET's own domain, UI and API always shipped as one version, and no third-party host able to change the code approvers run. |
| Routing / data | TanStack Router + TanStack Query | Type-safe routes and server-state caching. |
| API client | `@connectrpc/connect-web`, generated from the same `.proto` files | End-to-end types; no hand-written fetch code. |
| UI kit | shadcn/ui + Tailwind | Serious, precise, operational look (§23). You own the components, with no vendor lock-in. |
| Graph views | **React Flow (`@xyflow/react`) + ELK layout** | Renders *curated* subgraphs (paths, neighbourhoods, before/after diffs) instead of the whole hairball, per §13.2: "not overwhelm users". |
| Live updates | Connect server-streaming (backed by JetStream) | The review queue and incident views update in real time. |
| Canonicalisation | `canonicalize` (RFC 8785) + WebCrypto SHA-256 | The browser computes the digest it asks the passkey to sign (§5.4). |

The screens map 1:1 to the concept doc's §13.1–13.7 sections. The Impact Simulator is the same `ImpactDiff` call with a draft change that is never submitted.

---

## 6. End-to-end flow: the "Rahul" scenario (§10)

```
Attacker (Rahul's stolen session)        ratchetd                          Graph       OPA      Approvers      Connector→Exchange
  │ Submit: assign role exchange-admin ──►│ authn (OIDC session ok)          │           │           │                │
  │                                       │ ImpactDiff @v18234 ─────────────►│           │           │                │
  │                                       │◄── +svc:wallet-signer (tier0), 3 new tier0 paths, controls 41 identities  │
  │                                       │ evaluate(facts) ─────────────────────────────►│          │                │
  │                                       │◄── REQUIRE_APPROVAL quorum=2 [security-leads] │          │                │
  │                                       │ tx: events+outbox+timeout job                  │          │                │
  │◄── "Awaiting independent approval"    │ notify ───────────────────────────────────────────────────►│               │
  │ Attacker tries to approve own req ───►│ ✗ approver == requester (I1), and no passkey anyway                         │
  │ Attacker edits withdrawal policy ────►│ safeguard tier0 weakened → REJECT; incident opened                          │
  │                                       │                                  Security lead opens review, sees diff,      │
  │                                       │◄──────────────────────────────── rejects + starts containment (passkey)     │
  │                                       │ MinimalContainmentCut(rahul) ───►│ → revoke 2 grants, end 1 session         │
  │                                       │ priority publish ─────────────────────────────────────────────────────────►│ revoke + verify
  │                                       │◄──────────────────────────────────────────────────────── EXECUTED (verified, 2.1s)
  │ (finance-report access still works — unrelated activity preserved, §7.6)    ledger: every step hash-chained ✓     │
```

All eight "must demonstrate" items in §19 of the concept doc appear in this one scenario.

---

## 7. Data model

### 7.1 Event store (Postgres)

```sql
CREATE TABLE events (
  tenant_id      uuid        NOT NULL,
  global_seq     bigint      GENERATED ALWAYS AS IDENTITY,
  stream_id      text        NOT NULL,          -- e.g. 'change:01J...', 'graph', 'policy'
  stream_version int         NOT NULL,          -- optimistic concurrency
  type           text        NOT NULL,          -- 'ChangeRequested', 'ApprovalGranted', ...
  payload        jsonb       NOT NULL,
  metadata       jsonb       NOT NULL,          -- actor, idempotency key, policy bundle hash, graph version
  prev_hash      bytea       NOT NULL,
  hash           bytea       NOT NULL,
  recorded_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, global_seq),
  UNIQUE (tenant_id, stream_id, stream_version)
) PARTITION BY HASH (tenant_id);
-- + row-level security on tenant_id (defense in depth), INSERT-only grant for app role
```

### 7.2 Event catalogue (v1)

`ChangeRequested`, `ImpactAssessed`, `PolicyEvaluated`, `ChangeHeld`, `ApprovalGranted` (with WebAuthn assertion), `ApprovalDenied`, `ChangeRejected`, `ChangeExpired`, `ChangeExecutionStarted`, `ChangeExecuted`, `ChangeExecutionFailed`, `ContextChanged`, `TemporaryGrantExpired`, `ContainmentInitiated`, `AccessRevoked`, `SessionTerminated`, `DriftDetected`, `DriftReverted`, `IncidentOpened`, `IncidentClosed`, `GraphNodeUpserted`, `GraphEdgeAdded`, `GraphEdgeRemoved`, `SyncCompleted`, `PolicyBundleActivated`, `LedgerCheckpointSigned`.

### 7.3 Read models (rebuildable at any time)

`change_requests_view`, `approval_queue_view` (per approver group), `incidents_view`, `identity_summary_view`, `audit_search_view`. All are generated by the projector and disposable. The truth is the log.

Data access uses **`sqlc`** (type-safe Go generated from SQL; no ORM) and **`pgx/v5`**. Migrations use **`goose`**.

---

## 8. Scaling design: how it grows without breaking

| Stage | Load | Topology | What changes |
|---|---|---|---|
| **0: demo / free** | 1–5 tenants, ≤100k edges | One VM: `ratchetd --roles=all`, Postgres, NATS, Authority | Nothing to manage |
| **1: early customers** | ≤50 tenants, ≤2M edges each | 2–3 `api,graph` replicas behind an LB, 1–2 `workflow` workers, Postgres primary + replica, 3-node NATS cluster | Config only. Graph replicas are routed by **tenant consistent-hashing** so each replica holds only its tenants' graphs. |
| **2: growth** | Hundreds of tenants | **Cells**: N independent copies of the Stage-1 stack, each serving a subset of tenants. A tiny global **cell router** maps tenant → cell. | Add cells; never grow one cell without limit. Big regulated customers get a **dedicated cell in their own VPC or on-prem**, the same artifact. |
| **3: enterprise / global** | 10⁷+ edges per tenant, multi-region | Per-region cells; read-only graph replicas in other regions; Temporal replaces River if workflows get very complex; SPIFFE/SPIRE for workload identity | Adapters, not rewrites, because of the port/adapter boundaries |

**Why cells are the right scaling model for RATCHET specifically:**

- A failure, bad deploy or breach in one cell affects only that cell's tenants. RATCHET applies its own blast-radius principle to itself.
- Each cell stays small enough to reason about and test. Scale comes from repeating a proven unit, not from building an ever-bigger cluster.
- It matches how banks and exchanges buy software: dedicated, isolated and data-resident deployments.

**Hot-path latency budget (inline-hook decisions, p99 < 50 ms):** authn ~1 ms, graph `ImpactDiff` 2–20 ms (in memory), OPA ~1 ms, event append ~3–5 ms. Ingestion is decoupled through JetStream with backpressure, so a 1M-edge sync never slows down decisions.

---

## 9. Failure modes and behaviour

| Failure | Behaviour |
|---|---|
| `ratchetd` replica dies | LB routes to others. Graph replicas are reconstructible (snapshot + tail). No state is lost because the state lives in the log. |
| Postgres primary down | Decisions that need to write fail closed (escalations blocked). Reads continue from replicas. Promote the replica. |
| NATS down | Commands still commit (the outbox buffers them). The relay catches up when NATS returns. Connectors buffer locally and replay with idempotency keys. |
| Connector offline | Approved changes queue durably. Drift detection resumes on reconnect and reconciles from the target's audit log since the last checkpoint. |
| Graph replica lagging | Decisions carry `graph_version`. A caller requiring `min_version` waits (bounded), then fails closed for escalations. |
| Policy bundle invalid or unsigned | Refused. The last valid bundle stays active and an Authority alert is raised. |
| Entire control plane down | Inline hooks fail closed for escalations. Reductions go through the break-glass path (I6). |
| Clock skew (timers, expiries) | Expiry jobs use database time (`now()`), not node clocks. Temporary grants are also stamped with an expiry in the target system where it supports one (belt and braces). |

---

## 10. Securing RATCHET itself

- **Separation of trust domains** (§4.1); no Authority keys in the control plane.
- **Passkey-only** for approvals, containment and Authority administration.
- **Least-privilege database roles:** a migration role (offline), an app role (no UPDATE or DELETE on the log), and a read-only role for projections.
- **Secrets:** SOPS + age for encrypted config in Git (free). Connector credentials use envelope encryption with per-tenant data keys.
- **Supply chain:**
  - Minimal Go dependencies; `govulncheck` in CI.
  - Distroless images; an SBOM via `syft`.
  - Images signed with `cosign` keyless signing via GitHub OIDC (free), and connectors verify the signature before self-update.
  - The npm surface is limited to the web console, with a lockfile and `npm audit` in CI.
- **mTLS** between connectors and the control plane, plus NATS nkeys/JWT per tenant account.
- **Rate limits and lockouts** on approval and containment endpoints (NATS KV counters).

---

## 11. Zero-cost deployment plan

| Piece | Free option | Notes |
|---|---|---|
| Backend VM | **Oracle Cloud Always Free**: Ampere A1, up to 4 cores / 24 GB RAM | Runs Postgres, NATS, `ratchetd`, Authority, Simulator, and a monitoring stack comfortably. Go cross-compiles to `arm64` with one env var. Oracle asks for a card to verify identity; Always Free resources are not billed. |
| Fallback with no card | Your own laptop + **Cloudflare Tunnel** (free) | Good enough for demos and judges. |
| Web console | **Embedded in `ratchetd`** | Served by the backend itself, at no extra cost. During development, run Vite's dev server and proxy `/api` to `ratchetd`. |
| HTTPS | **Cloudflare Tunnel** (demo, no domain needed) or **Caddy** + Let's Encrypt (with a domain) | Both free. The tunnel needs no open ports. |
| Kubernetes target for the connector demo | **kind** or **k3d** locally | A real cluster with real RBAC and an admission webhook, all on your machine. |
| CI/CD | **GitHub Actions** | Free for public repos (generous minutes for private ones). Lint, test, `buf breaking`, `opa test`, build, sign. |
| Observability | OpenTelemetry → self-hosted Prometheus + Grafana + Loki on the same VM, or **Grafana Cloud's free tier** | Traces across the decision path are invaluable for showing "<50 ms". |
| Audit witness | Sigstore Rekor / OpenTimestamps | Both are free public services, and only hashes are published. |
| Every library | OPA, NATS, Postgres, River, ConnectRPC, go-webauthn, React, shadcn/ui, React Flow | All open source (Apache-2.0 / MIT / BSD / MPL / PostgreSQL licenses). |

Free-tier terms change over time. Check the current limits before relying on one. The design depends on none of them: it is plain containers that run anywhere.

---

## 12. Repository layout (Go monorepo)

```
ratchet/
├── proto/ratchet/v1/              # change.proto, graph.proto, containment.proto, audit.proto, authority.proto
├── cmd/
│   ├── ratchetd/                  # control plane (roles via flags)
│   ├── ratchet-authority/         # independent authority
│   ├── ratchet-connector/         # customer-side agent
│   ├── ratchet-sim/               # simulated crypto exchange + attack scenarios
│   └── ratchetctl/                # CLI: audit verify, policy sign, genesis
├── internal/
│   ├── domain/                    # PURE: change state machine, decisions, invariants (no I/O)
│   ├── graph/                     # CSR, overlay, reach, diff, paths, control set, mincut
│   ├── policy/                    # OPA wrapper, bundle verification
│   ├── eventstore/                # append, load, optimistic concurrency, outbox
│   ├── workflow/                  # command handlers, River jobs (timeouts, expiries, execution)
│   ├── approval/                  # WebAuthn verification, independence checks, canonicalisation
│   ├── ledger/                    # hash chain, Merkle checkpoints, verify
│   ├── projection/                # read models
│   ├── bus/                       # JetStream relay, consumers
│   ├── connector/                 # plugin interface + sim + kubernetes adapters
│   └── api/                       # ConnectRPC handlers (thin)
├── policies/                      # *.rego + *_test.rego
├── web/                           # React console
├── deploy/compose/                # docker-compose.yml (whole system)
└── deploy/helm/                   # later
```

The dependency rule is enforced in CI (for example with `go-arch-lint`): `domain` imports nothing internal, `api` → `workflow` → `domain`, and adapters depend inward, never the reverse.

---

## 13. Testing strategy (where "accuracy" is earned)

| Layer | Technique | Example |
|---|---|---|
| Domain invariants | **Property-based tests** (`pgregory.net/rapid`) | Generate random orgs and random sequences of changes and approvals, then assert I1–I3 always hold. For example, "no sequence lets a principal approve an expansion of its own control set". |
| Graph engine | Property tests + reference implementation | Compare CSR+overlay results against a naive, obviously-correct implementation on random graphs. Check the max-flow cut on known topologies. |
| Policies | `opa test` with fixtures | Every rule has allow and deny cases. A policy coverage gate runs in CI. |
| Parsers and canonicalisation | Go native fuzzing | Change-payload decoding, JCS digest stability across Go and TS (golden vectors). |
| Integration | `testcontainers-go` (real Postgres + NATS) | Outbox exactly-once, River timers, crash-and-resume mid-execution. |
| Attack scenarios | Scripted e2e against `ratchet-sim` and `kind` | The Rahul scenario, compromised developer, rogue admin creation, service-account over-grant, safeguard weakening, lateral spread (concept doc §11). |
| False-positive measurement | Replay realistic *benign* change streams | Directly measures "legitimate requests incorrectly delayed" (§21), so the evaluation doesn't only test what the system was programmed to block. |
| UI | Playwright | Review → passkey approval (virtual authenticator) → execution → audit verification. |

---

## 14. Build roadmap, mapped to the concept doc's §19 "must demonstrate" list

| Phase | Deliverable | Proves §19 item(s) |
|---|---|---|
| **P0: skeleton** (≈1 wk) | Monorepo, protos, `buf`, compose (Postgres + NATS), CI, `ratchetd` with health checks, empty React console | — |
| **P1: graph + simulator** (≈2 wks) | `ratchet-sim` exchange with seeded org (finance, admins, wallet-signer, service accounts, withdrawal safeguards); connector sync; graph engine with Reach / ImpactDiff / PathsTo; Infrastructure Map and Impact Simulator screens | 3 |
| **P2: change lifecycle** (≈2 wks) | Event store, state machine, OPA policies, River jobs, Change Review screen, notifications | 1, 2 |
| **P3: approvals + authority** (≈2 wks) | WebAuthn passkeys, digest-bound approvals, independence check via ControlSet, `ratchet-authority` with M-of-N signed bundles, Security Policy screen | 4, 5 |
| **P4: containment + audit** (≈2 wks) | Monotonic-reduction fast path, min-cut containment plan, priority execution + verification, hash-chained ledger, checkpoints, Audit screen, `ratchetctl audit verify` | 6, 7, 8 |
| **P5: real infrastructure** (≈1–2 wks) | Kubernetes connector: RBAC sync + admission webhook + drift revert on `kind`. Attack-scenario suite and benign-replay metrics. | All, on real infrastructure |

Roughly 10–11 weeks for one or two developers working steadily. P1–P4 are enough for a compelling demo, and P5 is what separates "simulation" from "it actually stops real escalations".

---

## 15. Alternatives considered and rejected (for v1)

| Option | Why not now | When it becomes right |
|---|---|---|
| Python (FastAPI) backend | CPU-bound graph work, GIL, heavy deployable for connectors, OPA only via sidecar | Offline analytics or research notebooks |
| Node/TS backend | Event-loop blocking during traversals, npm supply-chain surface | Never for the core. TS stays in the UI. |
| Microservices per capability | Distributed-monolith risk, network glue, more to host for free | Roles already split by flag; split deployments when load demands it |
| Kafka | JVM/KRaft operations, overkill for the event rates in §1.2 | 100k+ events/s per cell, or many independent consumer teams |
| Neo4j / Memgraph | Network hop on the hot path, licensing, free-tier caps; Cypher approximates the escalation semantics poorly | An optional read-only analyst exploration tool, fed from the same events |
| Temporal | Excellent, but self-hosting is several services plus a database | Workflows get many branching long-running steps (Stage 3) |
| Kubernetes for RATCHET itself at v1 | Operational overhead on a single free VM | Stage 1+ (k3s → managed Kubernetes); compose files translate directly |
| Redis | NATS KV covers caching, counters and locks | — |
| Next.js | SSR is unnecessary for an authenticated console, and it needs a Node server runtime next to the Go backend | Public marketing site, if ever |
| SpiceDB / Zanzibar | Built for checking *your app's* permissions, not for analysing a *customer's* foreign IAM reachability | Possibly for RATCHET's own fine-grained authorization at large scale |
| Cedar (policy language) | Allow/deny only; RATCHET needs structured decisions (quorum, groups, reasons) | A formally verifiable subset of guardrail policies later |
| Blockchain for audit | Cost and complexity; a hash chain + signed checkpoints + a free external witness gives the same tamper-evidence | — |
| CockroachDB / YugabyteDB | Multi-region writes RATCHET doesn't need; loses `LISTEN/NOTIFY` and some locking semantics | Stage 3 multi-region, as an adapter swap |

---

## 16. Summary

RATCHET's hard problems are **graph semantics, cryptographic accountability, and independence of the trust root**. Raw throughput is not one of them.

The architecture answers each one directly:

- **Graph semantics:** an in-memory escalation-aware graph engine computes the before/after consequences of every change.
- **Cryptographic accountability:** approvals are hardware-backed signatures bound to the exact diff and graph version, and every step lands in a hash-chained, externally witnessed ledger.
- **Independence:** policy authority sits in a separately governed M-of-N trust domain that the control plane can verify but never forge.

All of it is built in Go on a deliberately small set of free, battle-tested components (Postgres, NATS JetStream, OPA, River). It is deployable on one free VM today, and it grows through stateless replicas and isolated cells without redesign.
