# Ishaan's implementation plan: Control Plane Core

**Prepared:** 2026-11-03  
**Owner:** Ishaan / Half A  
**Status:** Phase 3 in progress on `main`, explicitly authorized on 2026-11-05. Phase 2 and earlier peer integration acceptance remain pending; advancing core work does not waive those gates. See [Ishaan changelog](docs/ishaan/changelog.md). Phases run sequentially.
**Sources read in full:** [PRD](PRD.md), [product concept](RATCHET_Full_Idea_Document.md), [architecture](RATCHET_Architecture.md).  
**Companion:** [Sakar's implementation plan](SAKAR_IMPLEMENTATION_PLAN.md).

## 1. Scope and ownership

Build the part of RATCHET that computes the consequences of a proposed authority change, makes a deterministic policy decision, coordinates independently approved execution, and preserves the evidence. The initial product is one fictional exchange tenant. It is not an AI system, payment processor, identity-provider replacement, or production multi-tenant platform.

| Ishaan-owned path | Deliverable |
|---|---|
| `internal/domain/` | Pure change state machine, commands, events, decisions and invariants |
| `internal/eventstore/` | PostgreSQL event persistence, optimistic concurrency, idempotency and transactional outbox |
| `internal/bus/` | Outbox relay, ingestion consumers, execution command publishing and result handling |
| `internal/graph/` | Versioned graph, reach, takeover analysis, paths, immutable impact simulation, reduction proof and containment algorithm |
| `internal/policy/`, `policies/` | Embedded OPA, policy evaluation, signed-bundle loading and RATCHET's own authorization |
| `internal/workflow/` | Request handling, approvals, independence, quorum, execution guards, River jobs and restoration |
| `internal/projection/` | Rebuildable queue, overview, incident, identity and audit read models |
| `internal/ledger/` | Event hash chain, export format and checkpoint candidates |
| `internal/api/`, `cmd/ratchetd/` | Core ConnectRPC APIs, session login, authorization, passkey-handler mounting and embedding the completed web build |
| `internal/connector/conformance/` | Executable connector contract tests |

Sakar owns `web/`, `internal/canon/`, `internal/approval/`, `internal/trust/`, Authority, simulator, connector adapters, CLI and `e2e/`. Consume their public contracts; do not implement substitutes or change those paths to work around a dependency.

`proto/`, `internal/ports/`, `testdata/`, `deploy/compose/`, `.github/`, `PRD.md` and `RATCHET_Architecture.md` remain shared. Root Go-module files, code-generation settings and other common build metadata also need both people's agreement. Ishaan contributes his core, database, bus and CI portions; this does not make him responsible for Sakar's services or frontend. Shared changes require the other person's review before merge.

## 2. Execution rules and source conflicts

1. **No scaffolding deliverables.** Create a package, API route, job or executable when it performs its real operation. Do not merge empty handlers, `TODO` implementations, success-returning stubs, fake approvals, hardcoded decisions, or fixture-backed production responses. A directory tree or health endpoint alone does not complete a phase.
2. **No runtime fake mode.** The user's instruction overrides the PRD's `--mode=fake` and skeleton milestones. Shared fixtures, random graph generators and a test-only reference graph are legitimate verification inputs. Connector conformance tests may use an isolated protocol harness, but real integration gates must use the implemented services. The simulator is a required product target with actual IAM state, not a fake control plane.
3. **Integrate working increments.** Declare the v1 contracts early, but expose only implemented operations. Generate clients and bindings from real schemas. Defer an unavailable integration instead of returning plausible data.
4. **Record evidence from day one.** Implement hash chaining with the first persisted event, rather than adding audit history in Week 8. Later audit work adds search, export and checkpoints.
5. **No temporary trust bypass.** Signed-policy loading, passkey verification, independence checks and the execution guard must be active before any approved grant is executed. Their delivery is brought forward from the PRD's later trust milestone.
6. **Ordinary access needs owner approval.** Use FR-P2's one-resource-owner requirement. The M2 phrase "ordinary request is allowed" means allowed after the required approval, not an unconditional bypass.
7. **Protect safeguards consistently.** Ordinary tier-0 safeguard weakening is rejected. Authority governance may change a rule through its signed process; a bundle signature does not itself authorize a direct write to the target. Any resulting target change still needs an eligible decision, approved payload and verified execution.
8. **Keep v1 honest.** All P0 work is mandatory. P1 work is planned below and retains its PRD priority; any deferred P1 item must be named in the completion record. Kubernetes is a separately gated stretch target. P2 break-glass and external witnessing remain future work. Do not call unfinished selected scope complete.

### The R6 gap must remain visible

The PRD makes complete-control-plane-outage reductions an invariant but places the quorum-released break-glass mechanism in P2 (`FR-X6`, Sakar). Ishaan must block escalations on failure, preserve queued work, and never treat an unverified change as a reduction. Those controls do not create an outage-independent revocation channel. Record that limitation in v1 acceptance. If full R6 is required for release, release remains blocked until FR-X6 is separately scheduled in its existing owner scope; do not create an Ishaan-owned bypass.

## 3. Zero-cost constraints

The implementation and all acceptance tests must work on existing development hardware. No subscription, paid database, hosted policy engine, paid workflow product, trial credit, purchased domain, hardware security-key purchase, or cloud account is a prerequisite. Existing hardware, internet and electricity are assumed available; this is a zero additional service/software spend plan.

| Need | Free implementation choice |
|---|---|
| Database, bus and policy | Self-hosted PostgreSQL, NATS JetStream/KV and embedded OPA |
| Jobs | Open-source River scheduled jobs plus the explicit domain state machine. Do not use River Pro workflows, sequences or durable-periodic-job add-ons. [River feature boundary](https://riverqueue.com/docs/pro) |
| Contracts and generation | Local Protobuf/Buf CLI tooling and local generators; no paid registry dependency |
| CI | Standard GitHub-hosted runners for the public repository described by the PRD; no larger runners or paid overages. Retain short-lived test artifacts within included storage. [GitHub runner terms](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) |
| Development containers | Docker Engine and Compose on Linux/WSL2, or Docker Desktop only while eligible for its free license. [Docker terms](https://docs.docker.com/subscription-billing/desktop-license/) |
| Telemetry | Local OpenTelemetry collection and self-hosted Prometheus/Grafana/Loki; redact secrets and personal data |

The architecture's Oracle **4-core / 24-GB Always Free** assumption must not be used as a guaranteed resource budget. As checked on 2026-11-03, Oracle documents **2 OCPUs / 12 GB** for Always Free tenancies and possible capacity shortages. Cloud hosting remains optional and deferred. [Oracle Always Free documentation](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)

## 4. Phase sequence

Weeks are estimates from the agreed start date, not promises or instructions to overlap unfinished security gates. Moving a dependency changes the schedule, not ownership. Per the current user instruction, work on `main` only, use focused Conventional Commits, and keep shared changes subject to peer agreement. Use the twice-weekly check-in to report delivered contracts and blockers.

| Phase | Indicative window | Working result |
|---|---|---|
| 0 | Week 1 | Frozen contracts and a real append/read/restart core slice |
| 1 | Weeks 2-3 | Live organization ingestion and correct versioned graph analysis |
| 2 | Weeks 4-5 | Real policy decisions and independently approved, verified ordinary access |
| 3 | Weeks 6-7 | Adversarial approval, governance and stale-context cases enforced |
| 4 | Weeks 8-9 | Surgical containment, linked restoration and verifiable audit exports |
| 5 | Week 10 | Planned P1 core workflows, drift decisions and measured performance |
| 6 | Week 11 | Core support for the optional real Kubernetes demonstration |
| 7 | Week 12 or after prior gates | Completed-core hardening and release-readiness evidence |

There is no deployment phase or hosting blueprint in this document. Local Compose use is for development and acceptance of real components.

## 5. Phase 0 - Contracts and the first durable core operation

**Entry:** Documents are the current repository contents; do not assume application code or infrastructure already exists.

**Execution record (2026-11-04):** The real core slice, schemas, SQL, hash chain,
privacy separation, role restrictions, process operations and local checks are
implemented. Contract freeze/agreement remains pending peer review. The isolated
combined test run also reproduces an existing peer audit-fixture failure on
untouched `origin/sakar`. Phase 0 remains unsigned until the
[handoff gates](docs/ishaan/phase-0-handoff.md) are resolved. The user subsequently
explicitly authorized starting Phase 1 with these joint gates outstanding; this
does not imply peer approval. The user's instruction overrides the topic-branch
rule: all Ishaan changes are committed on `main` only.

### Ishaan's work

- [x] Establish the Go module and build configuration needed by the first actual core operation. Add implementation files as they become useful; do not populate empty future modules.
- [ ] Contribute the eight core service schemas: `ChangeService`, `ImpactService`, `GraphService`, `ContainmentService`, `IncidentService`, `AuditService`, `OverviewService`, `DecisionService`. Freeze request kinds, state names, enum meanings, pagination, typed errors, tenant identifiers, graph versions and idempotency fields with the peer.
- [x] Specify the control-plane side of `GraphSnapshot`, `GraphDelta`, `ExecCommand`, `ExecResult`, `ObservedState`, `AuditEvent` and `DriftReport`. Include connector identity, tenant, schema version, source revision, correlation ID, command ID, preconditions and read-back evidence. Keep the five PRD NATS subjects unchanged unless a reviewed additive contract change is necessary.
- [x] Review `ApprovalVerifier`, `BundleVerifier`, `Digester` and `PasskeyHandlerFactory` ports and their failure behavior. Specify how the authenticated actor and tenant enter these boundaries without trusting user-supplied identity fields.
- [x] Specify the approval envelope: exact change intent, requester and target, request/revision ID, graph version, impact digest, policy hash, tenant and expiration. Accept Sakar's canonicalization format instead of creating another digest implementation.
- [ ] Agree the append-only chain format and a replayable decision fact sheet. Specify byte encoding, sequence order, genesis hash, versioning and canonical metadata before events are stored.
- [x] Implement real PostgreSQL migrations and repositories using `pgx`, `sqlc` and `goose`: append/load an event stream, expected-version conflicts, command idempotency and outbox insertion in one transaction. Use a tenant-specific locked chain head or equivalent serialization so concurrent streams cannot fork the tenant hash chain. Do not assume generated sequence allocation equals commit order.
- [x] Start hash chaining immediately with Sakar's real `Digester`. Separate mutable personal-data storage and encrypted references from immutable event content. Do not duplicate justifications or names into permanent metadata by accident.
- [x] Provide distinct migration and runtime DB privileges; runtime must not update, delete or truncate event/ledger rows. Read-model writers need only their projection permissions. Runtime must not own tables or hold superuser privileges.
- [x] Make `ratchetd` perform a real persisted operation and expose honest liveness/readiness. Readiness distinguishes migration, database and graph/bundle readiness; unavailable decision dependencies never appear healthy for escalation.
- [x] Contribute working local Postgres/NATS startup and core checks to shared Compose/CI. Add `go vet`, lint, focused integration tests and race checks for code that exists. Establish the initial Buf baseline; later contract diffs run `buf breaking` against it.

**Dependency:** The real digester and canonical vectors come from the peer-owned package. Before that lands, design schemas and SQL or test independent domain operations; do not add a second digester or bypass hash verification.

**Exit evidence:** A valid event survives process restart; an aborted transaction leaves no partial event/outbox write; concurrent appends cannot fork the chain; a duplicate command has one effect; runtime SQL cannot mutate prior events. CI runs actual checks and both people review the shared contracts.

**Handoff:** Approved core schemas, ledger format, core CI job names, real database operation and examples of typed errors. Shared-path changes merge before dependent implementation PRs.

## 6. Phase 1 - Ingestion, graph correctness and impact

**Requirements:** FR-G1-G5, FR-G7, FR-I1; core API support for FR-G6 and FR-I2.

**Execution record (2026-11-04):** Core operations and verification are implemented
without runtime fakes. Real PostgreSQL/JetStream/TLS acceptance passes. Shared
fixtures remain review candidates and the actual peer adapter fails five
conformance checks; its executable also lacks actual NATS publication. The
[handoff](docs/ishaan/phase-1-handoff.md) records exact evidence and owner actions.
Phase 1 is not signed off; Phase 2 was subsequently authorized and is in progress. The first 100k-edge impact
baseline is 1.38 s/op; the 100 ms target remains unmet and is scheduled for Phase 5.

### Ishaan's work

- [x] Implement the outbox-to-JetStream relay with durable acknowledgement, stable message IDs, retry/backoff and observable backlog. Mark delivery only after acknowledgement; tolerate replay. Exactly-once business effects come from durable idempotency, not a claim of exactly-once transport.
- [x] Implement ingestion authorization and consumers for actual connector snapshots/deltas. Deduplicate input, check source ordering, reject cross-tenant or malformed data, and atomically expose a completed snapshot. Detect gaps and request/respect resync rather than silently dropping edges.
- [x] Build the typed graph for humans, service accounts, groups, roles, permissions, resources, safeguards, sessions and credentials. Preserve access provenance and resource tiers 0-3.
- [x] Implement takeover inheritance, role-modification self-grant semantics and safeguard-protection semantics. `ControlSet` must account for control powers acquired through memberships and roles, not only directly attached takeover edges. Handle cycles and transitive control safely.
- [x] Implement immutable CSR snapshots, delta application and isolated proposed-change overlays. Publish versions atomically; one query cannot mix graph generations. Version results from their applied event position.
- [x] Deliver `Reach`, `PathsTo`, `ControlSet` and `ImpactDiff`. Analyze every identity affected by the change, including identities other than the requester. Return new resources, controllable identities, tier-0 paths, weakened safeguards and blast-radius changes by tier.
- [x] Implement `GraphService` node details, focused neighborhoods, provenance and bounded/paginated paths; implement draft-only `ImpactService`. Simulation must not submit a request, publish an execution command, mutate target state or advance the graph.
- [x] Support bounded `min_version` waits and explicit stale/unavailable responses. Do not make an escalation decision against a replica known to be behind the required revision.
- [ ] Produce reviewed expected impact fixtures from the real seeded exchange and policy fact inputs. Keep fixture updates in shared PRs.
- [x] Extend connector conformance coverage for sync, snapshot completeness, duplicate messages, delta gaps, tenant isolation and reconnect/replay.

**Verification:** Compare optimized queries with an independent test-only reference traversal on random cyclic organizations. Include indirect role administration, service-account takeover, missing nodes, multi-identity impact and concurrent simulations. Record a first reproducible 100k-edge benchmark with dataset seed and hardware.

**Exit evidence:** A real connector sync appears through the core graph API. Simulating Rahul's admin request returns the wallet-signer path and correct graph version, matching reviewed fixtures, while subsequent reads and simulator IAM remain unchanged. This supplies the core evidence for D3.

**Handoff:** Real `GraphService`/`ImpactService`, version semantics and impact fixtures. UI/layout and adapter defects stay with their existing owner.

## 7. Phase 2 - Real decisions and safely executed ordinary access

**Requirements:** FR-C1-C3, FR-C5 rules, FR-C7-C9 core, FR-P1-P2, FR-P4 loading, FR-P6, FR-O1 data, FR-U1, FR-U3, FR-L1. These security checks are required now, not optional Phase 3 additions.

**Execution checkpoint (2026-11-04):** The user explicitly authorized Phase 2.
Password sessions, the pure state machine, signed prepared OPA policies,
transactional River workers, guarded command staging/read-back and core API
operations are implemented. Native component tests use real PostgreSQL, real
cryptography and real River jobs. Live browser/peer-target acceptance is still
blocked by the peer session/verifier/connector conformance gaps. No unsafe peer
handler or simulated assertion endpoint is mounted. Final runtime/CI/contract
verification and handoff are recorded in [the Phase 2 handoff](docs/ishaan/phase-2-handoff.md).
The core race/contract checks pass, but peer conformance fails reproducibly;
do not sign off this phase yet. The user subsequently authorized Phase 3 core work
on 2026-11-05 while these peer gates remain open.

### Ishaan's work

- [x] Implement seeded-user login with actual session verification, expiration, logout and server-derived actor identity. Use secure cookie configuration appropriate to the origin, CSRF protection for state changes and policy authorization at each service operation. A role dropdown or arbitrary user-ID header is not login.
- [ ] Mount the peer's real passkey handlers through the agreed factory and dependencies; do not reimplement enrollment or assertion verification. Block privileged operations while the verifier or required identity binding is unavailable.
- [x] Implement pure `(state, command) -> events/error` transitions for Submitted, Assessed, Allowed, AwaitingApproval, Held, Rejected, Approved, Executing, Executed, Failed, Expired and Revoked. Define valid transitions explicitly; support added context and reassessment after a hold. Do not create a direct Submitted-to-Executed shortcut.
- [x] Validate each supported change kind, justification, target, requested access, incident linkage and optional expiration. Reject unknown or unsupported kinds with a typed error.
- [x] Embed OPA prepared queries. Return structured `ALLOW`, `REQUIRE_APPROVAL`, `HOLD` or `REJECT`, with reasons and required groups/quorum. Bind policy inputs to recorded, replayable facts rather than live wall-clock or network lookups during evaluation.
- [x] Implement the actual demo policy: ordinary access requires one independent resource owner; a new tier-0 route requires two distinct security leads; tier-0 safeguard weakening is rejected; an authorized verified reduction is eligible for allow. Use hold where required context is incomplete.
- [x] Load policy exclusively through the real peer `BundleVerifier`, pinned to the agreed genesis trust root and current registry history. An invalid bundle cannot replace the last valid bundle; without any valid bundle, escalation stays unavailable. Record the active bundle hash on each decision. Current support is pinned epoch 1; later epochs refuse activation pending verified history in Phase 3.
- [x] Implement approval orchestration using the peer `ApprovalVerifier`. Check requester versus approver, requester control over approver, allowed group membership, distinct human identities and conflicts where the approver or an identity they control benefits from the proposed expansion. Multiple passkeys for one person never count as multiple people.
- [x] Persist the exact approved envelope and assertion evidence. Quorum completion, the transition and its outbox/job writes must be concurrency-safe; retries or parallel submissions cannot count one signature twice.
- [x] Implement River-backed assessment/execution jobs in the same transaction as domain events. Use OSS jobs and explicit state transitions, not paid workflow abstractions.
- [x] Before dispatch, re-evaluate current graph impact, policy version, approval eligibility and target preconditions. A changed approved context returns to review with `context changed` and invalidates stale approval reuse. Define this conservatively when graph versions differ; no silent substitution of a new digest.
- [ ] Publish a correlated, idempotent command only after all guards pass. Consume the connector's apply/read-back evidence. Record Executed only after verified observed state matches the approved intent; an acknowledgement or successful HTTP write alone is insufficient. On uncertain execution, reconcile instead of blindly repeating a non-idempotent operation.
- [x] Project request details, approval queues and attention-oriented overview data. Implement the real core Change/Overview handlers; provide clear pending, failed and unavailable results.
- [x] Add connector conformance cases for Execute/Verify, duplicate delivery, failed preconditions, mismatched read-back, interrupted execution and recovery. The actual peer fails precondition enforcement; see the handoff for exact failing cases.

**Dependency gate:** Signed initial bundle, enrolled approvers, real assertion verifier and real connector Execute/Verify are required inputs. If any is unavailable, keep affected requests pending and work on independent core tests. Never substitute an unsigned policy or automatically approved request.

**Exit evidence:** D1 succeeds through one legitimate owner passkey approval, actual target execution and read-back. D2 requires two security leads with reasons. Self-approval and a write with bad read-back cannot grant access. Every decision/transition is already hash-chained.

## 8. Phase 3 - Adversarial trust, policy governance and context changes

**Requirements:** Complete FR-C7-C8 enforcement, FR-P4 loading/enforcement and R1-R4/R7 evidence. The basic implementations already exist from Phase 2.

**Core checkpoint (2026-11-05):** The implementation and owned acceptance checks are delivered. Joint browser/connector acceptance remains pending; the execution contract is defined as a proposal and the actual peer fails precondition enforcement. See [Phase 3 evidence](docs/ishaan/phase-3-handoff.md).

### Ishaan's work

- [x] Extend independence tests to requester-controlled approvers, newly acquired control, transitive takeover, beneficiary self-approval, multiple credentials for one person and concurrent quorum attempts.
- [x] Re-check independence and permissions at execution as well as assessment. A later graph/registry change must not let a formerly independent approval execute an expansion.
- [x] Exercise invalid, missing, duplicate, revoked and wrong-context signatures returned through the verifier boundary. Do not duplicate its cryptographic implementation in workflow code.
- [x] Verify activation behavior across valid/invalid bundles, changed approver registries, threshold changes and rollback attempts. Only artifacts verified against the authorized trust-root history may influence policy; prevent replay of an obsolete but previously valid bundle.
- [x] Preserve last-known-valid operation when Authority is temporarily unavailable, subject to recorded validity rules. Record activation events and make bundle history available through core projections where required.
- [x] Confirm ordinary target requests cannot edit approver lists, quorum, withdrawal safeguards or trust-root configuration through an alternate API path. No admin-session override may bypass `BundleVerifier`.
- [x] Define execution serialization/preconditions with the connector contract so a relevant target revision cannot change unnoticed between approval, dispatch and apply. A core recheck alone is not proof against target-side races.
- [x] Run property-based sequences over random organizations and changes for R1-R3: no deciding self-benefit, no claimed reduction that creates reach, and no stale approval executing a changed intent/context.
- [x] Demonstrate deterministic decision replay using recorded graph revision, policy bundle, facts and evaluator/schema version. Export the required evidence through the agreed interfaces.

**Exit evidence:** D4 refuses both Rahul and an identity he controls without advancing request approval state. D5 rejects ordinary withdrawal-rule weakening, while a legitimate governance amendment only becomes active after independently signed Authority verification. Changing graph or policy after approval forces reassessment rather than execution. No runtime bypass flags exist.

**Handoff:** Reproducible backend failure cases, versioned activation/read models and structured reasons; Sakar consumes these in screens and end-to-end scenarios.

## 9. Phase 4 - Containment, restoration and audit proof

**Requirements:** FR-X1-X3 core, FR-X5, FR-L1, FR-L2 candidates, FR-L4 chain format, core services supporting FR-X4 and FR-L3.

### Ishaan's work

- [ ] Implement `IsMonotonicReduction`: every affected identity's after-reach is a subset of before-reach and no safeguard is weakened. Removal of a deny rule, approval requirement or protective membership is not automatically a reduction. Unknown semantics cannot enter the fast path.
- [ ] Implement passkey-confirmed authorized responder commands for restriction, grant removal, service-permission removal and session termination. Bind the assertion to the exact containment action/plan and context through the peer verifier.
- [ ] Persist and publish verified reductions on the priority containment subject without waiting for ordinary grant approvals. Revalidate the plan/context before dispatch and verify the result through the same durable evidence flow.
- [ ] Implement weighted min-cut containment against a super-sink for tier-0 resources. Cut candidates must map to executable revocation operations; derived reachability edges cannot be presented as removable target grants. Account for shared grants and protected/non-removable edges.
- [ ] Prove zero remaining tier-0 reach by simulating the complete proposed action set through the real graph semantics. Report affected and preserved non-critical activities. If an exact minimum cannot be established for a topology, identify that limit and use a verified safe alternative; do not claim an unproven optimum.
- [ ] Implement `ContainmentService` Plan/Execute/Restore and `IncidentService` List/Get. Store incident correlation, actions, failures, residual paths and restoration prerequisites.
- [ ] Treat restoration as a new increase through normal independent review; preserve the incident link and never reuse a containment passkey assertion to restore access.
- [ ] Complete audit projections and `AuditService` search/export with actor/resource/request/incident/time filters and role-based visibility. Export raw chain evidence separately from redacted display records.
- [ ] Finalize the versioned offline chain format: canonical event bytes, previous/current hashes, ordered tenant sequence, approval envelopes/assertions, historical public keys and registry/bundle evidence. Export no private keys. Privacy retention may erase separate encrypted personal data without changing immutable bytes.
- [ ] Compute unambiguous checkpoint candidates with sequence range, prior checkpoint reference, leaf encoding and Merkle algorithm. Submit candidates through the peer signing contract, verify returned signatures and append checkpoint references without a self-referential hash cycle.
- [ ] Add DB tamper-denial, chain-fork, replay/rebuild and checkpoint-continuity tests. Supply deliberately corrupted export fixtures for the peer's verifier tests.

**Verification:** Measure from containment click initiation through passkey confirmation, dispatch and verified read-back; also report machine processing time separately so human interaction is visible. Exercise a normal-work backlog and a connector restart. Check actual report-access probes before/after containment, not merely counts in the graph.

**Exit evidence:** Core D6-D8 evidence is available: verified revocation under the PRD's 5-second scenario target, zero tier-0 reach, finance reports retained, complete chain export and signed checkpoint candidates. The final end-to-end/CLI verdict is supplied through the peer-owned acceptance suite.

## 10. Phase 5 - Planned P1 workflows, drift and performance

**Requirements:** FR-C10-C11, FR-I3, FR-E1-E3 core, FR-O2 stream, FR-K4 core, FR-L2 candidate scheduling; non-functional targets.

### Ishaan's work

- [ ] Add requester-safe response redaction at the API boundary. Keep investigator detail policy-restricted; do not rely on the frontend to hide sensitive fields.
- [ ] Implement configurable approval expiry and durable emergency-grant expiry using database time. Schedule revocation atomically when the grant is committed, preserve it across restart, and reconcile missed/late jobs. Never record Revoked until the target confirms revocation.
- [ ] Route emergency requests to the existing eligible independent approver policy and enforce fixed duration/minimum necessary access. An emergency flag must not disable quorum, passkeys or impact analysis.
- [ ] Add temporary-grant review read models, including failed expiry/revocation requiring attention. Flag over-broad access from explicit requested resources/permissions; do not infer business intent through AI or invented scores.
- [ ] Implement resumable Change/Incident Watch streams with stable cursors and explicit reconnect behavior, backed by real projections/events. Avoid data races between list results and streamed updates.
- [ ] Consume actual `DriftReport`/audit observations. Correlate against approved commands, decide whether a reversal is a proven reduction, open the incident and publish the authorized corrective command. Unknown/unsafe restoration is held for review rather than labeled reduction.
- [ ] Prevent drift-reversion loops, duplicate incidents and false drift alarms from normal read-back delay. Preserve provenance of the observed and corrective changes.
- [ ] Expose authenticated `DecisionService` from the same graph/policy engine; keep inline decisions side-effect semantics explicit in the shared contract and record enforcement decisions durably. A previous allow response is not a reusable execution authorization.
- [ ] Optimize prepared policy queries, graph snapshots and bounded traversal using measurements. Benchmark inline p99 < 50 ms on the demo dataset and ImpactDiff < 100 ms at 100k edges; publish hardware, graph composition, sample counts and tail results. Do not advertise targets as achieved without evidence.
- [ ] Build the core benign-change replay/metrics harness in Ishaan-owned packages. Measure unexpected delays/rejections against expected legitimate outcomes, report denominator and causes, and target < 5%. Do not modify the peer's `e2e/` scripts.
- [ ] Add trace spans across submit, assessment, decision, outbox, connector result and verification, preserving correlation IDs. Emit backlog, graph-lag, policy-version, job failure and containment-duration metrics without leaking approval secrets or personal data.

**Exit evidence:** Temporary access actually expires after restart; requester redaction survives direct API access; live streams recover; unauthorized target drift creates one incident and a verified corrective action; realistic benign and performance results are recorded. Any unfinished P1 item is explicitly marked deferred, never represented by a stub.

## 11. Phase 6 - Optional Kubernetes core integration

**Requirements:** FR-K5 decision endpoint; this is stretch scope, not a reason to weaken the completed simulator path.

- [ ] Review the shared mapping for Role/ClusterRole, RoleBinding/ClusterRoleBinding, wildcard grants, `bind`, `escalate`, `impersonate` and service-account token creation. Implement their core graph/policy semantics where needed; API parsing and admission integration remain connector-owned.
- [ ] Support admission request identity, target revision and approved-intent correlation through `DecisionService`. Unsupported or stale sensitive changes must not default to allow.
- [ ] Ensure the inline allow decision corresponds to the exact admission object/context; reconcile webhook observation and execution state without inventing a second grant path.
- [ ] Run core fail-closed and latency checks with the real peer adapter on local `kind`. Keep request errors, policy refusals and downstream unavailability distinguishable.
- [ ] Support drift decisions and incident/read-model evidence for actual RBAC changes. Record any unsupported D1-D8 mapping explicitly; do not claim full Kubernetes parity from one blocked RoleBinding.

**Exit evidence:** The real adapter's admission request receives the correct decision, a sensitive grant is blocked during core unavailability, approved changes are correlated and observed, and core metrics remain reproducible. If this stretch is deferred, label it deferred in release scope without changing either person's ownership.

## 12. Phase 7 - Hardening and completion evidence

### Ishaan's work

- [ ] Exercise database, NATS, graph lag, Authority unavailability and connector outage independently. Prove durable queues/reconciliation, fail-closed grants and honest degraded status. Do not claim HA from a single local instance.
- [ ] Rebuild graphs/read models from events after restart and compare them with pre-restart results. Validate snapshot integrity, replay checkpoints, migrations and local backup/restore for the core database.
- [ ] Finish privacy-key deletion and sensitive-record access checks; demonstrate that retained chain verification survives deletion of separate personal data. Keep required non-personal replay facts available.
- [ ] Complete rate limits, request-size limits, malformed-payload fuzzing, dependency checks and concurrency testing for core-owned code. Enforce inward dependencies so domain logic stays free of I/O.
- [ ] Make `ratchetd` roles selectable without code changes; test the supported combined and separated-role configurations locally. Preserve tenant fields and isolation checks without building a production cell router or multi-tenant SaaS.
- [ ] Embed the peer's actual built web assets through the agreed artifact path and same-origin API routes. Verify SPA fallback does not intercept `/api` errors; no placeholder index page may replace a missing build.
- [ ] Contribute core container builds, non-root/distroless settings, SBOM generation and image-signature verification checks to reviewed shared build files. Complete core configuration/readiness/restore documentation; do not write the peer's component runbooks.
- [ ] Run required checks: `go vet`, `golangci-lint`, `go test -race ./...`, property tests/fuzz regressions, `opa test`, Buf lint/breaking, actual connector conformance and real local Compose smoke integration. Whole-repository failures are routed to their owner instead of fixed across the boundary.
- [ ] Attach core evidence to the joint D1-D8 report, including known R6/P2 limits, retained/deferred P1 scope, selected Kubernetes scope, latency results, benign false-positive results and preserved business activities. Reference Sakar's scenario/CLI results instead of duplicating their implementation.

**Exit:** Every selected core operation is implemented, every relevant check passes on the same candidate commit, no unfinished runtime substitute remains, and failures/limitations are stated accurately. A green build alone is not product completion.

## 13. Requirement coverage for Ishaan

Only Ishaan's portion of split requirements appears below; consuming a peer deliverable does not transfer its implementation ownership.

| Requirement | Ishaan deliverable | Phase |
|---|---|---|
| FR-G1, FR-G2, FR-G3, FR-G4, FR-G5, FR-G7 | Ingestion, escalation semantics, reach/paths/control and versioned graph responses | 1 |
| FR-C1, FR-C2, FR-C3 | Submit API, pure lifecycle, impact/policy orchestration | 2 |
| FR-C5 | Reviewer authority and transition rules | 2-3 |
| FR-C7, FR-C8 | Independence, distinct quorum and current-context execution guard | 2-3 |
| FR-C9 | Execution orchestration and verified-state completion | 2 |
| FR-C10, FR-C11 | Requester redaction and approval timeout | 5 |
| FR-I1, FR-I3 | Isolated impact diff and explicit over-grant detection | 1, 5 |
| FR-P1, FR-P2, FR-P4, FR-P6 | Rego decisions, demo policies, verified-bundle loading and policy hash | 2-3 |
| FR-X1, FR-X2, FR-X3, FR-X5 | Containment workflow, reduction proof, minimum-disruption plan and reviewed restoration | 4 |
| FR-E1, FR-E2, FR-E3 | Emergency routing, durable timer and review data | 5 |
| FR-L1, FR-L2, FR-L4 | Append-only chain, checkpoint candidates and offline export specification | 0, 4-5 |
| FR-O1, FR-O2 | Attention read models and resumable streams | 2, 5 |
| FR-K4, FR-K5 | Drift decision/incident and inline decision endpoint | 5-6 |
| FR-U1, FR-U3 | Real seeded sessions and server-side policy authorization | 2 |
| PRD sections 6, 9, 10, 13 | Core NFRs, contracts, conformance, CI and measured outcomes | All; final evidence in 7 |

FR-G6, FR-C4/C6, FR-I2, FR-P3/P5, FR-X4, FR-L3, FR-K1/K2/K3/K6 and FR-U2 are peer-owned implementations. Their integration remains necessary for acceptance but is not an additional Ishaan task. FR-X6 and FR-L5 remain deferred P2 mechanisms.

## 14. Completion gate before any deployment blueprint

- [ ] All P0 core requirements above work with real peer components, without fake mode or trust bypasses.
- [ ] D1-D8 pass end to end on the simulator, including owner approval, independent admin quorum, target read-back, continuity and offline audit verification.
- [ ] Each P1 item has a truthful completed/deferred status, and all P1 items selected for the release pass their checks. The Kubernetes stretch has its own demonstrated/deferred status.
- [ ] Shared CI, property tests, conformance, replay, restart, retention and supply-chain checks pass; published metrics match the tested candidate.
- [ ] Both people accept their own half's evidence and the integrated results. The R6/FR-X6 scope conflict is explicitly resolved or documented as a v1 limitation; full R6 cannot be claimed without its mechanism.
- [ ] No new paid service, trial-funded dependency or cloud allocation is necessary to reproduce completion locally.

**Deployment blueprint: deliberately deferred until the selected project scope is fully implemented and these gates pass.** This document does not provision hosting or prescribe DNS, TLS, network topology, rollout or production deployment commands. After actual completion, Ishaan supplies the verified core artifact, resource measurements and configuration/restore requirements for that later blueprint; deployment work is not silently reassigned to him.
