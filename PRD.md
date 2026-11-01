# RATCHET — Product Requirements Document (PRD)

**Version:** 1.0 · **Date:** 2026-11-02
**Team:** Ishaan · Sakar
**Repository:** https://github.com/sakararya43-web/Ratchet
**Source documents:** [`RATCHET_Full_Idea_Document.md`](RATCHET_Full_Idea_Document.md) (what and why) · [`RATCHET_Architecture.md`](RATCHET_Architecture.md) (how)

This PRD turns the idea document into buildable requirements and splits the work into two halves that can be built in parallel without breaking each other. If this PRD and the idea document ever disagree on *what RATCHET is*, the idea document wins.

---

## 1. Product summary

**RATCHET is an independent security control plane that stops someone who has got inside an organisation from quietly gaining more power, rewriting the rules that protect critical systems, or using one compromised account to reach the organisation's most valuable assets.**

> **Getting inside an organisation should not mean gaining control of the organisation.**

RATCHET reviews sensitive access and security changes **before they take effect**. It computes what new power each change would create, decides through the organisation's rules (Allow / Require independent approval / Hold / Reject), never lets a requester approve its own escalation, protects security rules through an independently governed authority, and makes taking access away faster than granting it.

RATCHET is **not** an AI product, a dashboard of threat scores, a fraud-monitoring tool, or a replacement for existing identity products (idea doc §5).

---

## 2. Goals and non-goals

### 2.1 Goals for v1 (idea doc §19)

v1 runs against a **simulated cryptocurrency exchange**. It must demonstrate, end to end:

| # | Must demonstrate |
|---|---|
| D1 | A normal employee can request ordinary access, and it is handled through the normal process. |
| D2 | A request for administrator privileges is detected and treated as a sensitive change. |
| D3 | RATCHET shows which additional resources the new role would expose, and any new routes to critical assets. |
| D4 | A compromised employee cannot approve their own privilege increase, nor have it approved by anyone they can control. |
| D5 | An attempt to change a critical security rule is rejected or sent to independent review by the Authority. |
| D6 | A security responder can revoke compromised access quickly. |
| D7 | Unrelated safe activities keep working during containment. |
| D8 | Every important decision is recorded in a tamper-evident log and can be reviewed and verified. |

**Stretch goal (strongly wanted):** D1–D8 also run against **real Kubernetes RBAC** on a local `kind` cluster, proving RATCHET stops real escalations and not only simulated ones.

### 2.2 Non-goals for v1 (idea doc §19)

- Covering every cyberattack type, industry or infrastructure kind.
- Replacing the organisation's identity provider or security products.
- Fraud monitoring, payment processing or transaction approval.
- Anything AI-based.
- Claiming that breaches become impossible.
- Production multi-tenancy at scale. The design must *allow* it (architecture §8), but v1 runs one demo tenant.

---

## 3. Users

| Persona | Primary need in RATCHET | Main screens |
|---|---|---|
| **CISO / security leadership** | Define and protect the rules for sensitive changes; be part of the Authority quorum | Security Policy, Overview |
| **Security operations responder** | Review suspicious changes, contain compromised accounts | Overview, Change Review, Incident Containment |
| **IAM team** | Understand the consequences of powerful access changes | Change Review, Impact Simulator, Infrastructure Map |
| **Cloud / DevOps engineer** | Request access and changes for legitimate work | Request form, request status |
| **Business / system owner** | Confirm the business need for access to their resource | Change Review (approver) |
| **Independent approver** | Approve sensitive changes separately from the requester | Change Review (passkey approval) |
| **Auditor / risk** | See who requested, approved and executed what, and verify the record | Audit & History |
| **Employee / service owner** | Get clear, fair decisions; normal work keeps running | Request status |

---

## 4. Product principles, as testable rules

These come from idea doc §7 and §9. Each one is an **invariant** that the code must enforce and the tests must check (architecture §1.1).

| ID | Rule | Idea doc |
|---|---|---|
| **R1: No self-escalation** | A principal can never be a deciding approver for a change that expands its own reach, **or the reach of any identity it can take over**. | §8.2, §10, §15.1 |
| **R2: Reductions are computed, not claimed** | A change counts as a reduction only if the graph shows that nobody gains reach **and** no safeguard is weakened. Removing a deny-rule or an approval requirement is an escalation. | §9 |
| **R3: Approve exactly what you saw** | An approval is cryptographically bound to the exact change and the graph state it was assessed against. If the state changed before execution, the change is re-assessed. | §4, §7.2 |
| **R4: Rules are independently governed** | Security policies and the approver list change only with M-of-N signatures from the Authority quorum. | §7.1, §8.1, §22.2 |
| **R5: Nothing is erased** | Every decision is an append-only, hash-chained record. | §7.7, §13.7, §15.4 |
| **R6: Fail closed for escalation, stay open for reduction** | If RATCHET is down, escalations are blocked and reductions remain possible through break-glass. | §7.5, §22.4 |
| **R7: Decisions are explainable and replayable** | Every decision lists human-readable reasons and can be reproduced from the recorded inputs and policy version. No opaque risk scores. | §7.7, §14 |
| **R8: Minimum disruption** | Containment proposes the smallest set of revocations that cuts off critical assets, instead of disabling everything. | §7.6, §17.4 |
| **R9: Privacy and proportionality** | Collect only what access decisions need; restrict who sees sensitive records; enforce retention. | §7.9, §16 |

---

## 5. Functional requirements

Priorities: **P0** = required for the v1 demo (D1–D8). **P1** = important; build if time allows. **P2** = later.
Each requirement names its **owner half** (see §8).

### 5.1 Organisation model and graph (Infrastructure Map)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-G1 | Ingest identities (humans, service accounts), groups, roles, permissions, resources (with criticality tier 0–3) and safeguards (security controls as first-class assets) from connectors. | P0 | A |
| FR-G2 | Model escalation semantics: taking over an identity inherits its reach; being able to modify a role means being able to grant it to yourself; being able to modify a safeguard weakens everything it protects. | P0 | A |
| FR-G3 | `Reach(identity)`: everything an identity can access or control, directly or indirectly. | P0 | A |
| FR-G4 | `PathsTo(identity, critical)`: concrete routes from an identity to tier-0 resources. | P0 | A |
| FR-G5 | `ControlSet(identity)`: the identities it can take over. | P0 | A |
| FR-G6 | Infrastructure Map screen: select any person, service or resource and see what it can reach, who granted that access, its paths to critical resources, and a focused neighbourhood view (not the whole graph at once). | P0 | B |
| FR-G7 | Every graph answer carries the graph version it was computed at. | P0 | A |

### 5.2 Change Review (idea doc §8.2, §13.3)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-C1 | Submit a change request: kind (assign role, create account, grant permission, change approver, modify safeguard…), target, requested access, justification, optional time limit, emergency flag. | P0 | A (API), B (UI) |
| FR-C2 | Every request goes through a state machine: Submitted → Assessed → {Allowed, Awaiting approval, Held, Rejected} → Approved → Executing → Executed / Failed; plus Expired and Revoked. | P0 | A |
| FR-C3 | Assessment runs the impact analysis (FR-I1) and then policy evaluation, producing one decision with reasons. | P0 | A |
| FR-C4 | Change Review screen shows: who is asking, their current access, the requested access, the justification, affected resources, the new power created, the required approvals, the decision and its reasons. | P0 | B |
| FR-C5 | Reviewers can approve, reject, hold or request more info, within their authority. | P0 | A (rules), B (UI) |
| FR-C6 | Approval needs a RATCHET-enrolled passkey signing the change's digest (R3). | P0 | B |
| FR-C7 | Independence check: approver ≠ requester, approver not in the requester's control set, and quorum met by distinct people (R1). | P0 | A |
| FR-C8 | Before executing, re-check the impact at the current graph version. If it differs from what was approved, return the request to review with the reason "context changed" (R3). | P0 | A |
| FR-C9 | Execution is verified by reading back the target system's state. "Executed" is only recorded after verification. | P0 | A (flow), B (connector) |
| FR-C10 | Requesters see a clear decision without leaking sensitive security detail (idea doc §14). | P1 | A (redaction), B (UI) |
| FR-C11 | Approval requests time out after a configurable period. | P1 | A |

### 5.3 Impact and blast radius (idea doc §8.3, §13.4)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-I1 | `ImpactDiff(change)`: newly accessible resources, newly controllable identities, new routes to tier-0, weakened safeguards, and the change in blast radius by tier. Computed as a temporary overlay; it never changes shared state. | P0 | A |
| FR-I2 | Impact Simulator screen: try a draft change (never submitted) and see a side-by-side before/after view with the new paths highlighted. | P0 | B |
| FR-I3 | Flag requested access that is broader than the stated need, e.g. requesting a role whose grants go far beyond the target resource. | P1 | A |

### 5.4 Policy and the Independent Authority (idea doc §8.1, §13.5)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-P1 | Change policies are written in Rego and produce a structured decision: `ALLOW`, `REQUIRE_APPROVAL{quorum, approver_groups}`, `HOLD`, `REJECT`, plus reasons. | P0 | A |
| FR-P2 | The demo ships a policy set covering: ordinary access → owner approval; new tier-0 path → 2 security leads; weakening a tier-0 safeguard → reject; verified reduction → allow. | P0 | A |
| FR-P3 | `ratchet-authority` is a separate service with its own database. At setup ("genesis"), N security leaders enroll passkeys and a threshold M is set. | P0 | B |
| FR-P4 | Policy bundles, approver-list changes and threshold changes need M-of-N passkey signatures. The control plane only *verifies* and refuses unsigned or invalid bundles. | P0 | B (sign and verify), A (load and enforce) |
| FR-P5 | Security Policy screen: propose a policy change, collect signatures, activate, view history. | P0 | B |
| FR-P6 | Every decision records the policy bundle hash it used. | P0 | A |

### 5.5 Emergency containment (idea doc §8.4, §13.6, §9)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-X1 | Responders can restrict an account, end a session, remove a grant or disable a service permission. | P0 | A (flow), B (UI + connector) |
| FR-X2 | Verified reductions by an authorised responder (passkey-confirmed) skip the approval queue and go on a priority channel. Target: under 5 s from click to verified revocation. | P0 | A (fast path), B (priority consumer) |
| FR-X3 | Minimal containment plan: suggest the smallest-disruption set of revocations that cuts every route from the compromised identity to tier-0 assets, and show which normal activities stay unaffected. | P0 | A (algorithm), B (UI) |
| FR-X4 | Incident Containment screen: affected identity, its access, cuttable routes, business activities affected, actions taken, and steps to restore access. | P0 | B |
| FR-X5 | Restoring access is an increase, so it goes through normal review linked to the incident. | P0 | A |
| FR-X6 | Break-glass: sealed emergency credentials, released only by Authority quorum. | P2 | B |

### 5.6 Emergency (temporary) access (idea doc §11.6, Journey E)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-E1 | An emergency request is marked time-sensitive and routed to the right independent approver. | P1 | A |
| FR-E2 | Only the necessary access is granted, for a fixed period. Auto-revocation is scheduled at the moment of grant. | P1 | A (timer), B (connector revoke) |
| FR-E3 | Temporary grants are listed for review after they expire. | P1 | A (data), B (UI) |

### 5.7 Audit and history (idea doc §13.7, §15)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-L1 | Every state change is an append-only event in a hash chain. The app's database role cannot UPDATE or DELETE these records. | P0 | A |
| FR-L2 | Periodic checkpoints: the Merkle root of new events is signed by the Authority. | P1 | A (candidates), B (signing) |
| FR-L3 | Audit & History screen: search by person, resource, request, incident or time. Each entry shows who requested, who approved, what it would have allowed, why, and when it took effect. | P0 | B |
| FR-L4 | `ratchetctl audit verify` re-walks the hash chain and re-verifies every approval signature offline. | P0 | B (CLI), A (chain format) |
| FR-L5 | Publish checkpoint hashes to a free external witness (Sigstore Rekor or OpenTimestamps). | P2 | B |

### 5.8 Security Overview (idea doc §13.1)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-O1 | Overview shows work needing attention: pending sensitive changes, recent approvals and rejections, policy changes, active incidents, recently restricted access. It is not a wall of statistics. | P0 | A (read models), B (UI) |
| FR-O2 | Live updates when requests or incidents change state. | P1 | A (stream), B (UI) |

### 5.9 Connectors and targets (architecture §5.6)

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-K1 | `ratchet-sim`: a simulated crypto exchange with finance staff (including "Rahul"), admins, wallet-signing service, customer database, service accounts, withdrawal-approval rules and safeguards. It exposes an IAM API and an audit log. | P0 | B |
| FR-K2 | `ratchet-connector` with the sim adapter: Sync, Execute, Verify, Watch. Connects outbound-only to the control plane. | P0 | B |
| FR-K3 | Broker mode: only the connector holds the credentials that can change the simulator's IAM. | P0 | B |
| FR-K4 | Drift detect and revert: if a change appears in the target's audit log without a matching approved request, it is auto-reverted and an incident is opened. | P1 | B (watch + revert), A (decision + incident) |
| FR-K5 | Kubernetes adapter: sync RBAC, a validating admission webhook that calls RATCHET's decision endpoint (fail closed), and drift watch. | P1 | B (adapter), A (decision endpoint) |
| FR-K6 | Scripted attack scenarios from idea doc §10–§11: stolen finance account, compromised developer, rogue admin creation, over-granted service account, safeguard weakening, lateral spread. | P0 | B |

### 5.10 Login and identity for RATCHET users

| ID | Requirement | Pri | Owner |
|---|---|---|---|
| FR-U1 | Console login with a session (demo: seeded users; later OIDC SSO). | P0 | A |
| FR-U2 | Passkey enrollment and management for RATCHET users. Approvals, containment and Authority actions always require a passkey. | P0 | B |
| FR-U3 | RATCHET's own permissions (who may view, approve, contain, administer) are enforced by policy. | P0 | A |

---

## 6. Non-functional requirements

| Area | Requirement |
|---|---|
| **Cost** | $0. Only open-source software and free tiers (architecture §11). |
| **Deployability** | The whole system starts with one `docker compose up` on one machine. The web console is embedded in `ratchetd` (same origin). |
| **Latency** | Inline decision endpoint p99 < 50 ms on the demo dataset. Impact diff on a 100k-edge graph < 100 ms. Containment < 5 s to verified revocation. |
| **Correctness** | R1–R3 are covered by property-based tests over randomly generated organisations and change sequences. |
| **Determinism** | Same inputs + same policy bundle → same decision. Any past decision can be replayed. |
| **Availability behaviour** | Fail closed for escalations, open for reductions (R6). No lost decisions after a crash (outbox + idempotency keys). |
| **Scalability** | Stateless API and graph replicas, partitioning by tenant, cell-based growth. No code changes needed to split roles across machines (architecture §8). |
| **Security** | Passkeys for privileged actions, separated trust domains, least-privilege database roles, signed container images, `govulncheck` in CI, secrets encrypted with SOPS + age. |
| **Privacy** | Personal data kept apart from the hash chain so retention can be enforced through crypto-shredding. Role-based visibility of investigation records. |
| **Observability** | OpenTelemetry traces across submit → assess → decide → execute. |
| **UX** | Serious, precise and operational (idea doc §23): plain-language explanations of impact, no decorative charts. |

---

## 7. Final tech stack

| Layer | Technology |
|---|---|
| Backend language | **Go** |
| Frontend language | **TypeScript** |
| API contract | Protobuf + ConnectRPC (`buf`) |
| Binaries | `ratchetd` (control plane), `ratchet-authority`, `ratchet-connector`, `ratchet-sim`, `ratchetctl` |
| Database | PostgreSQL: append-only event store, outbox, job queue, read models |
| Database access | `pgx/v5`, `sqlc`, `goose` |
| Message bus | NATS JetStream + NATS KV |
| Policy engine | OPA / Rego, embedded |
| Graph | Custom in-memory Go graph engine (CSR + overlay) |
| Workflows and timers | River (Postgres job queue) |
| Approvals and login | WebAuthn passkeys (`go-webauthn`), sessions (OIDC later) |
| Canonical digests | RFC 8785 JSON canonicalisation + SHA-256 (Go and TS, shared test vectors) |
| Audit | Hash chain + Authority-signed checkpoints (+ Rekor / OpenTimestamps later) |
| Web | React 19, Vite, TanStack Router + Query, shadcn/ui + Tailwind, React Flow + ELK, `@connectrpc/connect-web` |
| UI hosting | Embedded in `ratchetd` via Go `embed`. During development, Vite's dev server proxies `/api` to it. |
| Testing | Go tests, `rapid` (property tests), Go fuzzing, `opa test`, `testcontainers-go`, Vitest, Playwright |
| Secrets / supply chain | SOPS + age, `govulncheck`, `syft`, `cosign`, distroless images |
| Observability | OpenTelemetry, Prometheus, Grafana, Loki |
| Run / host | Docker Compose. Oracle Cloud Always Free ARM VM. Cloudflare Tunnel or Caddy for HTTPS. |
| Real demo target | Kubernetes RBAC on `kind` |
| CI | GitHub Actions |

---

## 8. Team split: two halves

The split follows a **clear system boundary**, not a feature list. Half A builds the brain that decides. Half B builds trust, the edges that touch the outside world, and the experience. The halves meet only through **contracts** (§9), which are written together in Week 0 and protected by CI.

### 8.1 Half A: Control Plane Core, owned by **Ishaan**

*"Given a proposed change, compute what it would do, decide according to policy, run it safely, and remember it forever."*

| Module | Responsibility |
|---|---|
| `internal/domain` | Pure change state machine and decisions (no I/O) |
| `internal/eventstore` | Append-only event store, optimistic concurrency, outbox |
| `internal/bus` | Outbox → JetStream relay; ingest consumers; connector command publishing |
| `internal/graph` | Graph engine: Reach, ImpactDiff, PathsTo, ControlSet, monotonic-reduction check, min-cut containment |
| `internal/policy` + `policies/` | OPA embedding, Rego policies + tests, loading bundles through `BundleVerifier` |
| `internal/workflow` | Command handlers, River jobs (timeouts, expiries, execution), re-check before execution, independence and quorum checks |
| `internal/projection` | Read models for the UI (queue, incidents, overview, audit search) |
| `internal/ledger` | Hash chain, checkpoint candidates, chain format spec |
| `internal/api` + `cmd/ratchetd` | ConnectRPC handlers, sessions, RATCHET's own authorization, fake mode, embedding the built UI |
| `internal/connector/conformance` | Test suite every connector must pass (a fake control plane) |

### 8.2 Half B: Trust, Edges & Experience, owned by **Sakar**

*"Prove who approved what, keep the rules out of attackers' reach, connect to real systems, and make it all understandable."*

| Module | Responsibility |
|---|---|
| `web/` | The entire console: Overview, Infrastructure Map, Change Review, Impact Simulator, Security Policy, Incident Containment, Audit & History |
| `internal/canon` | RFC 8785 canonicalisation + SHA-256 digest (Go), matching TS implementation, shared golden vectors |
| `internal/approval` | Passkey enrollment and assertion verification (`ApprovalVerifier`), HTTP handlers mounted into `ratchetd` |
| `internal/trust` + `cmd/ratchet-authority` | Independent Authority: genesis, approver registry, M-of-N bundle signing, `BundleVerifier`, checkpoint signing |
| `cmd/ratchet-sim` | Simulated crypto exchange (IAM API, audit log, seeded org, sessions) |
| `cmd/ratchet-connector` + `internal/connector/{sim,k8s}` | Connector framework, sim adapter, Kubernetes adapter + admission webhook, drift watch, priority containment consumer |
| `cmd/ratchetctl` | CLI: `genesis`, `policy sign`, `audit verify` |
| `e2e/` | Attack-scenario scripts and Playwright end-to-end tests |

### 8.3 Shared: both must approve any change

| Path | Contents |
|---|---|
| `proto/` | All ConnectRPC services and NATS message schemas |
| `internal/ports/` | Go interfaces that cross the boundary (§9.2) |
| `testdata/` | Shared fixtures: seeded org, sample changes, expected impact diffs, canonicalisation vectors |
| `deploy/compose/` | `docker-compose.yml` for the whole system |
| `.github/` | CI workflows, CODEOWNERS, PR template |
| `PRD.md`, `RATCHET_Architecture.md` | These documents |

### 8.4 Why this split doesn't break

- **No shared files outside the shared paths.** Each person owns separate directories, so there are no merge conflicts in day-to-day work.
- **Each half can run without the other from day one.** Half A develops against `testdata/` fixtures and the conformance fake. Half B develops against `ratchetd --mode=fake` (fixture-backed API) and the simulator.
- **Contracts are frozen early and checked automatically.** `buf breaking` blocks incompatible API changes. Contract tests and golden vectors fail CI if either side drifts.
- **Load is balanced.** Each half is about 11–12 person-weeks of work (architecture estimates).

---

## 9. Contracts between the halves

### 9.1 Network APIs (`proto/ratchet/v1/`)

| Service | Implemented by | Consumed by | Purpose |
|---|---|---|---|
| `ChangeService` | A | B (UI) | Submit, Get, List, Approve, Reject, Hold, RequestInfo, Watch (stream) |
| `ImpactService` | A | B (UI) | Simulate a draft change → ImpactDiff |
| `GraphService` | A | B (UI) | Node details, neighbourhood, paths to critical, reach |
| `ContainmentService` | A | B (UI) | Plan (min-cut), Execute, Restore |
| `IncidentService` | A | B (UI) | List, Get, Watch |
| `AuditService` | A | B (UI, CLI) | Query, Export chain |
| `OverviewService` | A | B (UI) | Attention items |
| `DecisionService` | A | B (k8s webhook) | Inline `Decide(ChangeIntent)`, p99 < 50 ms |
| `PasskeyService` | B | B (UI), mounted in `ratchetd` | Enroll, list, revoke passkeys; begin/finish assertion |
| `AuthorityService` | B | A (`ratchetd`), B (UI, CLI) | GetActiveBundle, GetApproverRegistry, ProposeBundle, SignBundle, SignCheckpoint |
| Connector messages (`connector.proto`) | A (control-plane side), B (connector side) | Both | Over NATS: `GraphSnapshot`, `GraphDelta`, `ExecCommand`, `ExecResult`, `ObservedState`, `AuditEvent`, `DriftReport` |

**NATS subjects (frozen in Week 0):**

```
ratchet.<tenant>.ingest.sync        connector → control plane   GraphSnapshot / GraphDelta
ratchet.<tenant>.ingest.audit       connector → control plane   AuditEvent / DriftReport
ratchet.<tenant>.exec.<connector>   control plane → connector   ExecCommand (normal)
ratchet.<tenant>.contain.<connector> control plane → connector  ExecCommand (priority, reductions only)
ratchet.<tenant>.exec.results       connector → control plane   ExecResult / ObservedState
```

### 9.2 In-process Go interfaces (`internal/ports/`)

These are the only places where code from one half calls code from the other inside the same binary.

```go
package ports

// Implemented by Half B (internal/approval). Called by Half A (internal/workflow).
// Checks that the passkey assertion is valid, comes from an enrolled RATCHET passkey,
// and signs exactly changeDigest. It does NOT check independence or quorum; Half A does.
type ApprovalVerifier interface {
	Verify(ctx context.Context, sub ApprovalSubmission, changeDigest Digest) (VerifiedApproval, error)
}

// Implemented by Half B (internal/trust). Called by Half A (internal/policy).
// Checks M-of-N signatures against the current approver registry and returns
// the Rego modules and data inside the bundle.
type BundleVerifier interface {
	Verify(ctx context.Context, raw []byte) (VerifiedBundle, error)
}

// Implemented by Half B (internal/canon). Used by both halves and mirrored in TypeScript.
// RFC 8785 canonical JSON, then SHA-256.
type Digester interface {
	Digest(v any) (Digest, error)
}

// Implemented by Half B (internal/approval). Mounted by Half A (internal/api) at /api/passkeys/.
type PasskeyHandlerFactory func(deps PasskeyDeps) http.Handler
```

### 9.3 Shared fixtures (`testdata/`)

| File | Produced by | Used by |
|---|---|---|
| `testdata/orgs/exchange-v1.json` | B (from the simulator's seed) | A (graph tests), B (sim seed), fake mode |
| `testdata/changes/*.json` (Rahul → admin, ordinary report access, withdrawal-rule edit, service-account over-grant, revoke) | Both | A (workflow tests), B (UI fake data, e2e) |
| `testdata/impact/*.json`: expected ImpactDiff for each change above | A | A (golden tests), B (UI fake mode) |
| `testdata/canon/vectors.json`: input → canonical bytes → digest | B | A (Go), B (Go + TS) |
| `testdata/policies/decisions.json`: change + impact → expected decision | A | A (policy tests), B (e2e expectations) |

### 9.4 Changing a contract

1. Open a PR labelled `contract` that touches only shared paths (plus fixture updates).
2. **Changes must be additive**: new fields, new RPCs, new subjects. `buf breaking` in CI enforces this. Removing or renaming something needs a deprecation over one milestone first.
3. **The other person must approve it** (enforced through CODEOWNERS).
4. Merge the contract PR first. Then each person updates their own half in separate PRs.

---

## 10. Working agreement (Git and CI)

| Topic | Rule |
|---|---|
| **Branches** | `main` must always build and pass CI. Work on `ishaan/<topic>` or `sakar/<topic>`. Keep branches short-lived (≤ 3 days); rebase on `main` before merging. |
| **Pull requests** | One concern per PR. PRs inside your own half: merge once CI is green (a review is welcome but optional, for speed). PRs touching shared paths: the other person must review. |
| **Commits** | Conventional Commits: `feat(graph): add ControlSet`, `fix(web): …`, `test(policy): …`, `docs: …`. Authored by Ishaan or Sakar only. |
| **CODEOWNERS** | Half A paths → Ishaan, Half B paths → Sakar, shared paths → both. Sakar (repo admin) enables branch protection on `main`: require PRs, passing CI and CODEOWNERS review. |
| **CI gates** | `go vet`, `golangci-lint`, `go test -race ./...`, `buf lint` + `buf breaking`, `opa test policies/`, connector conformance suite, canonicalisation vectors (Go + TS), web typecheck, lint and Vitest, `docker compose` smoke test. Playwright e2e from Milestone 2 onward. |
| **Fake modes** | `ratchetd --mode=fake` serves every Half-A API from `testdata/`, so the UI never waits on the backend. `ratchet-sim` plus the conformance fake let the connector be built without the real control plane. |
| **Integration** | At the end of every milestone, `main` must pass that milestone's demo script (§11) with real components and no fakes. |
| **Sync** | A 15-minute check-in twice a week. Contract questions are raised as GitHub issues labelled `contract`. |

---

## 11. Milestones and timeline

Week numbers count from the day you start. Each milestone ends with a joint integration demo on `main`.

### M0: Foundations (Week 1, **together**)

| Ishaan | Sakar | Joint output |
|---|---|---|
| Repo skeleton, Go module, `ratchetd` health check, Postgres + NATS in compose, CI pipeline | `web/` scaffold (Vite, React, Tailwind, shadcn), simulator domain sketch, `internal/canon` + vectors | **All `proto/` files v1, `internal/ports`, NATS subjects, `testdata/` seed org and changes, CODEOWNERS, branch protection** |

**Exit:** both halves compile against the frozen contracts, and CI is green.

### M1: "RATCHET sees the organisation" (Weeks 2–3)

| Ishaan | Sakar |
|---|---|
| Event store + outbox + relay; ingest consumer; graph engine (Reach, PathsTo, ImpactDiff, ControlSet); `GraphService`, `ImpactService`; **fake mode ready by end of Week 2** | `ratchet-sim` with the seeded exchange; connector framework + sim adapter `Sync`; passes conformance `sync` tests; Infrastructure Map + Impact Simulator screens |

**Demo:** the simulator's org appears in the Map, and simulating "make Rahul an admin" shows the new wallet-signer access and tier-0 routes. → **D3**

### M2: "Changes are decided" (Weeks 4–5)

| Ishaan | Sakar |
|---|---|
| Domain state machine; OPA + demo policies (FR-P2); River jobs; `ChangeService`, `OverviewService`; read models; execution flow + read-back check | Change Review + Overview + request form screens; connector `Execute` / `Verify` for the sim (broker mode); passkey enrollment (`PasskeyService`) |

**Demo:** an ordinary report-access request is allowed, executed in the sim and verified; an admin request lands in "Awaiting independent approval". → **D1, D2**

### M3: "Nobody approves themselves; the rules are protected" (Weeks 6–7)

| Ishaan | Sakar |
|---|---|
| Independence and quorum checks using ControlSet; re-check before execution; load policies only through `BundleVerifier`; reject safeguard weakening | `ApprovalVerifier` (passkey signs the digest; the browser recomputes the digest it displays); `ratchet-authority` genesis + M-of-N signing; Security Policy screen; `ratchetctl genesis` / `policy sign` |

**Demo:** Rahul's stolen session can't approve its own escalation; an approver Rahul can take over is refused; editing the withdrawal rule is rejected and only possible through Authority quorum. → **D4, D5**

### M4: "Contain and prove" (Weeks 8–9)

| Ishaan | Sakar |
|---|---|
| Monotonic-reduction fast path; min-cut containment plan; `ContainmentService`, `IncidentService`; hash-chain ledger + checkpoint candidates; `AuditService` | Incident Containment + Audit & History screens; priority containment consumer + session revocation in the sim; Authority checkpoint signing; `ratchetctl audit verify` |

**Demo:** the full Rahul scenario (idea doc §10) from attack to surgical containment. His finance reports keep working; the audit chain and every approval verify offline. → **D6, D7, D8**

### M5: "Real infrastructure" (Weeks 10–11)

| Ishaan | Sakar |
|---|---|
| `DecisionService` performance (p99 < 50 ms); drift → auto-revert + incident; benign-traffic replay harness to measure false positives; OpenTelemetry tracing | Kubernetes adapter on `kind` (RBAC sync, admission webhook, drift watch); all attack scenarios (FR-K6); Playwright e2e suite |

**Demo:** a real Kubernetes RoleBinding escalation is blocked by RATCHET, and an out-of-band change is reverted within seconds. → **D1–D8 on real infrastructure**

### M6: Hardening and demo (Week 12, **together**)

Bug bash, emergency access (FR-E*) if not done yet, deployment to the Oracle free VM, README, demo script, recorded walkthrough.

---

## 12. Demo acceptance checklist

| # | Scenario (`e2e/scenarios/`) | Backend owner | Edge / UI owner | Pass condition |
|---|---|---|---|---|
| D1 | `ordinary_access` | Ishaan | Sakar | Request allowed → executed → verified in the sim; requester sees the decision |
| D2 | `rahul_admin_request` | Ishaan | Sakar | State = awaiting approval, quorum 2, reasons listed |
| D3 | `rahul_admin_request` (impact) | Ishaan | Sakar | UI shows wallet-signer and the new tier-0 paths, matching `testdata/impact` |
| D4 | `self_approval`, `controlled_approver` | Ishaan | Sakar | Both approvals refused with a clear reason; no state change |
| D5 | `withdrawal_rule_edit` | Ishaan | Sakar | Rejected via the control plane; succeeds only with an M-of-N Authority bundle |
| D6 | `contain_rahul` | Ishaan | Sakar | Verified revocation in < 5 s |
| D7 | `contain_rahul` (continuity) | Ishaan | Sakar | Finance-report access still works after containment |
| D8 | `audit_verify` | Ishaan | Sakar | `ratchetctl audit verify` passes; tampering with one row makes it fail |

---

## 13. Success metrics (idea doc §21)

| Metric | v1 target (demo dataset) |
|---|---|
| Unauthorised privilege increases prevented in attack scenarios | 100% of FR-K6 scenarios |
| Dangerous policy changes stopped before taking effect | 100% |
| Legitimate requests wrongly delayed or rejected (benign replay) | Measured and reported; target < 5% |
| Tier-0 assets reachable from a compromised ordinary account, before vs after RATCHET-recommended containment | Before: reported; after: 0 |
| Time to verified revocation | < 5 s |
| Unrelated activities preserved during containment | Reported per scenario; target > 90% of the identity's non-critical access |
| Decision explainability | Every decision has ≥ 1 human-readable reason and a policy hash |
| Audit completeness | 100% of decisions in the chain; `verify` passes |

We will also test against realistic benign activity, not only scenarios RATCHET was written to block (idea doc §21).

---

## 14. Risks and mitigations

| Risk | Mitigation |
|---|---|
| The halves drift apart and integration breaks late | Contracts frozen in M0, `buf breaking`, golden fixtures, fake modes, integration demo at every milestone |
| The graph engine takes longer than planned (the hardest single piece) | Build Reach and ImpactDiff first (M1); add min-cut in M4; a naive reference implementation keeps tests going |
| Passkeys are fiddly across browsers | Develop with Chrome's virtual authenticator; Playwright uses one too |
| The Kubernetes connector slips | It is the M5 stretch goal; D1–D8 are already proven on the simulator by M4 |
| Free-tier VM unavailable | Run locally with Cloudflare Tunnel for demos |
| Over-strict policies block legitimate work (idea doc §22.3–22.4) | Benign replay metrics; HOLD instead of REJECT where the context is unclear; emergency access flow |
| RATCHET itself gets compromised (idea doc §22.2) | Separate Authority trust domain, M-of-N signatures, verifiable ledger |
| Repo is public | No secrets in Git (SOPS + age only); demo data is fictional |

---

## 15. Out of scope for v1

Real IdP or cloud-IAM connectors (Okta, Entra, AWS, GCP) · multi-tenant production hosting · SSO login · break-glass credentials (FR-X6) · external audit witness (FR-L5) · AI features of any kind · fraud or transaction monitoring.

---

## 16. Glossary

| Term | Meaning |
|---|---|
| **Blast radius** | Everything that could be affected if an account, service or permission were misused |
| **Tier-0** | The most critical assets (e.g. wallet signing, security policy, admin control) |
| **Control set** | The identities a given identity can take over, directly or indirectly |
| **Impact diff** | The difference in reach before and after a proposed change |
| **Safeguard** | A security control (e.g. withdrawal approval rule), modelled as an asset that can be weakened |
| **Authority quorum (M-of-N)** | At least M of the N registered security leaders must sign to change the rules |
| **Change digest** | A SHA-256 fingerprint of the canonical change; what the approver's passkey signs |
| **Broker mode** | Only RATCHET holds the credentials that can change a target system's IAM |
| **Fake mode** | `ratchetd` serving fixture data, so the UI can be built before the backend is finished |
