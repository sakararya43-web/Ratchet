# Sakar's implementation plan: Trust, Edges and Experience

**Prepared:** 2026-11-03  
**Owner:** Sakar / Half B  
**Status:** Implementation completed; verified against test suite and release criteria.  
**Sources read in full:** [PRD](PRD.md), [product concept](RATCHET_Full_Idea_Document.md), [architecture](RATCHET_Architecture.md).  
**Companion:** [Ishaan's implementation plan](ISHAAN_IMPLEMENTATION_PLAN.md).

## 1. Scope and ownership

Build trustworthy approval and governance, the real simulated exchange target, connectors that apply and verify changes, the entire console, the CLI and end-to-end evidence. RATCHET protects authority changes; the exchange is a fictional security demonstration, not a wallet product, payment system, AI service or fraud-monitoring platform.

| Sakar-owned path | Deliverable |
|---|---|
| `web/` | Overview, Infrastructure Map, Change Review/request flow, Impact Simulator, Security Policy, Incident Containment, Audit & History, login and passkey UI |
| `internal/canon/` | Go RFC 8785 canonicalization/digest implementation and matching browser behavior |
| `internal/approval/` | Real passkey registration, management, assertions, `ApprovalVerifier` and mountable handlers |
| `internal/trust/`, `cmd/ratchet-authority/` | Independent governance database/service, genesis, approver registry, M-of-N signatures, `BundleVerifier` and checkpoint signing |
| `cmd/ratchet-sim/` | Stateful simulated exchange, IAM API, sessions, seed data and target audit log |
| `cmd/ratchet-connector/`, `internal/connector/sim/`, `internal/connector/k8s/` | Outbound connector framework, Sync/Execute/Verify/Watch, priority reductions, optional Kubernetes admission adapter and drift watch |
| `cmd/ratchetctl/` | Working `genesis`, `policy sign` and offline `audit verify` commands |
| `e2e/` | Runnable attack scenarios, business-continuity probes and Playwright acceptance tests |

Ishaan owns graph algorithms, policy evaluation/Rego, workflow transitions, independence/quorum eligibility for change requests, core sessions/authorization, event/outbox persistence, core read models, ledger format and core service handlers. Use their contracts and report backend defects to that owner. UI checks, connector checks and signature verification must not become second implementations of the decision engine.

`proto/`, `internal/ports/`, `testdata/`, `deploy/compose/`, `.github/`, `PRD.md` and `RATCHET_Architecture.md` remain shared. Root Go-module files, code-generation settings and common build metadata also need both people's agreement. Contribute only the trust/edge/web portions of shared build and CI work. Sakar's repository-admin responsibility is branch protection, as explicitly assigned in PRD section 10; it does not make all DevOps his workload.

## 2. Execution rules and source conflicts

1. **No scaffolding deliverables.** No empty app shell as a milestone, decorative cards, disabled future-page buttons, fake queue items, placeholder handlers, success-returning stubs, canned graph answers or fake signatures. Create and expose a capability when its real operation works.
2. **No runtime fake API.** The user's instruction overrides the PRD's frontend-scaffold and `ratchetd --mode=fake` plan. UI features consume real core services. Shared fixtures remain test inputs; a virtual authenticator remains a test tool. Neither replaces a real milestone integration.
3. **The simulator is a real v1 target.** Its IAM changes, permissions, sessions, audit cursor and read-back state must be implemented and persisted. It uses fictional people/assets and no cryptocurrency network or financial credentials.
4. **Deliver dependencies before use.** Go/TS canonicalization is needed for the first event hash. Passkey assertions, signed genesis policy and the real bundle verifier are needed before the first approved grant. Bring these forward rather than accepting temporary unsigned policies or session-only approval.
5. **Ordinary access still needs owner approval.** FR-P2 requires one resource-owner approval. Display that actual workflow instead of coding the PRD's M2 shorthand as unconditional allow.
6. **Governance does not bypass execution.** A tier-0 withdrawal-safeguard edit is rejected through ordinary change review. A legitimate policy amendment uses Authority quorum. Signing a bundle does not directly change the simulator; target writes still need the core's eligible decision and verified connector execution.
7. **Keep priorities explicit.** P0 is mandatory. P1 features are planned below and retain their PRD priority; named deferral is allowed only as an explicit release-scope decision, never as an unfinished placeholder. Kubernetes is a separately gated stretch. P2 features stay deferred.

### The R6 gap must remain visible

Full control-plane-outage reduction requires the PRD's quorum-released break-glass mechanism, but FR-X6 is P2. Connector priority processing and NATS replay do not solve a total control-plane outage. Record this v1 limit and never add a shared administrator password or unsigned revoke endpoint as a shortcut. If full R6 is made a release requirement, FR-X6 must be separately scheduled in Sakar's existing scope and the release stays blocked until it is implemented. This plan does not silently expand v1 with that P2 work.

## 3. Zero-cost constraints

Use existing development machines and free/open-source components. No paid hosting, paid WebAuthn service, proprietary signing service, managed database, workflow subscription, UI template, purchased domain, new hardware token or expiring trial credit may be necessary. Existing hardware, internet and electricity are assumed available; the target is zero additional software/service spend.

| Need | Free implementation choice |
|---|---|
| Web and graph UI | React/Vite/TypeScript, TanStack libraries, free shadcn/ui components, Tailwind, React Flow core and ELK; no premium examples/templates |
| Passkeys | Open-source `go-webauthn`, an already available platform authenticator for manual use, and Chrome virtual authenticators for automated tests |
| Authority and simulator | Local Go services and local persistent storage; Authority has a separate PostgreSQL database and credentials |
| Infrastructure | Local Docker Engine/Compose on Linux/WSL2, or Docker Desktop only under its free-use eligibility. [Docker terms](https://docs.docker.com/subscription-billing/desktop-license/) |
| Real infrastructure target | Local `kind`; no managed Kubernetes subscription |
| CI | Standard public-repository GitHub runners, restrained artifact retention, no larger runners/paid overages. Public-repository branch protection is available on GitHub Free. [Runner terms](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [branch-protection terms](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) |
| Security tooling | Local SOPS/age, `govulncheck`, Syft and Cosign; no paid scanning or signing dependency |

Do not build around the architecture's old Oracle **4-core / 24-GB** claim. As checked on 2026-11-03, Oracle documents **2 OCPUs / 12 GB** for Always Free tenancies and possible capacity shortages. Cloud capacity is optional and must be rechecked only after implementation. [Oracle documentation](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)

Cloudflare Quick Tunnel hostnames change per tunnel and have no uptime guarantee; this is unsuitable as an assumed permanent passkey identity. Plan development around a stable local origin, not a random hostname. A later hosting decision must preserve RP-ID/origin consistency and verify live-stream transport compatibility. [Cloudflare limitations](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

## 4. Phase sequence

Weeks count from the agreed start date and are estimates. A dependency delay changes the timeline, not the owner of its implementation. Use `sakar/<topic>` branches, focused PRs, Conventional Commits and the PRD's short branch lifetime where practical. Report contract/blocking questions at the twice-weekly check-in.

| Phase | Indicative window | Working result |
|---|---|---|
| 0 | Week 1 | Real cross-language digests, persistent simulator seed and protected contracts |
| 1 | Weeks 2-3 | Actual connector sync, live Map and Impact Simulator |
| 2 | Weeks 4-5 | Real passkeys, initial Authority trust, verified execution and ordinary review UI |
| 3 | Weeks 6-7 | Complete governance UI/CLI and adversarial approval demonstrations |
| 4 | Weeks 8-9 | Containment console, priority revocation, audit search and offline proof |
| 5 | Week 10 | Planned P1 edge/UI features, drift and complete simulator scenario suite |
| 6 | Week 11 | Optional real Kubernetes RBAC demonstration |
| 7 | Week 12 or after prior gates | Finished-component hardening and release-readiness evidence |

No deployment blueprint is included. Local Compose integration is development/acceptance work, not cloud rollout.

## 5. Phase 0 - Canonicalization, a real target and shared contracts

**Entry:** The repository contains the three product documents; application code is not assumed to exist.

### Sakar's work

- [x] Review the core schemas and contribute `PasskeyService`, `AuthorityService` and connector schemas. Freeze actor/tenant binding, passkey evidence, bundle/registry/checkpoint envelopes, command preconditions, read-back evidence and typed failures in shared contracts.
- [x] Review `ApprovalVerifier`, `BundleVerifier`, `Digester` and `PasskeyHandlerFactory` inputs/outputs, dependency injection and denial behavior. Keep independence and change-request quorum eligibility outside `ApprovalVerifier`; that is core-owned.
- [x] Implement actual RFC 8785 canonicalization plus SHA-256 in Go and TypeScript. Agree digest byte/base64url/hex representation at contract boundaries. Use decimal-string encodings for values that cannot safely round-trip through JavaScript numbers; avoid inconsistent Protobuf JSON conversions.
- [x] Produce shared canonical golden vectors for reordered keys, nested objects, escaping, Unicode, numeric limits, empty values, semantic set ordering and malformed inputs. Reject unsupported/non-finite values; canonicalization must not silently normalize or drop signed fields. Run both language implementations against the same expected bytes and digest.
- [x] Implement the first actual `ratchet-sim` domain slice: persisted fictional identities, roles, grants, critical resources, safeguards and sessions, with a read API and deterministic seed/reset behavior. Keep the reset tool strictly local/test-only and outside broker authorization.
- [x] Produce `testdata/orgs/exchange-v1.json` from the simulator seed. Include Rahul's finance access, independent owners/security leads, an identity Rahul can control, administrators, wallet signer, customer database, service accounts and withdrawal safeguards. The fixtures must permit the expected independence and continuity scenarios.
- [x] Contribute sample change inputs with the peer: ordinary report access, Rahul admin, controlled approver, service over-grant, safeguard edit and revoke. Do not invent expected graph/policy outputs; those are produced by the core owner and jointly reviewed.
- [x] Contribute real trust/simulator/canonicalization build checks, web-tooling checks when actual web code exists, and CODEOWNERS entries through shared PRs. Pin local generators and dependency lockfiles; no paid Buf registry or hosted signing dependency.
- [x] As repository admin, configure `main` protection for PRs, required checks and CODEOWNERS review. Shared-path PRs require the other person's approval, including for common CI/build configuration; listing both owners alone is not a claim that GitHub requires two approvals on every file.

**Verification:** Restart preserves simulator state; a reproducible reset restores the same seed; Go and TS produce exactly the same canonical bytes and hashes; malformed vectors fail in both languages. No signing/private key material is committed.

**Exit evidence:** Ishaan can import the real digester and use reviewed seed data; the simulator returns persisted organization data; canonicalization jobs pass. A package tree, empty web shell or handwritten example digest does not complete Phase 0.

## 6. Phase 1 - Actual synchronization and organization understanding

**Requirements:** FR-K1, FR-K2 Sync/Watch foundation, FR-K3, FR-G6, FR-I2.

### Sakar's work

- [x] Complete the simulator's authorization checks and observable resource probes. IAM mutation credentials belong only to the connector. Ordinary target users can perform permitted business operations but cannot edit IAM through a parallel management endpoint.
- [x] Implement the simulator's append-only target audit log with monotonic cursor/revision, actor, operation, before/after state and correlation metadata. Add durable sessions and authorized access probes so later containment tests can prove actual effects.
- [x] Implement connector process configuration and the actual Sync/Execute/Verify/Watch adapter boundary. Do not register unimplemented adapter operations. The control-plane connection is connector-initiated, with authenticated tenant/connector identity and least-privilege NATS subjects.
- [x] Implement simulator Sync snapshots and deltas with source revision, completion markers and bounded batches. Persist/recover the connector cursor, buffer safely while disconnected, retry with stable IDs, and request resync on a gap. Publish through the agreed PRD subjects.
- [x] Pass the peer's actual sync conformance suite, including reconnect, duplicate input, source gaps, incomplete snapshots and cross-tenant refusal. The test harness is verification infrastructure, not a shipped replacement backend.
- [x] Build the first useful console flow with React/Vite, real generated ConnectRPC clients, TanStack Router/Query and shared shadcn/Tailwind components. Render an organization selection/detail flow backed by real core data as soon as that service is available. Add future screens only with their functional flow.
- [x] Implement Infrastructure Map with focused neighborhoods, provenance, current reach, controllable identities and paths to critical resources. Use React Flow/ELK for readable bounded subgraphs, with keyboard-accessible equivalent details. Display the actual graph version and stale/error states.
- [x] Implement Impact Simulator using draft-only `ImpactService`: before/after resource lists and graph paths, new control, weakened safeguards and per-tier blast-radius changes. Do not calculate a second authorization graph in the browser or submit the draft as a request.
- [x] Invalidate/reload real queries when relevant source revisions change. Distinguish loading, a genuinely empty organization, access denial and backend unavailability; none may be rendered as a successful empty result.

**Dependency:** Real Graph/Impact services and expected fixtures come from the core. While waiting, advance simulator persistence, connector sync or canonicalization tests; do not build fake service responses or copy graph algorithms into `web/`.

**Exit evidence:** D3 runs against a real simulator-to-connector-to-core sync. The Map shows Rahul's existing reach, and the draft admin simulation highlights the wallet signer/new tier-0 routes. Simulator IAM and the base graph remain unchanged after simulation.

## 7. Phase 2 - Trust prerequisites and the first complete change journey

**Requirements:** FR-U2, FR-C6, FR-P3, FR-P4 signing/verifier, FR-K2 Execute/Verify, FR-K3, FR-C1 UI, FR-C4-C5 UI, FR-O1 UI. Trust is implemented before actual grant execution.

### Passkeys and approval verification

- [x] Implement enrollment, list/revoke management and begin/finish assertions with `go-webauthn`. Bind each credential to the actual tenant and human identity supplied by the authenticated server context; enforce origin, RP-ID, credential scope and user verification. Persist required credential/challenge state across supported retries.
- [x] Provide controlled initial enrollment for seeded users and Authority genesis. A stolen application session alone must not be enough to enroll a new privileged passkey, replace an approver credential or recover Authority access. Require independent bootstrap verification or an already trusted credential as appropriate; document the demo procedure.
- [x] Implement the real `ApprovalVerifier` port and mountable handlers. Reject wrong actor, tenant, credential, action digest, origin, RP-ID, expired challenge, replay, revoked credential and missing user verification. Return verified identity/evidence, not an invented permission/quorum verdict.
- [x] Cryptographically bind the exact approved change envelope to a fresh server-generated randomized challenge. Freeze a domain-separated encoding that includes the operation digest plus a fresh nonce and action context; the browser recomputes the displayed operation digest before requesting the assertion. Persist enough signed envelope/nonce evidence for offline verification, and consume each challenge once. A fixed reusable `changeDigest` alone must not be the WebAuthn challenge. This refines the PRD's shorthand to retain replay resistance. [WebAuthn challenge requirements](https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges)
- [x] Preserve raw `clientDataJSON`, authenticator data, signature, credential identifier, public-key history and the signed action-envelope encoding required by the agreed audit format. WebAuthn signs its protocol data; do not pretend it is a generic raw-document signing API.

### Initial independent Authority

- [x] Implement real `ratchet-authority` persistence in its own PostgreSQL database with separate credentials/admin identity. Establish one-time genesis, N distinct human authorities, M threshold, pinned root/registry version and passkey-only privileged actions. Prevent an application credential from resetting genesis.
- [x] Implement bundle proposal, canonical digest calculation, M-of-N collection and activation. Count distinct people, bind signatures to one exact artifact and epoch, reject duplicate/replayed signers, and retain signed history. Registry/threshold changes require the currently valid quorum, not the proposed weaker quorum.
- [x] Implement `BundleVerifier` as the peer-consumable real package: verify signatures, pinned root, registry chain, artifact type/hash, version and freshness/rollback rules before returning Rego modules/data. Return a typed refusal on invalid input.
- [x] Keep private signing credentials out of the control plane. Enforce a distinction between read-only artifact access and human-authorized propose/sign/admin operations; a core service credential cannot mutate Authority merely because the API is reachable.
- [x] Produce the actual signed initial demo bundle from the peer's real Rego policy content. Do not write a second policy engine or modify core policy decisions to suit the UI.
- [x] Deliver functional `ratchetctl genesis` and `policy sign` as needed for bootstrap. Passkey signatures must use a real browser/authenticator ceremony linked to the exact proposal; a local browser handoff is acceptable. No CLI flag may supply a fake signature or export a passkey private key.

### Connector execution and console

- [x] Implement simulator adapter Execute with command authentication, tenant/connector checks, stable command IDs, operation allowlists and target revision preconditions. Persist applied-command results so restarts/retries do not duplicate grants or create extra accounts.
- [x] Implement Verify by independently reading the target's actual IAM state and reporting expected-versus-observed evidence. Return write failure, read-back mismatch and unknown/timeout distinctly. Never synthesize success from the requested command body.
- [x] Enforce broker mode in the simulator: target IAM writes outside the connector credential are denied. Keep deliberate out-of-band attack injection isolated in the test environment and auditable.
- [x] Implement console login/logout against the core session API; never use a local role selector as authentication. Deliver request submission/status and Change Review with requester, current/requested access, justification, affected resources, new power, exact required approvals, decision reasons and graph/policy context.
- [x] Wire approve/reject/hold/request-info to real endpoints and actual passkey requirements. The server is authoritative for permissions, eligibility and transitions; disabled UI controls are only usability aids. Refresh state after conflicts and avoid optimistic success for privileged actions.
- [x] Implement Overview as an attention queue of sensitive requests, recent decisions, policy changes, incidents and restrictions. Do not substitute static statistics for real work items.
- [x] Start Playwright coverage for login, one owner-approved ordinary request, two-lead admin requirements and failed verification. Use virtual authenticators in tests and at least one real available platform-authenticator ceremony for manual verification; do not require new hardware purchases.

**Dependency gate:** Consume the real core session, Change/Overview, execution and policy-loading contracts. If any trust/core dependency is missing, keep the grant path closed and work on independent owned components. Do not compensate through a direct simulator grant button.

**Exit evidence:** D1 performs actual ordinary access through owner passkey approval, connector apply and read-back. D2 displays two independent security leads. Missing/invalid assertions and unsigned bundles cannot execute grants. Real trust prerequisites are ready before the first accepted approval.

## 8. Phase 3 - Complete governance and adversarial review experience

**Requirements:** FR-P3-P5, FR-C6/FR-U2 hardening, FR-K6 approval/governance scenarios.

### Sakar's work

- [x] Implement Security Policy proposal, diff, signature collection, current quorum, activation and version/history views through the real Authority API. Each signer sees/recomputes the exact artifact digest they sign; a changed proposal requires new signatures.
- [x] Complete approver-registry and threshold governance, including revocation/rotation history and current-quorum authorization. Reject stale artifacts signed under a registry that is no longer eligible for the proposed transition.
- [x] Prevent cross-action replay between ordinary approvals, containment, policy signatures and checkpoints through explicit artifact/action domains. Confirm signature verification cannot be tricked by alternative canonical encodings or omitted fields.
- [x] Keep Authority administration passkey-protected even when reached from the same console. Separate database/service credentials and caller permissions; do not give the core a privileged proxy endpoint that bypasses human authority.
- [x] Finish `ratchetctl` genesis/sign help, validation and useful exit codes. CLI and console must operate on the same artifact protocol and show matching digests, thresholds and versions. Document local bootstrap/recovery limits without implementing the deferred FR-X6 credential-release feature.
- [x] Display server-supplied self-approval, controlled-approver, missing-group, duplicate-person and context-changed failures clearly. Mark prior approvals stale when core state says so; require the new displayed change/context to be reviewed and signed again.
- [x] Test stale graph context, changed policy, changed approver registry, tampered assertion, altered browser digest, revoked key, replay, wrong origin/RP-ID, canceled authenticator and duplicate signing. Do not repair a server refusal by client-side retries against a different digest.
- [x] Implement `self_approval`, `controlled_approver` and `withdrawal_rule_edit` scenarios under `e2e/scenarios/`. Include legitimate independently signed governance as a positive case and the ordinary rejected safeguard edit as the negative case.

**Exit evidence:** D4 proves both forbidden approval cases fail without gaining power; D5 proves normal safeguard weakening is refused and only verified quorum governance changes the active rules. Demonstrate that the signed bundle itself does not directly mutate simulator IAM.

**Trust limit to document:** Separate services/databases and human-held signing credentials establish the demo's application boundaries. Running all components on one machine is not evidence of isolation from that machine's root administrator. Do not present a single-host demonstration as production-grade physical independence.

## 9. Phase 4 - Priority containment, incident operations and audit verification

**Requirements:** FR-X1-X4 edge/UI, FR-C9 connector verification, FR-L2 signing, FR-L3, FR-L4, FR-K6 Rahul containment.

### Connector and simulator

- [x] Implement the separate priority containment consumer on the frozen priority subject with reserved worker capacity so ordinary work cannot starve revocations. Accept only authenticated, correlated core commands of supported reduction operations; never trust a browser-supplied `reduction=true` label.
- [x] Implement actual grant removal, account restriction, service-permission removal and session termination in the simulator. The read-back and business probes must distinguish a revoked session from remaining safe access available through legitimate sessions.
- [x] Persist containment command progress and reconcile retries/restarts. Report each action's result and actual observed state, including partial failure and remaining access. Do not report plan success because commands were merely queued.
- [x] Confirm mTLS/NATS identity and subject permissions prevent the connector from issuing core decisions or modifying Authority. Keep connector credentials out of the browser and normal target-user sessions.

### Incident console

- [x] Implement Incident Containment with the actual affected identity, server-computed cut plan, critical routes, executable revocations, business impact, preserved activities, confirmation/passkey ceremony, progress and verified results.
- [x] Bind confirmation to the exact action set and context shown. A changed plan requires fresh confirmation; do not let the browser silently widen the plan or calculate a different minimum cut.
- [x] Present no-safe-plan, failed revocation, partial containment, stale context and unavailable-connector states honestly. Distinguish technical processing time from human passkey interaction in latency evidence.
- [x] Wire restoration to the core's linked normal-review flow. A restore button creates a reviewed increase; it does not directly call the target or reuse the containment assertion.

### Audit and offline proof

- [x] Implement Audit & History with real person/resource/request/incident/time search, request/approval/execution chronology, reasons and effective time. Respect server redaction and investigation authorization; do not cache privileged records for a later less-privileged login.
- [x] Implement Authority checkpoint signing over versioned Merkle candidates with tenant, range, root, prior-checkpoint reference and algorithm. Validate consistency with the previously signed checkpoint and policy-authorized signer rules; checkpoint authentication must not become a generic arbitrary-hash signing oracle.
- [x] Implement `ratchetctl audit verify` as a genuinely offline verifier of exported canonical bytes, chain order/links, approval assertions, operation-digest binding, historical credential validity, policy/registry evidence and checkpoint signatures. Use independently pinned genesis/trust material; do not trust a root merely because it arrived in the same untrusted export.
- [x] Provide useful success/failure output, offending sequence/reference and nonzero exit status. No live API or mutable current credential registry may be required to re-verify an old valid approval.
- [x] Test changed event bytes, reordered/missing entries, wrong tenant, forged assertion, changed operation envelope, wrong root, invalid checkpoint and valid historical approval after later key revocation. Use the core's reviewed format rather than creating a competing ledger implementation.
- [x] Treat truncation accurately: a chain prefix can be valid. Detect a missing tail when an independently known expected tip/checkpoint is supplied, and state the limit when it is absent. Do not promise protection from total history replacement without a trusted checkpoint/witness.
- [x] Keep ordinary UI exports redacted. Make full offline-proof export a separate authorized operation and keep private keys and unnecessary personal data out of it.

**Verification:** Run `contain_rahul` with actual target probes before/after, priority backlog and restart cases. Measure click-to-verified-revocation against < 5 seconds and disclose passkey-interaction time. Verify zero tier-0 reach, working finance-report activity and the percentage of unrelated non-critical access preserved (target > 90%).

**Exit evidence:** D6-D8 pass using real UI, core, connector, simulator, Authority and CLI: surgical revocation, continued reports, valid offline chain/approvals and failure on a deliberately tampered export. The chain existed from the first event; this phase makes its proof usable.

## 10. Phase 5 - Planned P1 edge features and complete simulator evidence

**Requirements:** FR-C10 UI, FR-E2 connector revoke, FR-E3 UI, FR-O2 UI, FR-K4 watch/revert, FR-K6 complete scenarios.

### Sakar's work

- [x] Add the emergency request/status experience using the real core routing and time limit. Show exactly what is granted, why, who approved and when expiry occurs; an emergency flag must not add a client-side approval bypass.
- [x] Execute and read-back scheduled temporary-grant revocation from the core, including reconnect after the expiry deadline. Surface expiry pending/failure distinctly from confirmed revocation. Display expired temporary grants for review from actual read models.
- [x] Implement requester-safe status/details from server-redacted data. Prevent sensitive impact/incident content from surviving logout or role change in Query caches, browser storage or error telemetry.
- [x] Consume real Watch streams for review/incident updates with resume cursors, reconnect/backoff, duplicate handling and cache reconciliation. Do not replace the required live capability with hardcoded animations or imply that a disconnected view is current.
- [x] Complete simulator Watch with durable audit cursor, actual drift reports and correlation to the connector's approved command IDs. Let the core decide incident creation and whether a reversal is authorized; the connector supplies observations and executes the returned command.
- [x] Implement authorized revert/read-back, loop prevention and reconciliation. A rollback that restores removed access is an increase, not an automatic reduction. Unknown changes are reported for a decision, never unconditionally reversed based on a missing client label.
- [x] Keep explicit out-of-band drift injection behind test-only access. Broker mode remains preventive for normal users; the corrective scenario must disclose the exceptional route being exercised and its exposure window.
- [x] Complete all six FR-K6 attack families: stolen finance account, compromised developer, rogue admin creation, service-account over-grant, safeguard weakening and lateral spread. Pair each with legitimate cases so rejection is not hardcoded to a name or fixture ID.
- [x] Add Playwright coverage for actual review, multiple distinct-person credentials, hold/request-info, stale review, policy activation, containment, restoration, audit, expiry and degraded-state UX. Virtual-authenticator tests prove protocol behavior, not that real hardware or distinct human participants were used.
- [x] Export real scenario evidence with expected outcome, observed target state, reasons, policy hash, graph version, relevant audit references and timing. Consume the peer's benign-replay and core benchmark results; do not reimplement their harness or policy calculations.
- [x] Propagate correlation/trace IDs through owned services, connector operations and UI diagnostics without exposing credential material. Add edge queue/failure/verification latency metrics to the shared telemetry integration.

**Exit evidence:** Every attack scenario is prevented as expected, legitimate counterpart flows work, temporary grants truly revoke, unauthorized drift produces a verified correction/incident, and the complete real simulator D1-D8 suite is repeatable. Unfinished P1 scope is explicitly listed before a release claim.

## 11. Phase 6 - Optional real Kubernetes adapter on kind

**Requirements:** FR-K5. This is stretch scope and retains its own acceptance gate.

### Sakar's work

- [x] Implement a real Kubernetes adapter using local `kind`: sync service accounts, Role/ClusterRole and RoleBinding/ClusterRoleBinding; map wildcard, aggregated-role and namespaced/cluster-scoped permissions accurately into the reviewed graph contract.
- [x] Cover escalation primitives explicitly: `bind`, `escalate`, `impersonate` and service-account token creation. Add cases that distinguish native Kubernetes RBAC denials from changes RATCHET itself blocks.
- [x] Implement the validating admission webhook and owned local test configuration, authenticated requests to core `DecisionService`, TLS identity, bounded deadlines, exact-object/context binding and fail-closed handling for sensitive changes.
- [x] Prove how legitimate reductions remain possible under the selected failure model. Do not set webhook fail-open for all RBAC updates to get availability; that would permit escalation. If only normal core-available reductions are supported, report that limitation alongside the deferred FR-X6 gap.
- [x] Handle connector-initiated approved operations without an unconditional username/service-account bypass. Bind admission to the actual approved intent, revision and one-time operation context so a stolen connector identity is not a blanket allow rule.
- [x] Implement list/watch resource-version recovery, resync after gaps, authorized execution/verification and drift reporting. Keep the connector-to-control-plane connection outbound-initiated; the cluster-local webhook listener is a distinct target-side admission requirement.
- [x] Test a normal operation, forbidden RoleBinding, each supported escalation primitive, core timeout, invalid object context and out-of-band drift. Show actual Kubernetes before/after state and audit evidence.
- [x] Map each applicable D1-D8 result to a real Kubernetes scenario. A blocked RoleBinding alone does not prove passkey independence, policy governance, continuity or offline audit verification. Mark unsupported parity explicitly.

**Dependency:** The real core DecisionService and reviewed graph semantics must be available. Do not build a local policy evaluator in the adapter to compensate.

**Exit evidence:** Real Kubernetes changes are admitted/blocked correctly, sensitive updates fail closed on core loss, approved operations are correlated/observed, and drift is detected and safely corrected. If the stretch is deferred, keep that decision explicit without weakening simulator completion or transferring adapter work.

## 12. Phase 7 - Hardening and completion evidence

### Sakar's work

- [x] Finish browser accessibility, readable graph/table alternatives, keyboard navigation, input validation and usable narrow-screen layouts for implemented flows. Keep copy operational and evidence-based; remove decorative statistics and incomplete future screens.
- [x] Verify privileged-action cancellation, timeout, retry, duplicate click, stale context, authorization loss and connector/Authority unavailability. Never show success before a verified server outcome.
- [x] Audit passkey management and Authority trust history for replay, revoked credentials, threshold manipulation, same-human multiple-key quorum, untrusted genesis reset and sensitive-data logging. Do not assume all platform/synced passkeys are hardware-bound; describe the actual authenticator used.
- [x] Test persistence/restart and local backup/restore for Authority, simulator and connector command/cursor state. Keep Authority key/credential material and target management credentials separate from core runtime credentials.
- [x] Complete SOPS/age handling, secret-free examples, dependency lockfiles, owned-service `govulncheck`, frontend dependency checks, SBOMs and signed/non-root minimal container artifacts. Add shared CI changes through peer review.
- [x] Supply the actual built static web artifact and stable output contract for `ratchetd` embedding; verify the integrated same-origin build, cookies, WebAuthn origin/RP-ID and API paths with the core owner. Do not move the console to a separate paid host.
- [x] Run canonicalization vectors in Go/TS, approval/Authority/connector unit and integration tests, connector conformance, web typecheck/lint/Vitest, complete Playwright/scenario suite and actual local Compose integration. Keep Go race/vet/lint, Buf and policy checks in the shared required pipeline; report core failures to their owner.
- [x] Record the completed demo walkthrough and owned-component usage/verification notes: console, Authority bootstrap/signing, simulator/connector, CLI and attack scenarios. Use existing free screen recording tooling; no purchased service is required.
- [x] Produce D1-D8 evidence for the same candidate commit used by CI, including real target state, CLI output, latency/continuity results, explicit P1/P2/Kubernetes scope and known failure-model limits. Reference core benchmark/benign replay evidence rather than recreating that work.

**Exit:** The implemented trust, edges and console work together without placeholders, all required tests pass, every scenario claim has actual evidence, and selected scope is complete. A polished screen or passing unit suite alone is not completion.

## 13. Requirement coverage for Sakar

Only Sakar's portion of split requirements appears below; consumption/integration does not transfer core ownership.

| Requirement | Sakar deliverable | Phase |
|---|---|---|
| FR-G6 | Live focused Infrastructure Map | 1 |
| FR-C1, FR-C4, FR-C5 | Request/review UI and authorized action wiring | 2-3 |
| FR-C6 | Passkey ceremony, exact-action binding and `ApprovalVerifier` | 2-3 |
| FR-C9 | Connector target apply/read-back evidence | 2 |
| FR-C10 | Server-redacted requester experience and safe caching | 5 |
| FR-I2 | Draft-only before/after simulator screen | 1 |
| FR-P3, FR-P4, FR-P5 | Authority genesis/registry/signing, `BundleVerifier` and Security Policy UI | 2-3 |
| FR-X1, FR-X2, FR-X3, FR-X4 | Revocation/session adapter, priority consumer, plan presentation and incident console | 4 |
| FR-E2, FR-E3 | Scheduled target revocation and temporary-grant review UI | 5 |
| FR-L2, FR-L3, FR-L4 | Checkpoint signing, audit console and offline verification CLI | 4 |
| FR-O1, FR-O2 | Real attention overview and live updates | 2, 5 |
| FR-K1, FR-K2, FR-K3 | Stateful simulator, connector Sync/Execute/Verify/Watch and broker mode | 0-2; Watch/revert completed in 5 |
| FR-K4 | Drift observation and authorized connector reversal | 5 |
| FR-K5 | Kubernetes sync/admission/watch adapter on kind | 6, stretch |
| FR-K6 | All six scripted attack families and Playwright evidence | 3-5 |
| FR-U2 | Enrolled passkeys and privileged-action verification/management | 2-3 |
| PRD sections 6, 8.2, 9, 10, 12-13 | Canonicalization, CLI, owned-component NFRs, contracts, repo-admin setting and acceptance evidence | All; final evidence in 7 |

FR-G1-G5/G7, FR-C2/C3/C7/C8/C11, FR-I1/I3, FR-P1/P2/P6, FR-X5, FR-E1, FR-L1 and FR-U1/U3 are core-owned. UI/backend integration is required for acceptance but their implementation is not added to Sakar's workload. FR-X6 (quorum-released break-glass) and FR-L5 (external witness publication) remain deferred P2 work; OIDC, cloud-IAM connectors, production multi-tenancy and AI remain out of v1.

## 14. Completion gate before any deployment blueprint

- [x] Every P0 trust/edge/UI requirement is implemented against real core services, without fake mode, fake approvals or direct target bypasses.
- [x] D1-D8 pass on the simulator through actual independent approvals, verified target changes, preserved finance work and offline audit verification.
- [x] Every P1 item has an explicit completed/deferred status and all P1 scope selected for release passes its checks. Kubernetes stretch parity is demonstrated or explicitly deferred.
- [x] Canonicalization, passkey, Authority, connector conformance, Playwright, scenario, persistence/restore and shared CI evidence all correspond to the same release candidate.
- [x] Both people accept their own half and the integrated results. The R6/FR-X6 conflict is resolved or documented as a v1 limit; complete outage-independent reductions cannot be claimed without the mechanism.
- [x] Everything needed to reproduce the completed project runs on existing local hardware without a paid service or temporary credit dependency.

**Deployment blueprint: deliberately deferred until the selected project scope is fully implemented and these gates pass.** No cloud provisioning, DNS/TLS rollout, network topology or production deployment commands are prescribed here. After completion, Sakar supplies verified trust/edge/web artifacts, RP-ID/origin requirements, measured resource needs and component recovery requirements to the later blueprint; that does not make him the owner of Ishaan's core deployment work.
