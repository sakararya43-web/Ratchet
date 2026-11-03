# RATCHET — Sakar's Half Implementation Changelog

> **Owner**: Sakar (Half B: Trust, Edges & Experience)  
> **Repository**: `https://github.com/sakararya43-web/Ratchet.git`  
> **Active Git Branch**: `sakar` (tracks `origin/sakar`)  
> **Operational Rule**: Strict phase-by-phase implementation, zero scaffolding, no synthetic/placeholders, do not touch Ishaan's Half A (core graph traversal algorithms, Rego evaluation engine, event outbox). Review this changelog before beginning any new task or phase.

---

## Table of Contents
1. [Phase 0 — Foundations & Golden Test Harness](#phase-0--foundations--golden-test-harness)
2. [Phase 1 — Simulator Expansion, Connector Sync & Topology UI](#phase-1--simulator-expansion-connector-sync--topology-ui)
3. [Phase 2 — Trust Prerequisites, Passkeys, Independent Authority & D1/D2 Journeys](#phase-2--trust-prerequisites-passkeys-independent-authority--d1d2-journeys)
4. [Phase 3 — Complete Governance, Approver Registry, Policy UI & Adversarial Scenarios](#phase-3--complete-governance-approver-registry-policy-ui--adversarial-scenarios)
5. [Current State & Verification Status](#current-state--verification-status)
6. [Roadmap for Subsequent Phases](#roadmap-for-subsequent-phases)

---

## Phase 0 — Foundations & Golden Test Harness
- **Commit**: `e0d5823`
- **Scope & Deliverables**:
  - `internal/canon/canon.go` & `web/src/lib/canon.ts`: RFC 8785 canonical JSON serializer + SHA-256 digester in Go and TypeScript.
  - `testdata/canon/vectors.json`: 13 golden test vectors (Unicode surrogates, number boundaries, reordering, malformed JSON rejection).
  - `internal/canon/canon_test.go` & `web/src/lib/canon.test.ts`: Golden vector test suites (15/15 passing in TS, 100% passing in Go).
  - `internal/ports/ports.go`: Defined shared in-process Go interfaces (`ApprovalVerifier`, `BundleVerifier`, `Digester`, `PasskeyHandlerFactory`).
  - `cmd/ratchet-sim/`: Stateful simulated crypto exchange (domain, seed, store, HTTP read API, broker mode, local reset).
  - `testdata/orgs/exchange-v1.json`: Deterministic seed fixture with Rahul, security leads, and Tier-0 assets.
  - `testdata/changes/`: 6 sample changes (`ordinary_report_access.json`, `rahul_admin_request.json`, `controlled_approver.json`, `service_overgrant.json`, `safeguard_edit.json`, `containment_revoke.json`).
  - `.github/CODEOWNERS` and `.github/workflows/ci.yml`.

---

## Phase 1 — Simulator Expansion, Connector Sync & Topology UI
- **Commit**: `80cb601`
- **Scope & Deliverables**:
  - `cmd/ratchet-sim/`: Added `CheckAccess`, `CheckSessionAccess`, access probe (`POST /api/v1/probe`), business routes (`POST /api/v1/business/finance-report/read`, `POST /api/v1/business/wallet/sign`), and monotonic audit logging with before/after state.
  - `internal/connector/`: Sync framework, `sim.Adapter`, snapshot & incremental delta sync, revision cursor persistence, gap detection & rollback resync. Tested in `internal/connector/connector_test.go`.
  - `cmd/ratchet-connector/main.go`: Standalone connector binary.
  - `web/`: Full React 19 + Tailwind + Vite console with:
    - `InfrastructureMap.tsx`: Focused authorization graph with React Flow/ELK layout, blast-radius tier overlays, keyboard accessibility.
    - `ImpactSimulator.tsx`: Before/after overlay diff, crown jewel routes, blast radius delta.

---

## Phase 2 — Trust Prerequisites, Passkeys, Independent Authority & D1/D2 Journeys
- **Commit**: `e4b1a96`
- **Scope & Deliverables**:
  - `internal/approval/`:
    - `store.go`: CredentialStore managing enrolled passkeys and session state.
    - `verifier.go`: WebAuthn assertion verification with domain-separated challenge binding `ComputeApprovalChallenge` (`RATCHET_APPROVAL_V1:`, tenant, actor, changeDigest, nonce). Validates RP-ID, origin, user presence, user verification, and ECDSA ASN.1 signatures.
    - `handlers.go`: HTTP endpoints for registration, assertion begin/finish, listing, revocation, and simulation.
    - `seed.go`: Deterministic seed credentials for demo exchange identities (`user:sec-lead-1`, `user:sec-lead-2`, `user:finance-lead`, `user:rahul`, `user:rahul-assistant`).
  - `internal/trust/`:
    - `model.go` & `store.go`: One-time genesis ceremony, $M$-of-$N$ threshold, pinned authority root, canonical digest calculation, distinct signer checks, and bundle activation.
    - `verifier.go`: Real `BundleVerifier` validating RFC 8785 canonical bundle digests and $M$-of-$N$ ECDSA ASN.1 signatures against genesis members before delivering Rego modules.
  - `cmd/ratchet-authority/main.go`: Standalone independent Authority service.
  - `cmd/ratchetctl/main.go`: Operational CLI supporting `genesis`, `policy propose/sign/activate/status`.
  - `internal/connector/sim/adapter.go`: Added `Execute` and `Verify` with target broker authentication and independent read-back verification. Tested in `adapter_test.go`.
  - `cmd/ratchet-sim/d1_d2_integration_test.go`:
    - `TestD1_OrdinaryAccessJourney`: Proves access blocked (403) $\rightarrow$ Resource Owner passkey approved $\rightarrow$ connector executes $\rightarrow$ read-back independently verifies $\rightarrow$ live business report succeeds (200 OK).
    - `TestD2_SensitiveAdminEscalationTwoLeadQuorum`: Proves sensitive escalation requires two independent Security Leads $\rightarrow$ 1-of-2 rejected $\rightarrow$ second lead signs $\rightarrow$ quorum reached $\rightarrow$ tampered request verification fails.
  - `web/src/components/ChangeReview.tsx`: Interactive change review with Invariant R1 enforcement (self-approval and controlled-approver rejection), WebAuthn passkey assertion verification, connector execution, and live business probe.
  - `web/src/components/SecurityOverview.tsx`: Real-time attention queue, governance posture, target sync health, and audit preview.

---

## Phase 3 — Complete Governance, Approver Registry, Policy UI & Adversarial Scenarios
- **Commit**: `639941c`
- **Scope & Deliverables**:
  - `internal/trust/`:
    - Enhanced `model.go` & `store.go` with `RegistryProposal` and `RegistryHistoryEntry`.
    - **Current-Quorum Rule**: Membership rotation or threshold changes require signatures from the *currently valid* quorum under the active epoch, NOT the proposed weaker quorum.
    - **Stale Artifact Rejection**: Proposals created under older epochs are immediately rejected if the registry advances to a new epoch before activation.
    - **Cross-Action Replay Defense**: Enforced explicit domain separators:
      - `RATCHET_APPROVAL_V1:` for change approvals
      - `RATCHET_POLICY_BUNDLE_V1:` for policy bundle proposals
      - `RATCHET_REGISTRY_V1:` for membership/threshold governance
      - `RATCHET_CONTAINMENT_V1:` for containment confirmations
      - `RATCHET_CHECKPOINT_V1:` for audit checkpoints
    - Tested in `internal/trust/governance_test.go` (100% pass).
  - `cmd/ratchet-authority/main.go`:
    - Mounted `/api/v1/authority/registry/propose`, `/sign`, `/activate`, `/history`, and `/proposals`.
    - Mounted `/api/v1/authority/bundle/proposals` and `/history`.
  - `cmd/ratchetctl/main.go`:
    - Added `ratchetctl registry list`, `propose`, `sign`, `activate`, and `history`.
    - Structured exit codes: `0` (Success), `1` (Bad arguments/input), `2` (Quorum failure), and `3` (Signature rejection).
  - `e2e/scenarios/`:
    - `self_approval/self_approval_test.go` (D4): Proves Invariant R1 refusal when requester (Rahul) attempts to approve his own escalation. Simulator IAM remains untouched.
    - `controlled_approver/controlled_approver_test.go` (D4): Proves Invariant R1 refusal when a subordinate within the requester's Control Set attempts approval. Zero privileges gained.
    - `withdrawal_rule_edit/withdrawal_rule_edit_test.go` (D5):
      - *Negative Case*: Direct modification of `safeguard:withdrawal-rule` by ordinary user/operator is rejected.
      - *Positive Case*: Governed policy update is signed by independent Security Leads ($M$-of-$N$ quorum), verified by `BundleVerifier`, and activated in Authority.
      - *Separation of Concerns*: Demonstrates signed bundle updates Authority active rules without mutating simulator IAM.
  - `web/src/components/PolicyGovernance.tsx`:
    - Complete governance UI with Active Bundle inspector, Propose Governed Amendment form with live diff, Multi-Signer Quorum Collection with WebAuthn passkey ceremony, Approver Registry table, and Epoch Transition History.
  - `docs/trust_limits.md`:
    - Documented single-host demonstration limits vs physical hardware isolation, domain separation prefixes, and quorum immutability rules.

---

## Current State & Verification Status
- **Git Branch**: `sakar` (clean, synchronized with `origin/sakar`).
- **Go Test Suite**: All unit, integration, and e2e scenario tests passing:
  - `cmd/ratchet-sim` (cached)
  - `cmd/ratchet-sim/domain` (passed)
  - `e2e/scenarios/controlled_approver` (passed)
  - `e2e/scenarios/self_approval` (passed)
  - `e2e/scenarios/withdrawal_rule_edit` (passed)
  - `internal/approval` (passed)
  - `internal/canon` (passed)
  - `internal/connector` (passed)
  - `internal/connector/sim` (passed)
  - `internal/trust` (passed)
- **Web Console**: `npm test` (15/15 golden vectors passed) and `npm run build` (0 TypeScript errors).

---

## Roadmap for Subsequent Phases

### Phase 4 — Priority Containment, Incident Operations & Audit Verification
- **Requirements**: FR-X1–X4 edge/UI, FR-C9 connector verification, FR-L2 signing, FR-L3, FR-L4, FR-K6 Rahul containment.
- **Scope**:
  - Connector priority containment consumer on frozen priority subject with reserved worker capacity.
  - Actual grant removal, account restriction, service-permission removal, and session termination in simulator.
  - Incident Containment console with server-computed cut plan, critical routes, executable revocations, business impact, preserved activities, passkey confirmation ceremony, progress and verified results.
  - Audit & History console with real person/resource/request/incident/time search, request/approval/execution chronology, and reasons.
  - Authority checkpoint signing over versioned Merkle candidates.
  - Offline verifier: `ratchetctl audit verify` verifying canonical bytes, chain order, approval assertions, operation-digest binding, policy evidence, and checkpoint signatures.
  - Run `contain_rahul` scenario: click-to-verified-revocation < 5s, zero tier-0 reach, working finance report activity, preserved non-critical access > 90% (D6–D8).

### Phase 5 — Planned P1 Edge Features & Complete Simulator Evidence
- Emergency request/status experience.
- Scheduled temporary-grant revocation execution and read-back.
- Watch streams for review/incident updates with resume cursors, reconnect/backoff.
- Simulator Watch with durable audit cursor and drift reports.
- Complete all six FR-K6 attack families paired with legitimate cases.
- Virtual-authenticator Playwright coverage for all flows.

### Phase 6 — Optional Real Kubernetes Adapter on kind (Stretch)
- Sync ServiceAccounts, Roles/ClusterRoles, RoleBindings/ClusterRoleBindings.
- Escalation primitives: `bind`, `escalate`, `impersonate`, service-account token creation.
- Validating admission webhook.

### Phase 7 — Hardening & Completion Evidence
- Accessibility, keyboard navigation, input validation.
- Privileged action cancellation, timeouts, retries, duplicate clicks, stale context.
- Dependency audit (`govulncheck`, npm audit), minimal container artifacts, and final evidence pack.
