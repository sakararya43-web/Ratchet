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
5. [Phase 4 — Priority Containment, Incident Operations & Audit Verification](#phase-4--priority-containment-incident-operations--audit-verification)
6. [Current State & Verification Status](#current-state--verification-status)
7. [Roadmap for Subsequent Phases](#roadmap-for-subsequent-phases)

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

## Phase 4 — Priority Containment, Incident Operations & Audit Verification
- **Requirements Covered**: FR-X1–X4 edge/UI, FR-C9 connector verification, FR-L2 signing, FR-L3, FR-L4, FR-K6 Rahul containment (D6–D8).
- **Scope & Deliverables**:
  - `internal/connector/priority.go` & `priority_test.go`:
    - `PriorityContainmentEngine` running reduction commands on dedicated worker capacity to prevent starving under standard change backlog.
    - Explicit reduction operation allowlist enforcement (`TERMINATE_SESSION`, `REVOKE_ROLE`, `RESTRICT_ACCOUNT`, `REMOVE_SERVICE_PERMISSION`), rejecting non-reduction commands.
    - Read-back verification via `TargetAdapter.Verify()` and file-backed containment history persistence.
  - `internal/trust/checkpoint.go`:
    - `AuditCheckpoint` model with `ComputeMerkleRoot`, domain-separated `ComputeCheckpointSigningDigest` (`RATCHET_CHECKPOINT_V1:`), creation, member signing, and $M$-of-$N$ threshold verification.
  - `internal/trust/model.go` & `store.go`:
    - Added `DomainContainment` (`RATCHET_CONTAINMENT_V1:`) challenge computation `ComputeContainmentChallenge`.
    - Checkpoints persistence and lookup in `Store` (`SaveCheckpoint`, `GetCheckpoint`, `GetLatestCheckpoint`, `ListCheckpoints`).
  - `cmd/ratchet-authority/main.go`:
    - Mounted `/api/v1/authority/checkpoint/create`, `/sign`, `/latest`, and `/list`.
  - `internal/audit/`:
    - `model.go`: `AuditEvent`, `ComputeEventDigest` ($H_i = \text{SHA256}(H_{i-1} \parallel \text{canonicalJSON}(E_i))$), `StoredCredentialRecord`, `AuditExportBundle`.
    - `verifier.go`: Real `OfflineVerifier` evaluating complete export bundles against pinned Genesis, strictly monotonic sequences, unbroken hash chains, temporal credential validity, WebAuthn passkey assertion signatures over domain-separated challenges, Merkle roots, Authority $M$-of-$N$ signatures, and truncation/tip detection.
    - `audit_test.go`: Comprehensive test suite (Happy path, tampered event data, broken sequence, forged approval assertion signature, tampered checkpoint Merkle root, insufficient signatures, truncation detection, revoked credential rejection, broken hash chain link).
  - `cmd/ratchetctl/main.go`:
    - Mounted `ratchetctl audit verify --export-file=<path> [--genesis-file=<path>] [--expected-tip=<hex>] [--expected-checkpoint=<hex>] [--json]`.
    - Return codes: `0` (Success), `1` (Bad arguments/input), `2` (Quorum failure), and `3` (Cryptographic failure/tampering).
  - `cmd/ratchet-sim/server/server.go`:
    - Added session-aware access probes via `SessionID` to `/api/v1/probe`.
    - Handled `REMOVE_SERVICE_PERMISSION` and `TERMINATE_SESSION` in `/api/v1/execute`.
  - `e2e/scenarios/contain_rahul/contain_rahul_test.go` (D6–D8):
    - Automated verification of the Rahul compromise and containment journey.
    - Verified click-to-verified-revocation < 5s SLA (executed in ~1ms).
    - Probed target before and after: Rahul workstation session terminated and account restricted; 0 Tier-0 reach.
    - Proved unaffected business continuity: Priya (`user:finance-lead`) finance report read preserved uninterrupted; preserved non-critical operations > 87.5% of total identities, 100% of unaffected staff.
    - Generated complete audit export bundle and validated 100% cryptographic integrity offline.
  - `web/src/components/IncidentContainment.tsx`:
    - Dedicated Incident Containment console with target scope selection, server-computed minimum cut plan, crown jewel threat routes eliminated, Security Lead WebAuthn passkey ceremony (`RATCHET_CONTAINMENT_V1:`), priority execution, passkey vs machine latency disclosure, live target probe results, and reviewed restoration link.
  - `web/src/components/AuditHistory.tsx`:
    - Audit ledger console with search by actor/target/action, event type filtering, hash chain integrity indicators, Authority Merkle checkpoints overview, expandable inspection drawer for canonical evidence, and offline proof bundle download.
  - `web/src/App.tsx`: Mounted "Incident Containment" and "Audit & History" tabs.

---

## Current State & Verification Status
- **Git Branch**: `sakar` (clean, synchronized with `origin/sakar`).
- **Go Test Suite**: All unit, integration, and e2e scenario tests passing:
  - `cmd/ratchet-sim` (passed)
  - `cmd/ratchet-sim/domain` (passed)
  - `e2e/scenarios/contain_rahul` (passed)
  - `e2e/scenarios/controlled_approver` (passed)
  - `e2e/scenarios/self_approval` (passed)
  - `e2e/scenarios/withdrawal_rule_edit` (passed)
  - `internal/approval` (passed)
  - `internal/audit` (passed)
  - `internal/canon` (passed)
  - `internal/connector` (passed)
  - `internal/connector/sim` (passed)
  - `internal/trust` (passed)
- **Web Console**: `npm test` (15/15 golden vectors passed) and `npm run build` (0 TypeScript errors).

---

## Roadmap for Subsequent Phases

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

