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
6. [Phase 5 — Planned P1 Edge Features, Drift Watch & Complete Attack Scenario Suite](#phase-5--planned-p1-edge-features-drift-watch--complete-attack-scenario-suite)
7. [Phase 6 — Kubernetes RBAC Adapter & Validating Admission Webhook](#phase-6--kubernetes-rbac-adapter--validating-admission-webhook)
8. [Phase 7 — Hardening, Evidence Pack & Release Readiness](#phase-7--hardening-evidence-pack--release-readiness)
9. [Current State & Verification Status](#current-state--verification-status)

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

## Phase 5 — Planned P1 Edge Features, Drift Watch & Complete Attack Scenario Suite
- **Requirements Covered**: FR-C10 UI, FR-E2 connector revoke, FR-E3 UI, FR-O2 UI, FR-K4 watch/revert, FR-K6 complete attack families.
- **Scope & Deliverables**:
  - `internal/connector/watch.go` & `watch_test.go`:
    - `WatchEngine` consuming target simulator audit log stream via `/api/v1/audit?since_revision=...`.
    - Durable file-backed watch cursor (`watch_cursor.json`).
    - Detection of out-of-band drift (mutations not originating from `broker:ratchet-connector`).
    - Corrective reduction execution: `RevertDrift` dispatches `REVOKE_ROLE` via connector and performs independent read-back verification.
  - `internal/connector/temporary.go`:
    - `TemporaryGrantManager` supporting time-bounded access grants with expiry deadlines.
    - Automated sweep and revocation upon TTL expiration with independent read-back verification.
    - Cold-start catch-up: revokes grants that expired while connector process was disconnected.
  - `cmd/ratchet-sim/server/server.go`:
    - Mounted `/api/v1/test/inject-drift` to simulate out-of-band rogue operator mutations for test and acceptance verification.
  - `e2e/scenarios/k6_attacks/k6_attacks_test.go`:
    - Complete suite of all six FR-K6 attack families paired with legitimate counterparts:
      - **Family 1**: Stolen finance account / session blocked vs legitimate active lead session.
      - **Family 2**: Compromised intern self-escalation blocked under Invariant R1 vs legitimate 2-lead quorum promotion.
      - **Family 3**: Rogue admin out-of-band injection detected by Watch and reverted vs legitimate review flow.
      - **Family 4**: Service account over-grant blocked without broker auth vs scoped time-bounded temporary grant auto-revoking on expiry.
      - **Family 5**: Direct safeguard edit blocked vs governed $M$-of-$N$ Security Lead policy amendment.
      - **Family 6**: Lateral spread to Tier-0 wallet signer blocked (0 reach) vs legitimate wallet operator grant.
  - `web/src/components/EmergencyAndDrift.tsx`:
    - Unified UI console supporting:
      - Emergency access requests with TTL countdown, justification, and Security Lead WebAuthn passkey ceremony.
      - Scheduled temporary grants table with live status and manual/automated revocation verification.
      - Target Watch stream monitoring with durable cursor tracking, out-of-band drift injection simulation, and one-click authorized corrective reversion.
  - `web/src/App.tsx`: Mounted "Emergency & Drift" tab with full React 19 + Tailwind controls.

---

## Phase 6 — Kubernetes RBAC Adapter & Validating Admission Webhook
- **Requirements Covered**: FR-K5 Kubernetes adapter foundation & admission webhook.
- **Scope & Deliverables**:
  - `internal/connector/k8s/model.go`:
    - Go domain models for Kubernetes RBAC (`Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, `PolicyRule`).
    - Kubernetes Admission models (`AdmissionReview`, `AdmissionRequest`, `AdmissionResponse`, `AdmissionStatus`).
    - Dedicated privilege escalation primitive detector `DetectEscalationPrimitives` scanning for:
      - `bind` verb on roles / clusterroles.
      - `escalate` verb on roles / clusterroles.
      - `impersonate` verb on users / serviceaccounts.
      - `create` verb on `serviceaccounts/token`.
      - Full wildcards `*` across API groups, resources, and verbs.
  - `internal/connector/k8s/webhook.go`:
    - `AdmissionWebhookHandler` with fail-closed security posture.
    - Legitimate reductions (`DELETE` of RoleBinding or role restrictions) always permitted even during control-plane disconnection.
    - Privilege escalations require single-use, non-expired `ApprovedIntent` from RATCHET; replayed or unapproved requests are refused (HTTP 403 Forbidden).
  - `internal/connector/k8s/adapter.go`:
    - `K8sAdapter` implementing `connector.TargetAdapter` for Kubernetes clusters.
    - Full `FetchSnapshot` mapping ServiceAccounts and admin users to Identity nodes, ClusterRoles and Roles with Tier-0 classification, and RoleBindings to `ASSIGNED` edges.
    - `Execute` and independent read-back `Verify` supporting `ASSIGN_ROLE` and `REVOKE_ROLE` operations.
  - `cmd/ratchet-k8s-webhook/main.go`:
    - Standalone HTTP service serving `/healthz`, `/validate` (Kubernetes AdmissionReview), and `/api/v1/intent`.
  - `internal/connector/k8s/k8s_test.go`:
    - 6 unit tests verifying primitive detection, reduction permission, unapproved escalation refusal, one-time intent consumption, cluster-admin binding protection, and adapter snapshot/execution (100% passing).

---

## Phase 7 — Hardening, Evidence Pack & Release Readiness
- **Requirements Covered**: Hardening, zero-cost verification, audit integrity, evidence generation, deployment readiness.
- **Scope & Deliverables**:
  - `docs/evidence_pack.md`: Complete evidence report detailing cryptographic protocols, verified acceptance journeys (D1–D8), FR-K6 attack matrix, CLI usage, and zero-cost constraints.
  - `docs/trust_limits.md`: Explicit disclosure of single-host demonstration boundaries versus physical hardware isolation.
  - `docs/security_hardening.md`: Security hardening specification covering zero-secrets, ephemeral keys, SOPS/Age integration, non-root UID 10001 containers, failure modes/degradation matrix, and supply chain audits.
  - `e2e/scenarios/hardening/hardening_test.go`:
    - Verified persistence and restart recovery across Simulator, Authority, and Priority Containment engine.
    - Verified Temporary Grant Manager cold-start sweep on service boot.
    - Verified cross-change assertion replay refusal and zero-digest rejection.
  - `deploy/`:
    - Multi-stage non-root container images: `Dockerfile.sim`, `Dockerfile.authority`, `Dockerfile.connector`, `Dockerfile.k8s-webhook`, and `Dockerfile.web`.
    - `docker-compose.yml` for unified local stack orchestration without paid cloud services.
  - Dependency audit: `npm audit` returned **0 vulnerabilities**; `go vet ./...` passed with **0 warnings**.
  - All Go packages, simulators, connectors, CLI, and scenario tests passing 100% without CGO dependency.
  - Web console compiles with 0 TypeScript errors (`tsc && vite build`).
  - `README.md`: Produced comprehensive hackathon-winning public specification with Mermaid sequence, architecture, containment flow, and invariant diagrams, detailed Ishaan/Sakar division of labor, cryptographic rigor, and quickstart guides.

---

## Current State & Verification Status
- **Git Branch**: `sakar` (tracking `origin/sakar`).
- **Go Test Suite**: All unit, integration, and e2e scenario tests passing:
  - `cmd/ratchet-sim` (passed)
  - `cmd/ratchet-sim/domain` (passed)
  - `e2e/scenarios/contain_rahul` (passed)
  - `e2e/scenarios/controlled_approver` (passed)
  - `e2e/scenarios/hardening` (passed)
  - `e2e/scenarios/k6_attacks` (passed)
  - `e2e/scenarios/self_approval` (passed)
  - `e2e/scenarios/withdrawal_rule_edit` (passed)
  - `internal/approval` (passed)
  - `internal/audit` (passed)
  - `internal/canon` (passed)
  - `internal/connector` (passed)
  - `internal/connector/k8s` (passed)
  - `internal/connector/sim` (passed)
  - `internal/trust` (passed)
- **Web Console**: `npm test` (15/15 golden vectors passed) and `npm run build` (0 TypeScript errors).
- **Public Documentation**: `README.md` published and synced with `origin/sakar`, featuring all required hackathon sections: *At a Glance*, *The Problem*, *Why RATCHET?*, *How It Works*, *System Architecture*, *Repo Layout*, *Test and Quality*, *Tech Stack*, *Honest Limits*, DataNova 2026 Devpost badge, and Hackathon Submission Details table.


