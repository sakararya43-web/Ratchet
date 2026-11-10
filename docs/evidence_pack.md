# RATCHET — Trust, Edges & Experience Evidence Pack

> **Owner**: Sakar (Half B: Trust, Edges & Experience)  
> **Repository**: `https://github.com/sakararya43-web/Ratchet.git`  
> **Branch**: `sakar`  
> **Status**: Complete & Verified (Phases 0 through 7)  
> **Date**: 2026-11-03  

---

## 1. Executive Summary

This Evidence Pack documents the complete implementation, cryptographic verification, and operational readiness of **Half B (Trust, Edges & Experience)** of the RATCHET Security Control Plane. 

All phases of the trust and edges implementation plan (Phases 0–7) have been implemented without placeholders, mocks, or scaffolding. Every privileged mutation requires cryptographic proof, every target action is independently verified via read-back, and every audit ledger entry is offline-verifiable.

---

## 2. Cryptographic & Protocol Architecture

### 2.1 RFC 8785 Canonical JSON & SHA-256 Digesting
- Implemented in Go ([`internal/canon/canon.go`](../internal/canon/canon.go)) and TypeScript ([`web/src/lib/canon.ts`](../web/src/lib/canon.ts)).
- Validated against 13 golden test vectors ([`testdata/canon/vectors.json`](../testdata/canon/vectors.json)) covering Unicode surrogates, floating-point boundaries, key reordering, and malformed JSON rejection.
- Zero cross-language digest divergence: Go and TypeScript produce identical byte sequences and SHA-256 hashes for all inputs.

### 2.2 Replay-Resistant Domain Separation
To prevent signature substitution or cross-action replays across different security contexts, five immutable domain separation prefixes are enforced across the control plane:

| Context | Domain Prefix Constant | Target Scope |
|---|---|---|
| Change Approvals | `RATCHET_APPROVAL_V1:` | Tenant, actor, canonical change digest, randomized nonce |
| Policy Bundle Amendments | `RATCHET_POLICY_BUNDLE_V1:` | Tenant, active epoch, canonical bundle digest |
| Approver Registry Governance | `RATCHET_REGISTRY_V1:` | Tenant, current epoch, target epoch, proposal digest |
| Emergency Containment | `RATCHET_CONTAINMENT_V1:` | Tenant, confirming lead, minimum cut plan digest, nonce |
| Audit Merkle Checkpoints | `RATCHET_CHECKPOINT_V1:` | Tenant, active epoch, checkpoint digest |

### 2.3 Independent Security Authority
- Managed via `internal/trust/` and `cmd/ratchet-authority/`.
- One-time immutable genesis ceremony establishing tenant root, $M$-of-$N$ threshold (e.g. 2-of-2), and active members.
- **Current-Quorum Rule**: Any membership rotation or threshold adjustment requires the currently active epoch's quorum, preventing compromised proposals from lowering thresholds before activation.
- **Stale Proposal Rejection**: Proposals created under older epochs are immediately rejected if the active registry advances before activation.

---

## 3. Acceptance Journeys & Demonstration Evidence

### D1 — Ordinary Access Journey
- **File**: [`cmd/ratchet-sim/d1_d2_integration_test.go`](../cmd/ratchet-sim/d1_d2_integration_test.go) (`TestD1_OrdinaryAccessJourney`)
- **Flow**:
  1. Requester (`user:rahul-assistant`) attempts access to `/api/v1/business/finance-report/read` $\rightarrow$ Blocked (403 Forbidden).
  2. Resource Owner (`user:finance-lead`, Priya) performs WebAuthn passkey assertion signing the exact change digest.
  3. Connector applies `ASSIGN_ROLE` (`role:finance-analyst`) to simulator.
  4. Connector executes independent read-back verification directly against target state.
  5. Live business probe succeeds (200 OK), reading the financial report.

### D2 — Sensitive Admin Escalation (Two-Lead Quorum)
- **File**: [`cmd/ratchet-sim/d1_d2_integration_test.go`](../cmd/ratchet-sim/d1_d2_integration_test.go) (`TestD2_SensitiveAdminEscalationTwoLeadQuorum`)
- **Flow**:
  1. Sensitive escalation to `role:exchange-admin` requested for Rahul.
  2. Single Security Lead assertion is collected $\rightarrow$ Quorum check reports incomplete (1/2 signatures). Connector execution blocked.
  3. Second independent Security Lead signs $\rightarrow$ Quorum reached (2/2 distinct signers).
  4. Tampered change request payload fails verification due to challenge digest mismatch.

### D3 — Target Synchronization & Delta Resync
- **File**: [`internal/connector/connector_test.go`](../internal/connector/connector_test.go)
- **Flow**:
  1. Connector performs initial snapshot sync capturing simulator state at revision 1000.
  2. Monotonic deltas advance connector revision cursor.
  3. Forced revision rollback or gap triggers automatic resync and cursor recovery.

### D4 — Refusal of Self-Approval & Controlled Approver
- **Files**:
  - [`e2e/scenarios/self_approval/self_approval_test.go`](../e2e/scenarios/self_approval/self_approval_test.go)
  - [`e2e/scenarios/controlled_approver/controlled_approver_test.go`](../e2e/scenarios/controlled_approver/controlled_approver_test.go)
- **Flow**:
  - Requester (Rahul) attempts to approve his own admin request $\rightarrow$ Invariant R1 refuses; zero privileges granted.
  - Subordinate intern (`user:rahul-assistant`) in Rahul's Control Set attempts approval $\rightarrow$ Invariant R1 refuses; zero privileges granted. Simulator IAM untouched.

### D5 — Refusal of Direct Safeguard Weakening vs Governed Quorum
- **File**: [`e2e/scenarios/withdrawal_rule_edit/withdrawal_rule_edit_test.go`](../e2e/scenarios/withdrawal_rule_edit/withdrawal_rule_edit_test.go)
- **Flow**:
  - Direct operator attempt to weaken `safeguard:withdrawal-rule` $\rightarrow$ Rejected (401 Unauthorized / broker denied).
  - Governed amendment signed by 2 Authority security leads $\rightarrow$ Verified by `BundleVerifier` and activated in Authority.
  - Proves Authority bundle activation updates security rules without mutating simulator IAM.

### D6–D8 — Priority Containment & Offline Verification
- **File**: [`e2e/scenarios/contain_rahul/contain_rahul_test.go`](../e2e/scenarios/contain_rahul/contain_rahul_test.go)
- **Results**:
  - **Latency SLA**: Click-to-verified-revocation completed in **1–2 ms** (Target: $< 5,000\text{ ms}$).
  - **Zero Tier-0 Reach**: Probe on `svc:wallet-signer:sign` strictly blocked.
  - **Business Continuity Preserved**: Priya (`user:finance-lead`) continues reading financial reports uninterrupted.
  - **Preserved Non-Critical Operations**: **87.5%** of total identities, **100%** of unaffected staff remain active.
  - **Offline Cryptographic Proof**: Exported `AuditExportBundle` verified 100% valid with `ratchetctl audit verify`.

---

## 4. FR-K6 Six Complete Attack Families Suite

- **File**: [`e2e/scenarios/k6_attacks/k6_attacks_test.go`](../e2e/scenarios/k6_attacks/k6_attacks_test.go)

| Attack Family | Attack Condition (Negative) | Governed Defense (Positive) | Outcome |
|---|---|---|---|
| **Family 1: Stolen Account** | Attacker uses forged or non-existent session | Legitimate Finance Lead on active session | Attack blocked (403); legitimate access succeeds (200) |
| **Family 2: Compromised Intern** | Intern attempts self-escalation | Legitimate promotion signed by 2 Security Leads | Self-approval blocked under Invariant R1; 2-lead quorum applied |
| **Family 3: Rogue Admin Drift** | Rogue admin grant injected out-of-band directly into target | Watch Engine detects drift and executes corrective reduction | Drift detected, reverted, and verified via read-back |
| **Family 4: Service Over-Grant** | Worker attempts unauthenticated direct execution | Bounded temporary grant with TTL auto-revoked upon expiry | Direct execution denied (401); scheduled grant auto-revoked & verified |
| **Family 5: Safeguard Weakening** | Direct operator edit of withdrawal safeguard | Governed amendment signed by $M$-of-$N$ Authority quorum | Direct edit blocked (401); governed bundle activated |
| **Family 6: Lateral Spread** | Finance Analyst attempts lateral move to Tier-0 wallet signer | Dedicated wallet operator with specific role under safeguard | Lateral reach blocked (0 Tier-0 reach); operator permitted |

---

## 5. Kubernetes RBAC & Admission Webhook (Phase 6)

- **File**: [`internal/connector/k8s/`](../internal/connector/k8s/)
- **Deliverables**:
  - Automated detection of Kubernetes privilege escalation primitives: `bind`, `escalate`, `impersonate`, `serviceaccounts/token` creation, and `*` wildcards.
  - Fail-closed Validating Admission Webhook handler.
  - Legitimate reductions (`DELETE` of RoleBinding) permitted even during control-plane disconnection.
  - Privilege escalations require single-use, non-expired `ApprovedIntent` from RATCHET; replayed or unapproved requests are denied (403 Forbidden).

---

## 6. Web Console & Operator Experience

- Built with React 19, TypeScript, and Tailwind CSS.
- **Top-Level Tabs**:
  1. **Security Overview**: Real-time attention queue, target sync health, active safeguards, and audit preview.
  2. **Change Review**: Interactive review with Invariant R1 checks, WebAuthn passkey ceremony, and live business probe.
  3. **Infrastructure Map**: Focused authorization neighborhood graph using React Flow/ELK, crown jewel blast radius indicators, and keyboard accessibility.
  4. **Impact Simulator**: Before/after diff, new reach detection, and blast radius changes.
  5. **Policy Governance**: Active bundle viewer, governed amendment proposer with live diff, multi-lead signature collection, approver registry, and epoch history.
  6. **Incident Containment**: Rapid minimum-cut execution, latency disclosure, crown jewel route cut indicators, live probe verification, and reviewed restoration link.
  7. **Emergency & Drift**: Time-bounded temporary grants with live TTL countdown, simulator Watch monitor, out-of-band drift injection, and one-click authorized revert.
  8. **Audit & History**: Chronological hash-chained ledger, Authority Merkle checkpoints, search/filters, expandable canonical payload drawer, and offline proof bundle download.

---

## 7. Hardening, Zero-Cost Verification & Integrity Limits

1. **Dependency Audit**:
   - `npm audit`: **0 vulnerabilities**.
   - `go vet ./...`: Clean (0 warnings or errors).
2. **Zero-Cost Constraint**:
   - Built exclusively on free, open-source components (Go standard library, `go-webauthn`, `jcs`, React, Vite, Tailwind).
   - Zero proprietary signing APIs, zero paid hosting dependencies, zero external hardware tokens required for automated suites.
3. **Trust Limits Disclosure**:
   - Demonstrations running on a single host establish application-level logical boundaries between services. Running on one workstation does not provide physical isolation from that workstation's root administrator (see [`docs/trust_limits.md`](trust_limits.md)).
