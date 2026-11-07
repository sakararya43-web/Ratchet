# RATCHET — Security Hardening, Zero-Secrets & Failure Boundaries

> **Owner**: Sakar (Half B: Trust, Edges & Experience)  
> **Document**: Hardening Specification & Release Readiness  
> **Status**: Verified  

---

## 1. Zero-Secrets & Credential Hygiene

1. **No Embedded Private Keys**:
   - The repository contains zero private signing keys, credentials, or live API tokens.
   - All tests generate ephemeral in-memory ECDSA P-256 keys on the fly using `crypto/rand` and `crypto/elliptic`.
   - Seed credentials for demo identities are generated deterministically in-process or read from environment variables (`SIM_BROKER_TOKEN`).
2. **SOPS / Age Encryption Workflow**:
   - For operational deployments requiring encrypted secrets, Age public keys are pinned in `.sops.yaml`.
   - Secret environment files are encrypted via `sops -e -i env.enc` using recipient public keys; plaintext secrets never reach version control.
3. **Target Management Credential Isolation**:
   - The connector's target management credential (`SIM_BROKER_TOKEN`) is known strictly to the connector and target adapter.
   - It is never transmitted to browser consoles, client sessions, or included in exported audit bundles.

---

## 2. Minimal Non-Root Container Execution

All deployable container images defined under [`deploy/`](../deploy/) follow multi-stage build patterns:
1. **Multi-Stage Build**:
   - Stage 1 (`golang:1.24-alpine` or `node:22-alpine`): Compiles Go binaries statically (`CGO_ENABLED=0`, `-ldflags="-s -w"`) or bundles static React artifacts.
   - Stage 2 (`alpine:3.21` or `nginx:alpine`): Strips build tooling, compiler caches, and source trees.
2. **Non-Root UID 10001**:
   - Containers run under explicit unprivileged user `ratchet` (UID 10001, GID 10001).
   - Eliminates container breakout risks and host filesystem tampering.

---

## 3. Failure Modes & Degradation Handling

| Service / Scenario | Failure Condition | Behavior & Defense |
|---|---|---|
| **Authority Service Unavailable** | Core cannot reach Authority | **Fail-Closed**: No new policy bundles or registry rotations can be activated; existing verified bundle remains cached |
| **Simulator Connection Loss** | Connector disconnected from target | Connector buffers commands, recovers cursor upon reconnect, and detects rollback/gap to force resync |
| **Kubernetes Control-Plane Loss** | DecisionService timeout | **Fail-Closed Webhook**: Escalations (`bind`, `escalate`, `impersonate`) denied (403); Reductions (`DELETE`) permitted |
| **Replayed Passkey Assertion** | Stolen clientDataJSON | **Challenge Mismatch**: Assertion binds exact operation digest and randomized nonce; replay against another change is refused |
| **Expired Temporary Grant** | Grant TTL exceeded | **Cold-Start Sweep**: If connector was down during expiration, it sweeps backlog on restart and forces target revocation |

---

## 4. Supply Chain & Vulnerability Audits

- **Go Toolchain**: `go vet ./...` executed with **0 warnings**.
- **Frontend Dependencies**: `npm audit` executed with **0 vulnerabilities**.
- **Static Artifact Embedding**: Built console files in `web/dist/` are self-contained and ready for embedding into `ratchetd` without third-party CDN or paid hosting dependencies.
