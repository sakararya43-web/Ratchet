# RATCHET Trust Model & Operational Limits

## 1. Application Boundaries vs. Physical Host Isolation

> [!WARNING]
> **Single-Host Demonstration Limit**: Separate microservices (`ratchet-sim`, `ratchet-authority`, `ratchet-connector`, and the control plane), dedicated persistence stores, and human-held signing credentials establish **logical application boundaries**. Running all components on a single development or demonstration machine does not provide isolation from that machine's root/kernel administrator. A single-host demonstration must not be presented as production-grade physical or hardware independence.

In production:
1. **Independent Authority** runs on an isolated network enclave with its own dedicated database and strict egress controls.
2. **Control Plane** has read-only access to published policy bundles and cannot issue policy mutations or reset genesis.
3. **Connectors** initiate outbound-only mTLS/authenticated connections to the control plane and hold target IAM broker credentials that are inaccessible to the browser or ordinary users.
4. **Key Management**: Security Leaders hold hardware FIDO2/WebAuthn authenticators (e.g. YubiKeys) where private keys never leave the secure hardware element.

## 2. Cryptographic Domain Separation

To prevent cross-action replay attacks, RATCHET enforces domain-separated hashing across all signing ceremonies:

| Action / Artifact | Domain Separator Prefix | Target Fields |
| :--- | :--- | :--- |
| **Change Approval** | `RATCHET_APPROVAL_V1:` | `tenantID`, `actorID`, `changeDigest`, `nonce` |
| **Policy Bundle** | `RATCHET_POLICY_BUNDLE_V1:` | `tenantID`, `epoch`, `bundleDigest` |
| **Registry Proposal** | `RATCHET_REGISTRY_V1:` | `tenantID`, `currentEpoch`, `targetEpoch`, `proposalDigest` |
| **Priority Containment** | `RATCHET_CONTAINMENT_V1:` | `tenantID`, `incidentID`, `actionSetDigest`, `nonce` |
| **Audit Checkpoint** | `RATCHET_CHECKPOINT_V1:` | `tenantID`, `range`, `merkleRoot`, `priorCheckpoint` |

An assertion or signature produced for one action domain cannot be replayed or accepted in any other domain.

## 3. Quorum & Governance Rules

1. **Current Quorum Rule**: Any proposal to alter Authority membership or the threshold $M$ requires the approval of the **currently active quorum** under the current epoch, not the proposed weaker quorum.
2. **Stale Proposal Refusal**: Proposals created under prior epochs are immediately marked stale when the registry advances to a new epoch.
3. **Immutability of Genesis**: Once genesis is established, the genesis ceremony endpoint rejects any attempt to reset or overwrite the authority root.
