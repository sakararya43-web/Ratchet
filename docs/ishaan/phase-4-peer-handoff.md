# Phase 4 integration and continuation handoff

Prepared 2026-11-05. Continue **Phase 4**, on `main` only. Phase 5 has not started.
Read [the current implementation checkpoint](phase-4-progress.md) for the delivered
operations and [the changelog](changelog.md) for committed increments. Preserve
Sakar's branch, source ownership and implementation plan.

## Verified candidate

Core code candidate: `0178de03dd25a4c6d7268c6d539e30a707012c09`.
Peer source: `origin/sakar d823a10` (production source unchanged since `c1b555f`).
The branches remain separate. Tests used an ignored, unversioned archive overlay;
no peer branch or source file was changed.

Passing on that core candidate:

- Full Linux `go test -race -tags=integration -count=1 -timeout=3m ./...` with
  actual PostgreSQL and JetStream, vet, module verification and zero-issue lint.
- Buf lint/breaking against the peer and earlier main baselines, reproducible
  protobuf/SQL generation, 300 properties at seed `20261105`, and a new-process
  append/retry/read/chain/readiness smoke.
- Ordinary `go test -race -count=1 -timeout=3m ./...` on the combined overlay.
- The actual peer Authority executable: HTTP candidate creation, real member
  signing, process restart, signature-preserving retry and core acceptance.

[GitHub CI for the code candidate](https://github.com/sakararya43-web/Ratchet/actions/runs/41985089581)
passed both jobs. Its actual-peer steps are conditional and skipped on separate
`main`; the overlay results above were run separately. Passing ordinary combined
tests does not imply that the raw Git merge resolves its shared-file add/add
conflicts automatically or that the conformance gates below pass.

## Required peer closures

`go test -race -tags=peerintegration -count=1 ./internal/connector/conformance`
still fails against the pinned overlay. Keep the failing tests enabled.

| Boundary | Observed failure | Closure needed |
|---|---|---|
| Passkey verifier | Wrong origin, RP-ID hash and ceremony type accepted; normal enrolled COSE key rejected | Real browser enrollment and exact-context, UV-required verification through the peer boundary |
| Passkey session factory | Unauthenticated credential management returns 200 | Authenticated tenant/actor from the core session adapter and no simulated assertion route |
| Simulator writes | A stale expected revision mutates actual IAM | Enforce the supplied precondition atomically at the real target |
| Snapshot | Missing complete envelope, safeguard semantics, session state and original grant IDs; dangling endpoints | Complete authenticated source snapshots with executable provenance |
| Offline checkpoint verifier | Altered `prior_checkpoint_digest` returns `Valid=true` | Recompute metadata digest before signature validation and enforce checkpoint continuity |

The checkpoint failure is reproduced by
`TestPeerAuditVerifierCheckpointHandoffConformance/wrong-prior-checkpoint` using
the [checked-in corruption fixtures](../../testdata/audit/checkpoints/README.md).
Core acceptance and `VerifyCheckpointHistory` reject it. The actual peer
create/sign/restart path passes; the offline-verifier acceptance defect is a
distinct gate.

Two additional dependencies remain beyond those negative tests:

- The peer connector CLI uses `LogPublisher`, rather than the actual authenticated
  command/result transport. Consume the bound command/capability/result proposal
  already recorded in the Phase 2 handoff, including the priority subject
  `ratchet.<tenant>.contain.<connector>`. A log acknowledgement is not delivery or
  verified target execution.
- Historical approval public keys need immutable credential-ID/key-format and
  enrollment/revocation evidence. The current credential store is in memory and
  `SaveCredential` can replace a revoked ID's key while retaining its original
  creation time. Current credential listings cannot establish historical validity.
  `ports.ApprovalVerifier` returns a credential ID, not that historical key evidence.
  Do not invent keys or represent the existing chain/checkpoint handoff as a
  complete offline browser-approval package.

## Remaining Ishaan implementation

1. Implement passkey-confirmed ExecuteContainment with exact plan/context binding
   and a current monotonic-reduction proof for all four executable action kinds.
   Recheck graph, policy, registry, actor authority, expiry and original grant
   provenance before publishing any target action.
2. Persist priority commands, attempts and incident action transitions atomically.
   Extend the actual bound execution contract beyond its current role operations;
   require target preconditions, durable deduplication and independent read-back.
   Reconcile uncertain results across restart without declaring success from ACKs.
3. Add verified incident action/failure/residual evidence and truthful containment
   transitions. Manual opening and role-restoration links already work and replay
   from immutable source events; they remain OPEN without verified execution.
4. Add supported account/service/session increase contracts for restoration.
   Existing role restoration creates a fresh independently reviewed request and
   binds the incident in its new approval envelope. Preserve that rule for every
   additional kind; do not revive a compromised session from an ambiguous string.
5. Finish the complete offline evidence package with historical approval keys,
   original assertions/envelopes and signed registry/bundle artifacts. Existing
   raw-chain, decision replay and checkpoint history are useful independent pieces,
   with their scope stated in their profiles.
6. Measure D6 from click through human passkey interaction and verified read-back,
   separately reporting machine time. Test backlog and restart. Measure actual
   finance-report access before/after for D7. Simulated preservation is not that
   business probe. Retain peer CLI/scenario acceptance for the final D8 verdict.

No phase is complete merely because core CI is green. Continue the unchecked
Phase 4 tasks before advancing; do not add fake success responses or substitute
temporary transport/verifier implementations to close these gates.
