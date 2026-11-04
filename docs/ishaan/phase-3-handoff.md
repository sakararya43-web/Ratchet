# Phase 3 governance and adversarial review handoff

Prepared 2026-11-05. The Ishaan-owned implementation and core acceptance are
delivered on `main`; **joint browser/connector acceptance remains pending**.
The user authorized continued sequential core work despite the earlier peer
gates. This record does not sign off D1/D2/D4/D5 end to end.

## Changes and operation

- Approval and dispatch enforce current policy authorization, human identity,
  independence before/after the proposal, distinct credentials/humans and current
  credential validity. Unauthorized stale proof cannot change a request's state.
- Approval envelope format 2 binds the registry epoch/digest in addition to the
  request, intent, private-context hash, graph, policy and impact. Old format-1
  pending requests require reassessment; they are not silently re-signed.
- Facts schema 2 records actor memberships, registry context, exact public graph
  digest and evaluator `opa-1.22.0/ratchet-facts-v2`. All policy facts remain
  deterministic; evaluation cannot consult the network or current wall clock.
- Registry verification starts with the independently pinned original genesis,
  reconstructs every transition through the actual peer Authority methods, and
  requires the old registry's quorum. A claimed member list/history is insufficient.
- Schema 6 stores immutable registry proofs, activation evidence and a durable
  epoch floor. A verified registry change invalidates old-epoch policy immediately
  when observed, including across restart and separately configured workers.
  Readiness consults the durable registry floor, so stale per-instance memory
  cannot advertise a ready policy after another instance observes a rotation.
- The console reloads Authority/bundle files every five seconds through fresh
  peer stores. A valid replacement bundle must match the verified current epoch
  and advance semantic version. Invalid replacements retain the last valid
  state; an observed rotation without a replacement bundle makes grants unavailable.
- Restart can verify persisted policy and registry proof while Authority is
  unavailable. The peer bundle format has no expiration field: last-valid use
  continues until an independently verified change is observed. No expiry promise
  or outage-independent revocation mechanism is invented.

Run `ratchetd migrate` with the existing administrative DSN before starting schema-6
code. Existing immutable schema-5 policy rows are preserved. Their first verified
restore establishes registry proof; subsequent restores can operate offline.
An unverified legacy row still requires the actual Authority. The private console
configuration and commands are unchanged from [Phase 2](phase-2-handoff.md).

## Actual evidence interfaces

Two additive Connect operations are mounted on `ChangeService`:

| Operation | Behavior |
| --- | --- |
| `GetDecisionEvidence` | Tenant, request ID and optional original assessment revision; zero selects the latest assessment. Returns canonical evidence JSON, assessment-event hash and genesis digest |
| `ListPolicyHistory` | Tenant, after-event position and bounded page size; returns verified bundle versions/digests, registry epochs/digests and monotone event positions |

Both require an authenticated session and the current signed `investigate` or
`policy_history` authorization. The demo policy permits security leads; ordinary
requesters and resource owners are refused. Session cookies/Origin/CSRF checks
remain active. These operations expose no mutation route for approvers, thresholds,
trust roots or Authority policy. A privileged target request cannot edit governance.

Evidence contains the original hash-chained assessment, its predecessor/hash,
the historical public graph, signed bundle and registry proof. It contains no
private signing key or plaintext requester justification. Historical graph
reconstruction verifies a contiguous tenant prefix and uses immutable public
graph events, not current mutable rows or erased display records.

`workflow.ReplayDecision` verifies the original event and envelope, historical
registry signatures, bundle, graph/impact, all derived facts and resulting policy
decision. Callers must independently pin the genesis **and** obtain the assessment
hash from verified history. A self-consistent single event does not prove a full
chain/checkpoint. Full export/checkpoint proof is Phase 4 work. Historical format-1
facts are retained but are explicitly unsupported by the new full replay evaluator.

The shared protobuf changes pass compatibility against the original peer baseline
and Phase 2. UI integration/shared review is still required before merged acceptance.

## Verification

Passing core checks include native acceptance, full Linux integration/race tests,
post-fix affected race checks, vet, zero-issue scoped lint, Buf lint/breaking,
reproducible protobuf/SQL generation and seeded property tests.

Actual PostgreSQL/peer-cryptography cases cover:

- Missing, invalid, unknown, revoked and wrong-context assertions; eight parallel
  copies of one human's approval count once; a second credential is not a second human.
- Newly acquired requester control, changed policy and revoked credentials after
  approval: proof is cleared, the request is held and no execution attempt exists.
- Requester and transitive controlled-owner refusal without advancing revision.
- Rejection of an ordinary typed withdrawal-safeguard weakening request.
- Missing old quorum, duplicate registry signers, forged genesis, epoch gaps and
  altered threshold; valid two-member approval is required to lower that threshold.
- Signed-bundle rollback refusal, registry-floor persistence, invalid file-source
  refusal and offline restore, including a genuine schema-5 artifact shape.
- Stable replay after context changes; modified graph/bundle/root/event/proof and
  an unpinned assessment hash are rejected.
- Actual TLS/Connect investigator authorization and governance-bypass refusal.

Property tests use an independent logical-edge fixed point for randomized R1/R2
organizations and random approval/context sequences for R3. CI runs 300 cases
with seed `20261105`, alongside the independent graph reference suite.

## Remaining peer and merge gates

Read-only integration uses `origin/sakar` at `c1b555f`. Its audit-fixture fix now
makes the combined ordinary `go test -race ./...` suite pass. Sakar's plan, code
and branch were not changed. Main's reused canon/ports/approval/trust files remain
byte-identical to the peer dependency versions.

The separate actual-component `peerintegration` suite still fails five passkey
checks (origin, RP hash, ceremony, COSE public key and unauthenticated factory),
atomic target revision enforcement and the five earlier snapshot conformance
checks. The target test proves a stale request changes persisted IAM. Passing
peer scenario/unit tests does not waive those failures.

Execution serialization remains the proposed `RATCHET_EXEC_V1` contract in
`workflow/execution.go`: exact command/correlation/approval bindings, atomic
compare-and-apply at the expected revision, durable command deduplication and
independent signed read-back. Core holds the tenant lock through command/outbox
staging; the connector must enforce the target transaction. A core-side recheck
cannot eliminate a target-side race. Joint agreement/implementation remains open.

The unsafe peer passkey handlers and nonconformant execution transport remain
unmounted. The earlier shared-file add/add merge conflicts require reviewed
resolution, and actual integrated conformance/D1-D5 must pass before release.
