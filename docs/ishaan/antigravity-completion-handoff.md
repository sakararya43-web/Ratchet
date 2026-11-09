# Antigravity prompt: finish RATCHET completion Phases A, B and C

Copy everything below into Antigravity. This is an implementation handoff, not
permission to replace working security mechanisms with a simpler demonstration.
Status captured on 2026-11-08 after the live Authority browser test passed.

---

You are continuing development of RATCHET, repository
`https://github.com/sakararya43-web/Ratchet.git`.
The current Windows checkout is `D:\Ishaan projects\Ratchet`.
The shell is PowerShell. Work on **main only**.

## 1. Objective and non-negotiable rules

Complete the remaining selected product scope in this order:

1. **Completion Phase A: live governance, verified containment and restoration.**
2. **Completion Phase B: automation and the complete operational console.**
3. **Completion Phase C: complete offline proof, integrated acceptance and release readiness.**

These are the NEW project-completion phases. They are NOT the earlier one-day
prototype A/B/C milestones, which were already accepted. Do not use those old
checked boxes to claim these new phases are complete.

- Finish and validate A before starting B; finish and validate B before C. Within
  a phase work task by task. Do not run multiple phases, implementation tasks or
  acceptance processes in parallel. Do not delegate parallel implementation.
- Deliver working operations through the real UI/API/core/broker/connector/target
  path. No empty handlers, success-returning stubs, fixture-backed production
  responses, fake approvals, disabled verification, logging-only delivery,
  hardcoded scenario outcomes, invented metrics or placeholder screens.
- Test fixtures, property generators and isolated protocol harnesses are valid
  tests. They do not substitute for real integration acceptance. The simulator
  is a real stateful required product target, not permission to simulate results.
- Preserve existing passkey, authorization, independent-quorum, signed-policy,
  target-CAS, immutable-ledger and read-back checks. Fix causes of failing tests;
  do not remove assertions, skip mandatory tests, invert negative assertions,
  relax production security limits or reduce scope to obtain a green report.
- Sakar's work has already been merged into main. Do not merge it again, edit
  the `sakar` branch or change `SAKAR_IMPLEMENTATION_PLAN.md`. The user has
  authorized required integrated connector/passkey/simulator fixes on main.
  Preserve both contributors' working implementations instead of reverting to
  an older branch version.
- Maintain `docs/ishaan/changelog.md` and an accurate task/evidence checklist.
  Commit useful increments on main: at least five meaningful commits per
  completion phase, more where justified. Existing Phase A commits count; do
  not manufacture empty/document-only filler commits to reach a number.
- Use the configured human Git author. Never add a Codex, ChatGPT or other AI
  co-author trailer. Push tested milestones to main under the user's existing
  instruction. Never use force push, reset away work, delete history or publish
  secrets. Inspect the actual diff and staged files before every commit.
- Keep work reproducible on existing hardware with free local tools/services.
  No paid hosting, subscription, trial credit, purchased domain or security-key
  purchase is required. Production deployment is a separate later decision.
- Keep progressing through the ordered phases without asking for routine
  implementation confirmations. State genuine blockers precisely. Do not invent
  completion to meet a time/token estimate.

## 2. Read first, reconcile evidence, then implement

Read these documents and inspect the actual current implementations before edits:

1. `PRD.md`, `RATCHET_Full_Idea_Document.md`, `RATCHET_Architecture.md`.
2. `ISHAAN_IMPLEMENTATION_PLAN.md` and, read-only,
   `SAKAR_IMPLEMENTATION_PLAN.md` for both sides of the integration contracts.
3. `docs/ishaan/changelog.md`, `completion-a-progress.md`,
   `completion-a-design.md`.
4. `docs/ishaan/prototype-progress.md`, `prototype-acceptance.md`,
   `prototype-runbook.md`, `prototype-execution.md`, `prototype-walkthrough.md`.
5. `docs/ishaan/phase-4-progress.md`, `phase-4-peer-handoff.md`,
   `phase-5-progress.md`, `phase-5-expiry-contract.md`,
   `phase-5-drift-contract.md`, `phase-6-progress.md`, `phase-6-peer-gates.md`,
   `phase-6-kind.md`, `phase-7-completion.md`.

Several older documents describe pre-merge defects and explicitly historical
handoffs. Their old failure lists are not proof those defects still exist.
Likewise, checked implementation-plan boxes are not proof the current integrated
runtime implements the operation. Establish current facts from source, actual
routes, executable wiring and reproducible tests.

Create a requirement-to-evidence matrix covering both plans and all selected PRD
requirements. Give each item: implementation paths, runtime entry point, current
status, missing integration, phase, positive/negative tests and evidence location.
Keep all P0 requirements mandatory. Any unresolved original shared-contract or
fixture-review sign-off remains visible; code cannot fabricate human agreement.

## 3. Exact handoff state: do not lose local work

At handoff, local `main` is at `2781fd2` with two commits beyond the locally
recorded `origin/main` baseline `8dae676`:

- `693bbcb`: native passkey evidence for governed artifacts.
- `2781fd2`: independent durable passkey governance and authenticated gateway.

Those two commits have NOT been pushed during this work. There are also
substantial tracked modifications and new, untracked implementation files.
The latest browser-tested source includes that working tree, not just HEAD.
`git status`, `git diff`, untracked files and `git log` are mandatory first reads.
Fetch before making a statement about the current remote; do not overwrite local
work while synchronizing.

If you are on another computer, a fresh clone of GitHub does NOT contain this
entire handoff. Obtain the two local commits plus a source-only transfer of the
tracked and untracked working files before continuing. Do not recreate an older
version based only on this description. Transfer private operator/recovery data
only through an explicit secure procedure, never Git or public artifacts.

Important uncommitted files/changes include:

- `cmd/ratchet-prototype/live.go`, updates to its `main.go`.
- `cmd/ratchetd/enrollment.go`, `cmd/ratchetd/console.go`,
  `internal/api/authority.go`.
- Authority model/transport and integration-test refinements.
- `deploy/completion-a.compose.yaml`, `deploy/completion-a-costs.json`,
  `deploy/prototype.Dockerfile`.
- `scripts/completion-a.py`, `scripts/completion-a-browser.py`, profile support
  in `scripts/prototype.py` and isolated test selection in `prototype-browser.py`.
- `web/src/AuthorityPanel.tsx`, `web/src/lib/authority.ts`, its tests, passkey
  digest helper in `web/src/lib/api.ts`, `App.tsx`, package/test configuration,
  `web/e2e/authority.spec.ts`, profile support in the existing prototype test.
- Actual rebuilt embedded assets and `internal/webassets/assets/manifest.json`.
- `policies/authz.rego` and `docs/ishaan/completion-a-design.md`.

Review the complete diff, not only this list. Do not stage deletions of old hashed
assets without the replacement files and the correct manifest.

### Current runtime and retained data

- The current completion profile is `ratchet-completion-a-v2`, operated by
  `scripts/completion-a.py`; private local artifacts are `.local/completion-a`.
- It has separate persistent core and Authority databases, NATS, simulator,
  connector state and signing identities. The HTTPS console is
  `https://localhost:8444`.
- Its actual browser-accepted Authority is at epoch 4 with policy `1.3.0` adopted
  by core. Alice's demo actor is `user:sec-lead-1`; membership now includes that
  actor and `user:finance-lead`, with threshold one. This state is the result of
  tested quorum-authorized transitions, not a recommended production threshold.
  `user:sec-lead-2` was removed from Authority membership; Authority membership
  and target security-lead approval eligibility are separate trust domains.
- `.local/completion-a/authority-browser-evidence.json` records the public test
  outcome. `.local/completion-a/virtual-authenticators.json` contains PRIVATE
  virtual-authenticator recovery keys. Never print, commit or upload that file.
- Previous completion profiles and private artifacts are preserved under
  `ratchet-completion-a`, `ratchet-completion-a-v1`,
  `.local/completion-a-preacceptance` and
  `.local/completion-a-v1-preserved`. The original accepted prototype
  `ratchet-prototype-v1` and its volumes are preserved separately.
- Do not delete/reset these databases, roots, ledgers or volumes to make a test
  pass. Do not use `docker compose down -v` or broad Docker cleanup. A genuinely
  fresh isolated acceptance profile needs its own explicit name and operator
  setup; preserve earlier evidence and keys.
- The existing Authority browser test is a fresh-genesis ceremony, not a
  repeat-from-epoch-four test. Do not blindly run it against an already advanced
  registry or weaken its epoch/quorum assertions. Add a real restart/resume test
  or use a separately named isolated fresh acceptance profile as appropriate.
- Keep existing localhost TLS identities during ordinary restart. The earlier
  browser privacy error was an untrusted local CA, not proof the app was down.
  Document explicitly trusting the local exported CA for manual use; do not
  disable HTTPS or globally disable browser certificate verification.

## 4. What is already delivered

### Accepted prototype and existing core

The earlier prototype implements real seeded-user sessions, operator-authorized
one-use passkey enrollment/revocation, same-origin embedded console, signed
complete graph ingestion, graph impact analysis, signed Rego policy loading,
independent owner/security-lead approval, guarded ordinary role execution,
durable command journals, target CAS/dedup receipts, signed read-back results,
read-only reconciliation, immutable event chains and persistence.

The actual four-account browser journey demonstrated ordinary owner quorum one,
sensitive distinct-lead quorum two, business 403-to-200 transitions, refused
self/duplicate/insufficient approvals, stale-context HOLD, exact-envelope/challenge
tamper refusal, real reviewed cleanup and independent audit-chain checking.
All 18 local acceptance gates passed on an earlier accepted prototype candidate.
Those historic results do NOT validate the newer dirty Phase A candidate.

Core already contains substantial containment planning/all-identity reduction,
manual incident and role-restoration, durable temporary-access timers, drift
decision/correction/incident, resumable streams, checkpoints, replay, privacy,
performance and selected real-kind integration. Do not rewrite those engines.
Adopt their real contracts and finish the missing executable integration.

### New Phase A Authority work

Implemented and locally exercised:

- Shared native WebAuthn evidence verification, with active enrolled-key lookup
  still enforced for ordinary live approvals.
- Native Authority member/signature metadata and purpose-separated policy,
  registry and checkpoint verification. Native members cannot fall back to
  raw-hash software signatures.
- Separate SQL-backed Authority state/history, immutable bootstrap pins/event
  receipts, transactional idempotency and cached-head tamper refusal.
- Signed core-to-Authority transport binding tenant, actor, method, path, exact
  body digest and short expiry; independent membership/quorum authorization.
- Authenticated HTTPS gateway, own-credential enrollment, limited candidate-only
  projection and member-only governance state.
- Enrollment-only bootstrap server with no target-change API. The explicit
  operator first pin checks actual active enrolled keys. Existing pinned genesis
  cannot be silently replaced on restart or rotation.
- Actual console proposal/review/passkey/signature/activation flows for policies,
  members, threshold and replacement credentials; browser recomputes artifact
  digests before the assertion.
- Public artifact export and independent original-root/history verification by
  core before adopting policy. Core adoption is checked separately from an
  Authority commit.
- Explicit local completion orchestration, operator-selected containment costs,
  persistent identities and original TLS preservation.

Latest local validation:

- Complete native Chromium WebAuthn/virtual CTAP2 governance test: **PASS**,
  57.1 seconds, finished `2026-11-08T09:00:40.397Z`, zero browser runtime errors.
  It exercises native genesis, duplicate/insufficient quorum refusal, policy
  activation, membership change, removed-member refusal, old-quorum threshold
  change, credential rotation, unchanged original root and actual core adoption.
- Targeted Go race suites for `cmd/ratchet-prototype`, `cmd/ratchetd`,
  `internal/api`, `internal/authority`, `internal/trust`, `internal/policy`: pass.
  The ordinary Authority invocation has no integration tests without its tag/DSN;
  do not count that as the dedicated SQL acceptance.
- All **20 frontend tests**, TypeScript/Vite production build and npm audit pass;
  actual embedded assets were rebuilt.
- Dedicated real PostgreSQL/HTTP Authority integration acceptance passed during
  implementation. Rerun it on the final committed candidate, particularly after
  the last model/transport changes.
- Full whole-project acceptance, new-profile restart/backup acceptance and hosted
  CI for the latest Phase A candidate have NOT yet been established.

The governance browser pass uses real browser ceremonies and backend signatures
with virtual authenticators. It does not certify physical hardware or distinct
human operators. Do not state otherwise.

## 5. Phase A: remaining implementation and acceptance

### A1. Close the live Authority increment properly

1. Review and preserve all pending Authority/bootstrap/UI changes. Finish tests,
   operator documentation and checkpoint/restart behavior required by this scope.
2. Verify current-member authorization remains independent from mutable target
   Rego: a registry change must not deadlock governance until a new bundle lands,
   and a target policy must not grant someone an Authority vote.
3. Preserve exact-artifact native proofs, historical registry keys/epochs and
   policy evidence for later offline verification. Candidate enrollment grants
   no vote; duplicate actors, credential IDs or public keys cannot fake quorum.
4. Validate first pin, restart, removed/revoked credentials, threshold and key
   rotation, duplicate retries, stale epoch, wrong RP/origin, no UV and cross-action
   replay. Do not remove legitimate historical verification after later rotation.
5. Add the real live-governance browser gate to CI with public-only evidence and
   teardown. The separate SQL Authority gate already exists; it is not the full
   browser gate. Keep the original prototype regression intact.
6. Commit tested coherent increments and update progress accurately. A1 passing
   does not close Phase A's remaining containment/restoration work.

### A2. Exact-plan, passkey-confirmed containment authorization

Implement the real `ExecuteContainment` flow, not only plan creation:

1. Reuse canonical persisted `ContainmentProposal`/`ContainmentBody` and the
   existing minimum-disruption planner. Display exact actions, consequences,
   preserved/disrupted activities, digests, graph/policy/registry context and
   expiry before confirmation.
2. Derive tenant/actor from the authenticated session. Check current signed
   responder authorization. Bind the fresh native passkey assertion to the exact
   plan and a containment-specific domain; ordinary approvals and governance
   signatures must not authorize containment.
3. Recheck graph version/source completeness, policy hash, registry epoch/digest,
   expiry, target preconditions, original grant provenance and responder rights
   immediately before staging. Changed context requires a new plan/review.
4. Re-simulate and prove monotonic reduction for every affected identity and the
   complete action set, including safeguards and denied authority. A client
   `reduction=true` label or a reduction-looking action name is not proof.
5. Make exact retries idempotent and conflicting retries fail. Keep immutable
   confirmation/context evidence. Staging the action commands, incident links,
   priority outbox and reconciliation work must be atomic.
6. Preserve honest no-safe-plan/analysis-limit/unavailable results. If explicit
   responder-selected actions are added, distinguish their verified safety and
   residual reach from a minimum-cut proof; do not label every proposal minimal.

### A3. Four real containment actions and reserved priority execution

Deliver all four, through the actual executable and real target:

1. Role revocation.
2. Account restriction, including the actual effect on owned sessions.
3. Exact service-permission/grant removal, preserving original grant provenance.
4. Exact session termination.

Use `ratchet.<tenant>.contain.<connector>` with real signed commands and a
separate consumer/reserved capacity. Ordinary queue backlog, retry backoff,
shared executor locks or outbox ordering must not starve this channel. Changing
a subject string without changing actual scheduling is insufficient.

Reuse the existing signed execution contract, durable target receipts and
reconciliation where practical. Extend it deliberately for non-role operations:

- Exact tenant, connector, command/request/correlation IDs, supported purpose,
  approved plan/intent/context, expiry and semantic before/after state.
- Target CAS against the approved preimage; never substitute a fresh target
  revision after the approved state changed.
- Persist journal intent before target I/O and result before result publication.
  Target mutation and durable receipt must commit atomically.
- Independently observe actual target state, including account/session/grant
  semantics. A successful write response or reduced role list alone cannot
  verify a session/account/service action.
- Recovery after target commit but lost response must find the original receipt
  and application time. Verify-only recovery never issues another mutation.
- Uncertain outcomes stay uncertain; signed mismatched/partial observations
  cannot become success. Preserve partial action progress across restart.

Known source pitfalls requiring real fixes rather than wrappers:

- `internal/connector/sim/command.go` currently deliberately accepts ordinary
  roles only and rejects nonempty purposes, emergency/duration and incident
  payloads. Do not simply advertise unsupported capabilities or delete checks.
- `internal/connector/priority.go` is a component, not a sufficient authenticated
  production execution/recovery boundary by itself. Audit it before reuse.
- Service-grant effects in `internal/graph/revocation.go` must match the real
  target's original grant IDs and ASSIGNED/GRANTS representation. Never treat a
  grant ID as a role ID or silently revoke unrelated grants.
- Account restriction's graph delta must include actual session effects; session
  termination must name the exact session, with unambiguous owner semantics.

### A4. Truthful incident lifecycle and residual evidence

1. Persist/replay each action's planned, dispatched, uncertain, verified and
   failed state, with revisions, references, evidence and useful failure reasons.
2. Make action/incident transitions atomic with their execution evidence.
3. Support partial success, timeout/outage, retries, conflicting target changes,
   process death and replacement-process reconstruction without duplicate effects.
4. Wait for the corresponding authenticated source revision before residual
   graph analysis. Mark CONTAINED only when verified actual actions plus a
   complete current analysis prove the required zero tier-0 reach.
5. Retain and display residual paths/failures and reopening/review conditions.
   Queued work, ACKs and intended postimages are never observed containment.
6. Wire the minimum usable console confirmation, action progress and incident
   details in A. Full console completion belongs to B; that is not permission
   to leave A's executable workflow unusable.

### A5. Fresh independently reviewed restoration

Existing role restoration starts a new incident-linked `ROLE_ASSIGN` request.
Complete the actual execution integration and add typed increase contracts for:

1. Restoring the authorized role.
2. Re-enabling the restricted account.
3. Restoring the exact service grant/permission.
4. Issuing a NEW replacement session linked to its revoked predecessor.

Validate the original incident/action and verified effect, current requested
scope and target state. Use current impact analysis, policy/registry, a new
approval envelope, fresh passkeys and the ordinary independent approval guard.
Never reuse containment authorization or revive the old session. Re-enabling an
account must not silently revive its revoked sessions.

Test that a legitimate restoration requester leaves enough independent approvers
to meet the actual quorum. If a responder outside the approver group is needed,
grant that role through real signed policy, not impersonation, a hidden bypass
or lowered quorum. Authority membership and target reviewer membership differ.
Restoration success also requires real target read-back and a durable incident
link; request submission alone does not establish restored access.

### A6. Exit gate

All A tasks above must be integrated and tested. Run positive and negative
crypto/context/authz tests, actual target four-action tests, priority-backlog
tests, lost-result/process-crash/restart tests, partial-failure/residual tests,
fresh restoration review and actual business probes. Preserve the already
working ordinary-access and governance journeys. Record public evidence and
useful commits. Do not begin B while any A requirement remains open.

## 6. Phase B: automation and complete operational console

Status: new completion Phase B has NOT started. Existing core implementations
and component tests are reusable foundations, not completed integrated B work.

### B1. Temporary and emergency access, including actual expiry

1. Adopt `phase-5-expiry-contract.md` in the actual simulator connector runtime:
   signed supported capabilities, `TEMPORARY_GRANT`, frozen grant expiry and
   `EXPIRE_GRANT` linked to the original command and exact grant.
2. Keep emergency requests bounded in duration/scope and routed to eligible
   independent reviewers. Emergency does not waive quorum or passkeys.
3. Atomically schedule durable database-time expiry when the grant is staged.
   Handle uncertain original writes, late jobs, broker/core/connector outages,
   restarts and reconnect after expiry without losing work.
4. Revoke only the timer-owned grant. Independent renewals or changed revisions
   must not be blindly removed. Use verified unchanged-state/refusal evidence
   and review where the original inverse is no longer safe.
5. Do not report REVOKED before signed independent target read-back. Show pending,
   uncertain and failed expiry clearly, retaining actual access state.
6. Expose emergency/duration/explicit scope inputs, pending approval expiry and
   post-expiry temporary-grant review in the real console. Use real list/read
   models; do not calculate authoritative status from a browser clock.

### B2. Actual drift Watch, report, decision and authorized correction

1. Finish actual connector Watch/audit consumption with durable cursors,
   authenticated signed drift publication and gap/resync/reconnect recovery.
2. Adopt `phase-5-drift-contract.md`; correlate exact operation/command IDs,
   tenant, target, action, revision, before/after state and timing with durable
   approved commands. Missing local-memory labels are not sufficient evidence.
3. Have the core decide incident creation and whether the corrective action is
   currently authorized and proved a reduction. The connector must not invent
   authorization from an action name or automatically restore removed access.
4. Execute supported corrections through the signed durable verified path.
   Unknown/unsafe changes require review. Preserve protection/grant provenance.
5. Prevent duplicate incidents, feedback loops, false positives from normal
   observation delay and drift-report ACK before durable persistence.
6. Broker mode remains preventive: only the connector holds target management
   credentials. Exceptional drift injection is explicit test-only access, not a
   production unsigned-write API.
7. Prove actual unauthorized mutation -> signed report -> core decision -> real
   authorized correction -> target read-back -> truthful incident evidence,
   including restart, forged reports, unsafe inverses and copied correlation.

### B3. Complete the console using real services

Audit the current screens against PRD requirements and finish every selected
workflow. Improve usable flow rather than adding a decorative dashboard:

- Overview: real actionable pending approvals, incidents, rejected/held work,
  failed expiry/revocation, policy updates and degraded dependencies.
- Infrastructure: focused identity/resource selection, provenance, reach,
  controllable identities, concrete critical paths and graph-version context;
  avoid an unusable whole-graph dump.
- Impact Simulator: genuine draft-only side-by-side before/after consequences,
  new tier-0 paths, safeguards, affected identities and explicit over-grant.
  Simulation never submits or mutates the target/shared graph.
- Change Review: current/requested access, exact bound impact, justification,
  reasons, distinct quorum, approve/reject/hold/request-more-info where supported,
  stale-review recovery and clear verified execution versus pending uncertainty.
- Security Policy: usable native Authority lifecycle/history, candidates,
  membership/threshold/credential rotation and core-adoption status, preserving
  the A security checks. Do not route users into legacy unsigned governance.
- Incidents: exact plan and its business consequences, passkey confirmation,
  per-action progress/failure/residual evidence, containment/review status and
  fresh restoration for all A-supported access kinds.
- Audit & History: authorized search by person, resource, request, incident and
  time; requester/reviewer/action/effect evidence. Keep redacted ordinary export
  separate from the privileged complete-proof export implemented in C.
- Temporary access and passkeys: actual lifecycle, operator enrollment/revocation
  tickets, expiry attention and appropriate permissions.

Consume existing authenticated resumable Change/Incident streams. Reconnect from
stable actor-bound cursors without missed/duplicate state or overwriting newer
data with an older list. Retain API-side privacy; hiding a UI element is not
authorization. Ordinary users must not gain investigator graph/evidence scope.
Handle loading, empty, forbidden, held, stale, resync and unavailable states
honestly, with practical next steps. Remove obsolete claims that newly completed
operations remain outside the prototype, but only after they actually work.

### B4. Exit gate

Real browser coverage must include emergency/temporary approval and target
expiry across restart, actual drift correction and unsafe refusal, stream
reconnect, all complete console workflows, restricted-user direct API/privacy
checks and degraded-state behavior. Rebuild the embedded console and rerun
regressions before calling B complete. Then proceed to C.

## 7. Phase C: offline evidence, full acceptance and release readiness

Status: new completion Phase C has NOT started. Existing raw-chain/replay,
checkpoint/CLI fixtures, native checks and supply-chain work are foundations.
They are not proof of a complete offline browser-approval package or final
product acceptance on the new candidate.

### C1. Complete authorized offline-proof package

Create one documented versioned export protocol, using the existing canonical
digester and ledger formats. Export the evidence needed to independently check:

- Original canonical event bytes, order, sequence/links and externally pinned
  genesis/trust material; known expected tip/checkpoint when supplied.
- Exact original approved envelopes, operation/impact digests, actor/tenant,
  nonce/challenge, credential IDs, native clientDataJSON/authenticatorData and
  signatures. Do not export a rewritten summary as if it were the assertion.
- Historical enrolled public keys and key formats, RP/origin context and
  enrollment/revocation evidence at the relevant event time. Later revocation
  does not retroactively invalidate a legitimately verified earlier approval.
- Historical signed policy bundles, registry/threshold/key transitions and
  artifact-specific Authority signatures/quorum.
- Checkpoint roots/ranges, prior-checkpoint continuity, metadata/algorithm and
  historical signer authorization. No generic arbitrary-hash signing oracle.
- Containment confirmation, actual execution/read-back and restoration links
  needed to verify the claimed history, with privacy boundaries preserved.

Keep private keys, passwords, sessions, tickets and unnecessary personal data
out of the export. Ordinary redacted exports must not masquerade as complete
offline proof. Make the full export a separately authorized operation.

### C2. Real offline CLI verification and live protocol compatibility

1. Finish `ratchetctl audit verify` against actual current exports containing
   nonzero native browser approvals and governed artifacts. Run with network
   access unavailable; verification must not fetch mutable current keys/policy.
2. Independently pin the trust root. Do not trust a root merely because the same
   untrusted export supplies it. Detect a missing tail with an external expected
   tip/checkpoint; accurately describe a valid prefix when no external tip exists.
3. Reject changed/reordered/missing entries, wrong tenant/root, forged assertions,
   changed envelope/challenge/RP/origin, duplicate quorum, invalid historical
   credentials/registry/bundle/checkpoint, broken checkpoint continuity and
   unsupported algorithms/versions. Return useful nonzero exit codes.
4. Confirm valid historical approvals still verify after later key revocation or
   registry rotation, with the actual historical evidence.
5. Audit existing genesis/policy/registry CLI commands against the new secure
   Authority protocol. Legacy raw-PEM signing and old HTTP routes are not
   interchangeable with native passkey governance. Implement supported secure
   interaction or an explicit, usable browser-assisted ceremony; never advertise
   an incompatible legacy command as the supported live administration path.

### C3. Full simulator D1-D8 and six attack families

Run on the same candidate through actual browser/core/Authority/NATS/connector/
target/CLI, with real independently authenticated reviewers:

| Demo | Required end-to-end result |
|---|---|
| D1 | Ordinary access needs owner approval, executes and is independently verified; requester sees the outcome. |
| D2 | Sensitive new authority needs two distinct eligible independent security leads; insufficient quorum cannot execute. |
| D3 | UI impact/path/blast-radius evidence matches the actual versioned graph and expected fixture, without mutating IAM during simulation. |
| D4 | Self approval and controlled-approver approval are refused without gaining power; legitimate counterpart approvals work. |
| D5 | Ordinary tier-0 safeguard weakening is refused; only the actual signed Authority quorum changes governance. A policy signature alone never directly changes target IAM. |
| D6 | Actual passkey-confirmed surgical containment is independently verified, including all four actions, priority backlog, partial failure and crash/restart cases. Measure the under-five-second target honestly. |
| D7 | Probe actual finance-report business access before/after containment and zero residual tier-0 reach. Measure unrelated noncritical activity preservation against a real denominator; target greater than 90%, never a hardcoded ratio. |
| D8 | Offline CLI verifies a real complete export with browser approvals and rejects deliberately tampered history. |

All six FR-K6 attack families need legitimate counterpart flows: stolen finance
account, compromised developer, rogue admin creation, over-granted service
account, safeguard weakening and lateral spread. Do not hardcode rejection to a
demo actor, role name or fixture ID. Verify all supported request kinds from the
PRD/selected release contracts; fail-closed unsupported routes are honest but
do not count as implemented P0 functionality. Implement any remaining mandatory
contract/flow gaps before release rather than silently deferring them.

Record click-to-verified containment time, human passkey interaction and machine
processing separately. Existing core p99 measurements exclude browser/user/
target time. A single fast sample is not a p95/p99 distribution. Preserve and
report failed timing/continuity targets instead of adjusting measurements.

### C4. Retained Kubernetes scope

Preserve existing real-kind RBAC inventory, exact object-bound admission,
independent review, one-use execution/read-back, fail-closed outage and drift
incident evidence. Rerun affected native tests after shared graph/policy/command
changes. Establish an explicit D1-D8 applicability matrix.

Automatic native watch/recovery/correction and live containment/continuity are
not established merely by the previously passing blocked-RoleBinding test.
Deliver selected native scope, or explicitly record a permitted stretch-scope
deferral; do not invent full simulator/Kubernetes parity. Financial safeguards
and external authorizers have no automatic RBAC equivalent.

### C5. Whole-project hardening and reproducible final candidate

- Run the actual current-main integration/race, executable connector conformance,
  graph/domain/workflow properties, malformed-input fuzzing, OPA tests, module
  verification, vet, strict lint, domain-boundary and vulnerability checks.
- Check Buf lint/breaking and reproducible protobuf/Connect/SQL generation after
  contract changes; preserve golden canonical vectors and old artifact validity.
- Run frontend tests, TypeScript/Vite build, audit and exact embedded-asset/source
  manifest reproduction. Browser tests must use the built same-origin artifact.
- Exercise DB, NATS, Authority, graph lag and connector outages separately. Prove
  no unauthorized grants, no lost jobs/commands and honest readiness/status.
- Validate replay/rebuild, replacement-process recovery, local backup/restore
  for core AND Authority/target/connector cursor/journal state, historical proof
  after privacy deletion and retention limits. Do not claim HA/RPO/RTO from one
  local quiescent backup.
- Preserve separated runtime/migration/Authority/target credentials, least-
  privilege SQL, protected enrollment, source/transport authentication, request
  limits, CSRF, secure cookies and secret redaction.
- Verify local images, nonroot/read-only operation, dependency locks, SPDX SBOM,
  signatures and supply-chain negative checks. Production identity/hosting claims
  need their own actual evidence, not disposable test keys.
- Update real operator startup, TLS trust, recovery, backup/restore, supported
  operations and demo walkthroughs. Keep optional hosting out of this scope.
- Run required hosted workflows on the final published main commit. Record their
  URLs and exact candidate. Old green CI does not validate newer code.
- Publish only safe evidence. Raw browser reports may contain submitted passwords
  or tickets; virtual authenticator files contain private keys. Never upload the
  entire `.local` directory, private traces or raw reports indiscriminately.

### C6. Honest final scope and release gate

Close every mandatory P0 gap and every selected P1 item with evidence. Record
any permitted P1/Kubernetes deferrals explicitly against the original requirement.
Do not reclassify P0 as deferred to claim completion.

FR-X6 (quorum-released break-glass) and FR-L5 (external witnessing) remain P2.
Priority NATS replay does not provide reductions during complete control-plane
loss. The R6 limitation must remain explicit. Do not add a shared admin password,
unsigned emergency revoke endpoint or other bypass. If full outage-independent
reduction is required as a release criterion, report that it requires separately
authorized FR-X6 implementation rather than claiming it already exists.

Human review/agreement by both contributors is a genuine release requirement;
provide evidence for review, never fabricate their sign-off. A working local
prototype, 100% of executed tests passing, 100% code coverage and full product
completion are different claims. Report only the one actually established.

## 8. Existing tools and practical execution notes

Use the repository scripts rather than guessing local infrastructure:

- `scripts/core-check.py`: runs selected commands in Linux Docker with module/
  build caches and a source-only copy. Useful on this Windows checkout where a
  native Go install is absent and Docker drive bind mounts have failed.
- `scripts/core-acceptance.py`: 18 existing sequential named gates. Inspect it
  before running; some historical peer overlays are compatibility tests, not
  substitutes for actual current-main runtime acceptance.
- `scripts/core-env.ps1`, `scripts/core-env-load.ps1`,
  `deploy/compose/compose.yaml`: existing isolated core development dependencies.
  Do not overwrite established private credentials or collide with the prototype.
- `scripts/core-authority-check.py`: real independent Authority scratch-database
  acceptance; load the core dev environment and start its PostgreSQL first.
- `scripts/core-web-build.py`: build/test/audit and regenerate actual embedded
  assets. The manifest hashes web source, including E2E tests; rebuild after
  changing those files, not only after changing React components.
- `scripts/completion-a.py setup`: fresh isolated native-genesis enrollment.
  `start` requires actual quorum policy and operator pin; `restart --no-build`
  preserves accepted state. Inspect the scripts and existing state first.
- `scripts/completion-a-browser.py`: actual fresh-genesis Authority browser
  acceptance. See the non-repeatable-state warning above.
- `scripts/prototype-browser.py`, `scripts/prototype-foundation.py`: existing
  ordinary journey and restart/outage acceptance. Preserve their original profile
  semantics and account for rate windows when running sequentially.
- Existing native-kind reproduction and supply-chain/backup scripts are linked
  from the phase evidence docs. Retain their test preconditions and safe owned
  teardown instead of deleting unrelated local resources.

On this machine Node is `C:\Program Files\nodejs\node.exe`; Python and Docker
are available. Prefer the configured tooling rather than introducing a paid or
unnecessary replacement. Never print connection strings containing passwords.
On Windows verify the resolved owned path before any recursive delete/move, and
use literal-path PowerShell operations without cross-shell string-built deletion.

## 9. Required working/reporting flow

1. Inspect/read and produce the live requirement/evidence matrix. Preserve the
   existing checkout; do not discard work to obtain a clean-looking tree.
2. Reconcile the handed-off Authority increment, run its required checks and
   commit/push coherent verified changes under the human identity.
3. Finish A2 through A6 sequentially, including actual acceptance. Update the
   changelog/evidence as each useful increment lands. Only then close A.
4. Complete B1 through B4 sequentially; only then close B.
5. Complete C1 through C6, final regression and hosted checks on the actual
   published main candidate. Keep unresolved human/P2 limits explicit.

During work give concise factual progress: completed task, actual test result,
remaining work and next step. Do not stop at a plan or a polished UI. At the end
provide one table with each phase's completed scope, remaining work (if any),
exact commits, actual test/evidence links and honest release limitations.
Never say "everything is 100% working" while a listed task, mandatory integration
gate or selected product requirement remains unimplemented or unverified.
