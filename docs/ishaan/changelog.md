# Ishaan implementation changelog

## Working rules

- Work on `main` only; implement phases sequentially.
- Commit useful increments without Codex/ChatGPT co-author trailers.
- Preserve Sakar-owned code and `SAKAR_IMPLEMENTATION_PLAN.md`.
- Shared contracts require peer agreement; a compiled proposal is not a frozen contract.
- Never claim phase completion without its real integration and security evidence.
- This file is separate from Sakar's root `CHANGELOG.md` to avoid Windows filename collisions.

## Phase 5 — in progress (2026-11-05)

The user explicitly authorized advancing while leaving Sakar's dependencies alone.
Phase 4's unfinished work remains in its handoff; it is not marked complete.
Only Phase 5 is active.

- Added reproducible core measurement/replay harnesses without changing peer
  e2e scripts. Published hardware, exact demo/100k-edge compositions, samples,
  warmups, latency tails and native/Linux results in `phase-5-measurements.md`.
  Actual PostgreSQL benign assessment replay reports 0/100 unexpected outcomes,
  explicitly excluding ceremony, user waiting and target execution. Earlier
  performance misses remain retained; the ImpactDiff tail is still above target.
- Optimized immutable edge overlays, reused traversal results and conservatively
  bounded affected-principal analysis, including non-requester controllers.
  CPU profiling removed an unnecessary full structural-proof map after an
  increase was already proved. A 300-seed full-analysis comparison and existing
  graph/safety/golden regressions pass. The shared 100k-edge single-CPU average
  fell from about 163 ms to 45 ms after the profiled allocation was removed.
- Mounted authenticated DecisionService using the same verified graph, policy,
  registry and independence checks as the normal guard. Inline decisions commit
  immutable evidence before returning. An allow requires the exact staged command,
  intent digest, target revision and admission ID; concurrent consumption releases
  exactly one authorization. Replays after replacement return HOLD, changed inputs
  conflict, and policy-only reduction allows cannot create an execution shortcut.
  Real PostgreSQL and TLS tests cover these boundaries, session impersonation and
  requester redaction. `phase-5-decision-contract.md` defines caller obligations;
  arbitrary Kubernetes object mapping remains Phase 6 and is not advertised.
- Added core temporary/emergency grant expiry: dispatch freezes a database-time
  deadline and atomically commits the durable timer, signed command and outbox.
  Replacement workers recover overdue timers; uncertain grant writes reconcile.
  Expiry issues only an exact revision-bound inverse, retains active status until
  signed independent read-back, and exposes CAS refusal as failed expiry requiring
  attention. Lost replies generate durable read-only probes. The signed connector
  capability must explicitly support scheduled revocation; peer adoption/actual
  target acceptance remains outstanding in `phase-5-expiry-contract.md`.
- Emergency routing retains owner or two-security-lead quorum and actual passkey
  checks. Deterministic scope review compares new effective authority with explicit
  requested resources/actions; excess scope or missing bounds is held. Version 3
  facts retain that evidence while version 2 historical decisions remain replayable.
  Temporary-only stable lists include revoked/failed expiry for review. API fields
  expose expiry state and keep excess-scope detail reviewer restricted.
- Real PostgreSQL/River tests cover emergency owner/tier-0 routing, extra resources/
  actions, replacement-worker revocation, write-ACK rejection, wrong roles, changed
  target refusal, attention and post-expiry review. Full workflow and console
  integration tests passed after these changes; peer simulator acceptance is not
  represented by the signed core protocol fixtures.
- Approval lifetime is configurable (1 second to 24 hours, default 900 seconds)
  through `approval_lifetime_seconds`. Assessment atomically persists its expiry
  job with the exact envelope digest/deadline. Workers compare database time,
  reschedule early delivery, ignore superseded timers and retry revision races.
  A real PostgreSQL/River replacement-worker test drains overdue timers without
  expiring a replacement envelope or asserting that an executed grant was revoked.
- Added Change/Incident Watch over verified durable events with tenant/actor/kind-
  bound authenticated cursors. Heartbeats advance past hidden events safely;
  streams end after five seconds and reconnect from the last received cursor.
  Change lists now reconstruct revisions at a fixed ledger boundary, including
  status filtering, and return the matching watch cursor. Incident lists expose
  the same boundary. PostgreSQL and real TLS tests cover updates during paging,
  replacement-service reconnects, redaction and cursor forgery/refusal.
- Added current-policy response visibility for requesters, independent reviewers
  and investigators. Requester responses omit approval envelopes/digests, registry/
  policy context, approver groups and detailed policy/reviewer reasons; explicitly
  directed more-information questions remain available. Unrelated requests are
  excluded from Get/List/overview. Mutation receipts use the same boundary.
- Session graph APIs restrict ordinary callers to their own aggregate reach and
  coarse impact result; investigator graph paths/details remain policy restricted.
  Real PostgreSQL/TLS regressions cover requester redaction, independent reviewer
  access, unrelated-user refusal and review after changed requester context.

## Phase 4 — unfinished, advancement authorized (2026-11-05)

- Schema 9 persists immutable checkpoint candidates and accepted references with
  tenant RLS. Preparation freezes a verified bounded range; acceptance verifies
  every real Authority signature, rechecks the covered chain and requires the
  next contiguous range/prior digest. Pending candidates cannot survive a trust
  rotation as a new acceptance. References are appended after their covered tip.
- Real PostgreSQL checks cover concurrent acceptance, stable preparation retries,
  forged-signature refusal, competing-range rejection, sequential coverage,
  fixed-tip evidence pagination, replacement-process recovery and runtime
  deletion denial. Proof artifacts are digest-bound by their ledger events.
- Mounted authenticated Prepare/Accept/ListCheckpoints operations and optional
  configured SubmitCheckpoint. The HTTP adapter consumes the actual peer
  create/list contract, checks returned metadata and looks up candidates before
  retrying create so lost acknowledgements cannot erase collected signatures.
  Redirects, invalid responses and altered ranges are refused. Raw chain pages
  now identify the latest verified acceptance within their captured tip.
- PostgreSQL/TLS regressions cover the real checkpoint API, evidence pagination,
  forged cursors and ordinary-session refusal. Linux integration/race checks and
  Buf compatibility pass; submission remains distinct from signed acceptance.
- Added an actual peer-executable checkpoint test on the isolated combined tree:
  create over HTTP, sign with the real member key, restart the Authority, retain
  signatures on resubmission and accept through a replacement core service.
  Peer source and branch remain untouched. CI runs this check when integrated.
- A real registry-rotation regression rejects new acceptance of pending old-epoch
  candidates while preserving verification/export of previously accepted proofs.
- Added bounded pure checkpoint-history verification with independently supplied
  root/tip pins and exact source bytes. It validates every acceptance artifact,
  signature, registry proof, contiguous range and later reference; actual database
  exports pass. SQL ordering aliases cannot masquerade as accepted evidence.
- Supplied a valid two-member signed history and nine deliberately corrupted
  export fixtures for the peer handoff. Core tests reject every corruption,
  including a fully rehashed fork with a substituted tip.
- Actual peer offline-verifier conformance exposes an additional unresolved gate:
  altered `prior_checkpoint_digest` is accepted because metadata digest/continuity
  is not rechecked. The failing test is retained; peer code remains untouched.
- Added real manual incident opening from a digest-verified stored proposal and
  signed security-lead authorization. IncidentService List/Get replay immutable
  opening evidence, verify the original plan and report current residual routes
  with observation time/version and bounded completeness. Opening is idempotent.
- Incident pagination uses a fixed cohort and authenticated tenant/status cursors;
  authorized overview and audit search expose the real records. PostgreSQL/TLS
  checks cover concurrent retry, cross-tenant and ordinary-user denial, source
  reconstruction and a later graph observation. Records remain OPEN until actual
  verified execution supports a containment transition; lifecycle work remains.
- Added real incident-linked role restoration through normal durable Submit and
  independent assessment. Current signed responder permission, a real incident,
  exact proposed role-revocation scope and absent direct assignment are required.
  Ordinary SubmitChange applies the same incident checks. New request, incident
  link, job, private context and outbox share one transaction.
- Concurrent/API retries create one restoration request and link. Tier-0 restores
  require two fresh independent leads with an empty initial approval set; signed
  policy excludes incident-linked requests from reduction fast paths. The incident
  retains OPEN status and versioned restoration IDs. Unsupported account/service/
  session increases remain refused and full restoration acceptance stays open.
- Moved Authority HTTP delivery outside the tenant-head transaction. A separate
  PostgreSQL advisory transaction preserves cross-instance serialization and
  releases on completion/process loss. A blocked real HTTP request regression
  proves another ledger append can commit, competing submissions refuse quickly
  and a completed submission releases its lock for retry.
- Final code candidate `0178de0` passes the full core Linux integration/race suite,
  vet, module verification, zero-issue lint, Buf/generation checks, 300 seeded
  properties, real-process smoke and both hosted CI jobs. Ordinary combined-tree
  race checks and actual peer Authority HTTP/restart also pass. Actual peer
  conformance remains failed, including the new altered-checkpoint-link case.
  See [the continuation handoff](phase-4-peer-handoff.md) for pinned evidence and
  the remaining own/peer work. Phase 4 stays open; Phase 5 has not started.

See [the Phase 4 checkpoint](phase-4-progress.md) for operation/configuration,
proof limits, delivered APIs and remaining tasks. The complete core Linux
integration/race suite, vet, zero-issue lint, Buf compatibility and generated-file
checks pass. Phase 4 remains unfinished and Phase 5 has not started.

- Schema 8 adds transactionally updated audit projections with tenant RLS and
  actor/time, request, incident and resource indexes. Missing projections rebuild
  against the complete contiguous source chain and captured tenant tip.
- Mounted actual redacted QueryAuditEvents with current signed authorization,
  actor/resource/request/incident/time filtering and filter-bound fixed-window
  cursors. Display state is verified against original ledger content; arbitrary
  raw assertions/justifications are absent from display results.
- Real database/TLS regressions detect forged display state, rebuild deleted
  projections, retain chain verification after private-context erasure, reject
  changed-filter cursors and deny ordinary-user search.

- Added real role-authorized raw AuditService export with exact canonical event
  bytes, verified sequence/hash links and an explicit export profile. HMAC cursors
  bind tenant, requested range, fixed snapshot tip and predecessor hash; later
  appends do not move a download's boundary. Pages are bounded by count and bytes.
- Actual TLS/database tests independently verify all exported entries, preserve
  the captured tip while appending another event, reject tampered cursors and
  deny ordinary users. No checkpoint signature or complete offline trust pack is
  invented; indexed/redacted search and the complete evidence package remain open.

- Added checkpoint candidates with an explicit ordered event-hash/duplicate-last
  Merkle profile, exact sequence range, predecessor event hash and prior checkpoint
  reference. Truncated/reordered ranges and missing continuity are rejected.
- Returned checkpoint signatures are individually verified through the actual
  peer SignCheckpoint boundary before quorum is counted. The peer's existing
  VerifyCheckpointSignatures only counts entries, so it is never trusted alone.
  Real signatures pass; invalid/duplicate/missing signatures and changed metadata
  fail. Candidate transport/acceptance-reference orchestration remains unfinished.

- Mounted the real PlanContainment Connect operation when explicit operator
  `containment_costs` are configured. The response exposes authoritative canonical
  bytes, proposed zero-tier-0 proof, optimality scope, cost, activity changes and
  route-count completeness. No default risk/disruption weights are invented.
- Real TLS/database acceptance validates the surgical admin-role proposal,
  canonical digest, idempotent retry and ordinary-user refusal. Execute/Restore
  are not mounted while their full verified orchestration remains unfinished.

- Added operator-cost catalogs scoped to reachable authority and schema-7 immutable
  containment proposals. Current policy authorization, graph/registry/policy context,
  complete catalog, exact actions/proof and expiry are bound to a canonical digest.
- Proposal, command receipt semantics and hash-chained evidence commit atomically.
  Eight concurrent retries return one proposal; changed input conflicts. Real
  PostgreSQL acceptance proves planning changes neither live graph nor execution
  state. This is planning evidence, not a claim of target containment.

- Added weighted super-source/super-sink min-cut over executable operations,
  including shared-grant cost gadgets and protected infinite-capacity edges.
  Every result is checked by the real graph/reduction model. Linear topologies
  have a certified minimum within the supplied catalog; nonlinear topologies use
  bounded exact search and label an unproved optimum as a verified alternative.
- Tests verify two critical assets, preserved finance reports, shared grants,
  protected catalogs, cancellation and a takeover counterexample that invalidates
  an optimistic flow cut. Seeded exhaustive-catalog comparisons check minimum cost.

- Added executable graph effects for complete role revocation, service permission
  removal by original grant ID, session termination and account restriction.
  Shared grant/binding effects are applied together. Protected/non-removable
  targets and grants are refused; arbitrary derived edges are not target actions.
  Applying a complete action set re-proves the all-identity reduction invariant.

Started only after Phase 3's core checks and handoff were committed/pushed.
Earlier joint peer gates remain open. No Phase 5 work has started.

- Added explicit all-identity `IsMonotonicReduction` proof and tightened ordinary
  impact classification to share it. Deny/approval/protection removal, protective
  membership removal, hidden asset deletion/relabeling and unknown node-property
  changes cannot enter the reduction path. Restriction of an identity remains a
  supported reduction. Focused and seeded graph/workflow regressions pass.

## Phase 3 — core implemented; joint acceptance pending (2026-11-05)

See [the Phase 3 handoff](phase-3-handoff.md) for configuration, schema-6 upgrade,
replay interfaces, tested adversarial cases and remaining actual-peer gates.
All nine core tasks have implementation evidence; this does not sign off the
unavailable joint browser/target demonstrations.

- Policy readiness and dispatch read the durable registry floor, not just an
  instance's prepared policy. A separate-instance rotation regression proves
  stale memory cannot report ready or execute the formerly approved request.
- Full core Linux integration/race checks pass. The ordinary combined core/peer
  race suite is now green against `origin/sakar` `c1b555f`; its audit-fixture
  correction resolves that old failure. The separate actual-peer conformance
  suite still reproduces passkey, stale target revision and snapshot failures.

- Closed a state-change authorization flaw: an unauthorized stale-digest approval
  can no longer force another request into Held before permission checks.
  Regression coverage verifies unchanged revision and approval state.
- Replay checks envelope/request/intent framing as well as hashes. Invalid
  Authority candidate files no longer prevent restoring already verified durable
  policy. A schema-5 artifact upgrade establishes registry proof without mutating
  immutable policy history, and then restores successfully with Authority offline.

- Real PostgreSQL guard cases now prove newly acquired requester control, a
  changed signed policy and credential revocation hold an already approved
  request, clear its proof and create no execution attempt. Requester and a
  transitively controlled owner cannot advance approval state. A real typed
  withdrawal-safeguard weakening is rejected by the prepared demo policy.

- Added seeded randomized organizations checked against an independent logical
  fixed point for R1/R2, and random approval/context sequences for R3. Three
  hundred seeded cases pass for each new property suite. CI now runs graph,
  domain and workflow properties with the published 20261105 seed.

- Added actual session/policy-authorized Connect evidence export and policy
  activation history with generated additive schemas. Security leads can retrieve
  replayable canonical evidence; ordinary requesters/owners cannot use these
  investigator operations. Real TLS/Connect acceptance verifies both boundaries.
- The same acceptance refuses ordinary target requests for approver/quorum/root
  changes even from a privileged console session; no admin override route exists.

- Approval envelope v2 binds registry epoch/digest. Assessment facts v2 bind the
  exact public graph digest and actor memberships. Historical graph reconstruction
  verifies the complete contiguous tenant prefix and uses no private display data.
- Deterministic replay verifies a pinned assessment hash, the independently
  pinned genesis, historical registry signatures, signed bundle, graph/impact,
  derived facts and final decision. Tampered graph/policy/root/event/proof fail;
  later context updates do not rewrite the original assessment.
- Actual database tests prove old signed-bundle rollback refusal, verified
  rotation invalidation, durable restart floors and offline last-valid restore.

The user explicitly authorized Phase 3 and sequential continuation through later
phases. Phase 2's actual peer passkey/transport/precondition exit gates remain
open; no runtime substitute or ownership exception is introduced.

- Re-check requester/approver policy authorization at dispatch and require the
  same enrolled credential when verifying recorded evidence again.
- Real PostgreSQL/peer-verifier tests reject missing, invalid, revoked, unknown
  and wrong-context proofs without advancing state. Eight parallel approvals by
  one human count once; a second credential for that human cannot satisfy quorum.
- Verify Authority rotation from the pinned original genesis by replaying actual
  peer proposal/signature/activation methods. Missing old quorum, duplicate
  signers, forged genesis, altered threshold and epoch gaps are rejected.
- Schema 6 persists immutable verified registry proofs and a durable epoch floor.
  A verified rotation invalidates old-epoch policy even before a replacement
  bundle arrives. Persisted historical proof supports offline restore/replay.
- Reload private Authority/bundle files every five seconds using fresh peer
  stores; transient source loss retains verified operation, while an observed
  rotation requires a valid current-epoch bundle. Native policy tests and real
  workflow/storage/runtime acceptance pass at this foundation checkpoint.

## Phase 2 — in progress (2026-11-04)

The user explicitly authorized the next phase after Phase 1's core handoff.
Phase 1's joint acceptance remains pending. No Phase 3 work has started.

The [Phase 2 handoff](phase-2-handoff.md) records runtime configuration, executable
evidence and exact peer corrections required for D1/D2. The implementation plan
now distinguishes completed core tasks from the two remaining integrated tasks.
Hosted [core CI for `4e9727f`](https://github.com/sakararya43-web/Ratchet/actions/runs/41858014416)
passes both contract and core/runtime jobs. Peer conformance remains a separate,
failing combined-checkout gate; this successful main build does not waive it.

- A real PostgreSQL/River regression stops the original workflow worker, creates
  a fresh instance with the same verified dependencies, and recovers the existing
  execution attempt through read-only probes. Exactly one original write remains;
  request/command identity and Executing state survive. Linux race acceptance passes.

- Extend CI lint to the implemented domain, policy and workflow packages and
  declare their existing dependencies as direct imports without changing versions.
- Final core verification passes: full Linux integration/race suite, affected
  post-fix race acceptance, module verification, vet, zero-issue lint, Buf lint
  and peer/Phase-1 compatibility, generated SQL/protobuf reproduction, actionlint
  and the real new-process persistence/readiness smoke.
- Added actual peer approval/target conformance cases. Against unchanged
  `9662c46`, five passkey checks fail (origin, RP, ceremony, COSE key, sessionless
  factory) and stale-revision execution changes actual persisted IAM. Duplicate
  commands, mismatched read-back refusal and lost-ack target recovery pass.
- The combined core/peer race suite compiles both halves and reproduces four
  inherited audit-fixture failures. The raw merge still has shared add/add
  conflicts. Neither a fully green merge nor Phase 2 exit acceptance is claimed.

- Keep the login limiter at a strict 10,000 peer buckets even under unknown-peer
  traffic; expired buckets recover capacity. Parse IPv6 peer addresses correctly
  while keeping a single host's source ports in the same bucket. Bounds and IPv6
  independence regressions pass, including Linux race execution.

- Persist another delayed read-only probe whenever reconciliation finds an
  execution still pending. Losing a verification reply no longer ends recovery;
  terminal state stops subsequent probes. The real-job test checks a scheduled
  successor bound to the newly committed workflow revision. Linux race checks
  pass for workflow, sessions and the full console runtime after this change.

- Verify both required prepared-query contracts before activating a signed
  bundle: a structured valid change decision must exist, and authorization must
  explicitly deny an empty identity/context. Signed unrelated modules or an
  unconditional authorization allow cannot displace the active bundle.

- Isolated River workers and job insertion to explicitly configured tenant queues.
  Schema version 5 migrates existing jobs from the shared queue; old workers must
  stop before migration. A real two-instance regression verifies independent
  assessment and rejects cross-tenant authorization.
- Recover configured graphs before starting workers; an incorrect existing graph
  decryption key now refuses startup. Attention projections filter before their
  limit, so completed history cannot hide pending requests.
- Bind submission consistency requirements and correlation IDs to idempotency;
  preserve correlation in signed commands/results and reject mismatched evidence.
  Record dispatch/application time separately so delayed reconciliation can prove
  an on-time application without admitting a late write.
- Native PostgreSQL/River/TLS acceptance passes for workflow, policy, storage,
  console and sessions after these fixes. Scoped lint reports zero issues.

- Added a pure event-producing change state machine covering submission,
  assessment, approval, holds/reassessment, rejection, execution, failure, expiry
  and verified revocation. Distinct-human/credential counting, context invalidation
  and read-back-only completion have deterministic regression coverage.
- Only explicitly supported typed intents validate. Personal context is represented
  by a private record reference/digest, never copied into permanent public facts.
- Read `origin/sakar` at unchanged `9662c46`: its passkey factory ignores SessionAPI
  and mounts `/assert/simulate`; its verifier omits RP-ID/origin checks and uses
  PKIX keys where actual WebAuthn enrollment returns COSE keys. These are peer
  handoff gates. Unsafe passkey handlers will not be copied or mounted.
- Reuse only exact production trust/store/verifier dependencies and the passkey
  store/verifier needed for actual conformance checks. No seed-key helpers or
  simulated-assertion handler is imported into the core runtime.
- Added real OPA 1.22 prepared change/authorization queries. Only the peer's
  BundleVerifier can admit modules/data, against an explicitly pinned genesis.
  Unsupported registry epochs are refused until verified history is available.
  Network, random and wall-clock builtins are unavailable to policy compilation.
  Real signed-bundle tests verify owner approval, two security leads, safeguard
  rejection, authorized reduction, permission denial and invalid replacement.
- Reused byte-identical trust production files and passkey store/verifier from
  `9662c46`; no peer-owned file was rewritten and no seed-key runtime was imported.
- Added schema version 3: tenant-isolated workflow projections/receipts, policy
  artifacts, password accounts and expiring sessions. River 0.51 migrations use
  a separate job schema and retain the existing migration/runtime privilege split.
- Change mutations serialize with graph/policy writes, rebuild authoritative state
  from verified ledger bytes, check durable command receipts before callbacks,
  and atomically commit events, projections and transaction-enqueued jobs.
- Signed policy activations are durably versioned and hash-chained. Restart reload
  re-verifies the persisted artifact; invalid replacements cannot erase a valid one.
- Full existing PostgreSQL acceptance passes after the schema upgrade.
- Added password-authenticated console sessions backed by real PostgreSQL and
  Argon2id hashes. Secure/HttpOnly/SameSite cookies, exact HTTPS Origin checks,
  CSRF tokens, DB-time expiration, logout, password-rotation revocation and bounded
  password work protect the session boundary. No caller-ID header authenticates.
- The real TLS/database login test passes for login, forged headers, CSRF failure,
  logout invalidation and expired-session refusal. Accounts require explicit admin
  provisioning with private passwords; no default login password is shipped.
- Added actual River assessment/guard/reconciliation workers and full replayable
  policy fact sheets. Tenant-serialized checks revalidate graph/policy context,
  distinct approvers, current group eligibility, requester control and benefit.
  Context changes clear approvals; private added context triggers reassessment.
- Added signed connector capability, bound command and signed read-back processing.
  Dispatch/outbox/evidence commit atomically; uncertain writes queue signed
  VERIFY_ONLY reconciliation instead of repeating the write. Missing conformant
  dependencies keep requests in review. No enable-unsafe flag exists.
- Real PostgreSQL/River tests pass for eight concurrent duplicate submissions,
  owner-assessment requirements, missing-verifier refusal, encrypted context,
  hold/context/reassessment, projection rebuild and chain verification. Ephemeral
  real-key protocol fixtures also pass approval, guarded staging, write-ACK refusal,
  read-only reconciliation, mismatched read-back rejection and duplicate evidence.
  These fixtures are not browser enrollment or real peer target acceptance.

- Added session-authenticated Connect Change/Overview handlers, bounded signed
  list cursors, requester context updates and policy-authorized graph/simulation.
  The exact canonical approval bytes are returned for independent digest checking.
  Only implemented unary routes are mounted; Watch remains Phase 5 work.
- Added actual HTTPS `console-serve` and administrative `provision-users` commands.
  Private configuration supplies TLS/session/graph keys and a pinned Authority
  artifact. Policy restore/rejection, jobs, graph refresh and event relay perform
  real operations. Readiness separately exposes missing workflow trust inputs.
- Native `go test ./...`, workflow integration, vet, scoped lint (zero issues),
  Buf lint/Phase-1 compatibility and generated SQL/protobuf checks pass at the
  publication checkpoint. Full runtime integration and Linux race checks follow.

- Added an actual console-runtime acceptance test using PostgreSQL, TLS,
  password login, a real Authority-signed bundle, River and generated Connect
  clients. It verifies assessment/review/context updates, canonical envelope
  bytes, cross-tenant refusal, unchanged pending graph and absent unsafe routes.
- Native runtime acceptance and Linux race checks of runtime/auth/workflow pass.
  The race fixture's login client deadline is eight seconds, within the existing
  production ten-second write bound; Argon2id parameters were not weakened.
- Added basic approval-independence tests for current/proposed inherited control,
  direct benefit and controlled beneficiaries. Execution also requires the role
  to belong to the selected target connector's source snapshot.
- Restricted Rego to an explicit pure builtin capability set, including refusal
  of certificate-validation builtins with implicit wall-clock behavior. Signed
  test modules prove clock/network/implicit-certificate-time calls cannot load.

- Added explicit verified-refusal handling: only signed independent read-back
  proving the exact unchanged pre-state records Failed. Uncertain application
  stays Executing with its signed evidence and read-only reconciliation.
- Transaction fault injection proves River job, ledger, private row, projection,
  receipt and outbox all roll back together; the original idempotency key remains
  usable. Ordinary and actual tier-0 assessments are covered by real-job tests.
- Responder eligibility comes from the verified Rego authorization query rather
  than an invented seed role. ALLOW remains subject to passkey authorization;
  the later containment interface is not implemented early or bypassed.

## Phase 1 — core implemented; joint acceptance pending (2026-11-04)

The user explicitly authorized starting the next phase after the Phase 0 handoff.
This supersedes the instruction to wait before starting Phase 1; it does not
constitute Sakar's approval or resolve the recorded peer audit test failure.
Only Phase 1 work is authorized by this execution record. No later phase has started.

### Scope and live integration observations

- Implement core relay, authenticated ingest, immutable graph, graph/impact APIs,
  connector conformance, golden impact data and reproducible first benchmarks.
- `origin/sakar` remains at `9662c46`. Its connector executable only logs messages;
  the adapter's graph conversion emits dangling permission targets and omits
  session/provenance data. These are peer-owned integration issues, not reasons
  to silently discard edges or invent a successful connector sync.
- Core graph code rejects malformed/unsupported semantics and keeps simulation
  isolated from shared state. Joint fixture/contract review stays explicit.

### Immutable graph analysis

- Added typed, validated forward/reverse CSR snapshots with stable edge identity,
  copied provenance and isolated proposed views. Versioned registry publication
  is atomic; invalidated/stale generations are never returned as current.
- Reach/control analysis handles membership, role inheritance, transitive
  takeover, role administration and resource-action denies. Impact compares
  every identity's powers and critical routes; protective-rule removal is
  classified as weakening even without a new currently reachable resource.
- Cyclic-control, indirect self-grant, multi-beneficiary impact, simulation
  isolation, malformed input, concurrent simulations and stale-read tests pass.
- Simple path enumeration has explicit bounds; an incomplete impact is an error.

### Durable source state and outbox delivery

- Added schema version 2 for source revisions, immutable ingest receipts,
  durable resync quarantine and retry timing. Event append can now participate
  in the same PostgreSQL transaction as source state updates.
- Complete snapshots and exact-base deltas are validated before publication.
  Public authority facts are replayable from the hash chain; display data is
  encrypted separately. Conflicting source ownership and reused message IDs
  are refused. Source merges are atomic across connectors.
- Outbox delivery holds a per-tenant lock through durable broker acknowledgement,
  keeps stable event IDs, persists bounded backoff and exposes backlog statistics.
- PostgreSQL/NATS integration verifies atomic ingest, privacy, replay, persistent
  gap quarantine, duplicate repair delivery and recovery from a lost publish ACK.

### Authenticated JetStream transport

- Added actual JetStream file-backed streams, durable explicit-ack consumption,
  persistent source deduplication, stable publish IDs and retry/backlog handling.
- Additive `SignedGraphSync` binds schema, tenant, connector, message/correlation
  IDs, revision and complete snapshot/delta to a pinned Ed25519 key. Signing uses
  domain-separated shared canonicalization; arbitrary identity headers are not
  trusted. Malformed or unauthenticated inputs never become published graphs.
- Added action-level reach/impact fields, path edge IDs and explicit neighborhood
  truncation to the existing schemas. Buf lint/FILE compatibility remain green.

### Graph correctness and shared impact candidates

- Independent fixed-point reference checks passed 200 generated cyclic graphs
  with seed 20261104. Added regressions for wildcard narrowing, revoked sessions,
  metadata versus secret possession and declared safeguard parameter changes.
- Withdrawal thresholds/check counts are explicit semantics; unknown edits fail
  analysis. Security parameters remain in replayable public facts while display
  metadata stays encrypted. Signature/correlation digests are bound to receipts.
- Reused the peer seed/change fixtures unchanged. Added candidate Rahul-admin
  impact and ordinary/service-overgrant/safeguard/revocation policy fact inputs.
  The peer ordinary fixture references a missing `user:finance-intern`, so the
  additional core scenario uses the existing finance assistant explicitly.
- First 100k-edge benchmark is recorded with hardware, command and dataset in
  `phase-1-benchmark.txt`: approximately 1.38 s/op and 220 MB/op on one CPU
  after complete removed-authority reporting (initial baseline was 0.98 s/op).
  The eventual 100 ms impact target is not achieved; optimization is still due.

### Recovery and complete affected-identity reporting

- Revalidating the same durable graph version restores availability after a
  transient database read failure, without accepting version regression.
- Healthy same-revision snapshots with a new message ID now persist a dedup
  receipt without producing a new graph event/version or outbox publication.
- Action-only revocations report removed powers/control even if resource counts
  stay constant. Partial denies against wildcard grants require explicit action
  expansion; analysis refuses an authority set it cannot represent exactly.
- Added regression coverage for these cases, valid ordered deltas, persisted
  JetStream acknowledgement cursors and metadata-before-possession traversal.
- Neighborhoods cap returned edges at 10,000 with explicit truncation.

### Authenticated graph and simulation runtime

- Added real Connect Graph/Impact handlers over immutable snapshots: node
  provenance, focused neighborhoods, paged reach/paths and exact draft impact.
- Verified client TLS certificates map to server-configured actor/tenant bindings.
  Cursor HMACs bind query scope, tenant and graph version. Header impersonation,
  tenant crossover, tampered cursors and stale-context pagination are refused.
- Added `ratchetd graph-serve`: PostgreSQL source recovery, authenticated connector
  ingestion, durable relay, refresh/invalidation and HTTPS service lifecycle.
  Private configuration supplies keys, connector pins and certificates; remote
  NATS requires TLS/credentials. Metrics expose the authenticated reader's tenant.
- Readiness remains unavailable for escalation until the later policy dependency
  actually exists. Graph/simulation do real work without mounting empty services.
- Native TLS tests and Linux `go test -race -tags=integration ./...` passed with
  real PostgreSQL 17/NATS 2.11. The runtime harness proves signed ingestion through
  live APIs and unchanged graph version after simulation; it is not a substitute
  for the peer's actual connector acceptance gate.

### Deliverable transport limits

- Canonical ledger entries must fit the 1 MiB durable broker limit before their
  event/outbox transaction commits. Envelope overhead cannot strand a tenant's
  ordered outbox behind an oversized event. A real PostgreSQL regression proves
  failed oversized appends leave no event, outbox item or consumed chain position.

### Executable peer conformance

- Added a reusable snapshot/model validator and a separate `peerintegration`
  suite that boots the actual peer simulator and calls its actual HTTP adapter.
  Default core tests do not require importing unavailable peer implementations.
- The isolated combined run against `origin/sakar` at `9662c46` fails five
  genuine acceptance checks: completeness/envelope, declared safeguard semantics,
  dangling permission targets (`policy`, `audit`, `iam`), all three omitted target
  sessions and missing grant identities. No expected-failure assertion hides this.
- Peer-owned CLI transport still logs sync messages instead of publishing them.
  Live connector-to-core D3 acceptance and joint fixture review remain pending.
- Updated policy-fact candidates to include removed powers on role revocation.
  Fixture updates still require joint review; no policy decision is hardcoded.

### CI and final checks

- Extended core CI to vet all present packages, lint graph/bus/conformance,
  run the full real-dependency race suite and fix the independent reference seed.
  Actual adapter conformance runs when the peer simulator source is integrated.
- Marked directly imported NATS and Rapid dependencies correctly; retained the
  peer's existing dependency set for the combined build.
- Final real-dependency Linux race suite passes. Scoped lint reports zero issues;
  module verification and the new-process append/retry/read/chain/readiness smoke
  pass. Contract compatibility and regeneration checks pass without generated diff.
- The corrected combined-source race run passes core and peer packages except
  the same four previously reproduced peer historical-credential audit failures.
  Tagged actual-adapter conformance fails separately and remains an explicit gate.
- Updated the implementation checklist and [Phase 1 handoff](phase-1-handoff.md)
  with runtime configuration, signing bytes, supported semantics, bounds, measured
  performance and exact peer fixes. Shared approval and live D3 are still open;
  no subsequent phase or Sakar-owned implementation was started or changed.

## Phase 0 — implemented; joint acceptance pending (2026-11-04)

### Dependency provenance

Initially imported the following files byte-for-byte from `origin/sakar` at
`9662c46`: `go.mod`, `go.sum`, `buf.yaml`, `proto/ratchet/v1/`,
`internal/ports/ports.go`, `internal/canon/`, and `testdata/canon/`.
No peer-owned implementation was rewritten and the branches remain separate.
Subsequent contract additions must preserve these field numbers and RPC names.
Core dependency additions were later made to the root Go module; original peer
dependencies were retained and exercised in the combined build.
The user confirmed dependency reuse with separate branches. The reused canonical
golden tests pass on Go 1.27.3; `internal/ports` compiles unchanged.

### Required completion evidence

- [ ] Eight core service contracts and connector envelopes agreed with Sakar.
- [x] Approval envelope, authenticated caller boundaries, ledger bytes and replay facts specified.
- [x] Real PostgreSQL migration and sqlc/pgx repository.
- [x] Atomic event/outbox/idempotency writes and serialized per-tenant chain.
- [x] Separate personal data and least-privilege database roles.
- [x] Restart persistence, rollback, concurrent-chain, duplicate-command and SQL tamper-denial evidence.
- [x] Real persisted `ratchetd` operation and honest readiness.
- [x] Local PostgreSQL/NATS Compose, core CI workflow, Buf baseline and local compatibility/check commands.
- [ ] Hosted GitHub Actions verdict after an authorized push.
- [ ] Peer audit fixture correction and a fully green combined candidate.

### Contract increment

- Added the eight core service definitions inherited from the peer, with additive
  typed kinds/states/decisions, mutation context, graph bounds, watch cursors,
  approval envelope, multi-identity impact and connector evidence metadata.
- Recorded authenticated caller rules, privacy, errors, five fixed subjects,
  approval/replay facts and byte-level audit-v1 chain encoding in
  `phase-0-contracts.md`. Peer agreement is still outstanding.
- Captured the original peer descriptors at `testdata/contracts/sakar-v1.binpb`.
  Buf 1.75.0 lint and FILE compatibility against that baseline pass. The existing
  DecisionRequest/Response names have a file-scoped naming-rule exception.

### Durable storage schema

- Added the real goose migration, sqlc queries and generated pgx/v5 bindings for
  tenant heads, events, command receipts, encrypted private records and outbox.
- Added runtime/projector/migration roles, forced tenant RLS and append-only
  mutation triggers. Runtime cannot update outbox payloads.
- Started real PostgreSQL 17 and JetStream-enabled NATS 2.11 using Compose.
  PostgreSQL uses configurable localhost port 55434 because 55432 belongs to an
  unrelated project. Local credentials were generated outside Git.
- The explicit migration command successfully applied schema version 1 using
  the non-superuser migration role. Integration evidence is recorded below.

### Canonical chain and private records

- Implemented the peer-compatible SHA-256 predecessor/canonical-content chain,
  strict UTC microsecond timestamps and the JCS safe-integer limit.
- Added AES-256-GCM private records with random nonces and tenant/record-bound
  associated data; neither plaintext nor encryption keys enter the ledger.
- Hash tampering, peer-format compatibility, invalid timestamp/sequence and
  ciphertext/key/tenant/record binding tests pass.

### Atomic repository and database evidence

- Implemented append/load, verified chain reads, exact-intent command receipts,
  optimistic stream versions, private-record retention and atomic outbox writes.
- Added explicit goose migration and database/schema/least-privilege probes.
- Real PostgreSQL acceptance passed: 32 concurrent streams form one continuous
  chain; 16 racing identical commands create one event/outbox/receipt; conflicting
  intents and stale stream versions are refused.
- A trigger-injected failure after partial writes rolls back all five tables;
  retry starts at sequence 1. New pool reads survive restart, private-record
  deletion preserves immutable bytes, and outbox bytes match the event.
- SQL UPDATE/DELETE/TRUNCATE and trigger-disabling attempts are denied. Forced
  RLS prevents cross-tenant reads/writes; elevated migration credentials fail
  the runtime role check. A test cleanup-order deadlock was fixed before rerun.

### Replay input validation

- Reject unsafe JSON integers before canonicalization can round them; require
  object-shaped replay facts, bounded identifiers/content and known personal
  fields in encrypted records. Regression tests pass.

### Executable core operation

- `ratchetd` now performs real migrate, record-core-evidence, load-stream and
  verify-chain operations. Its health listener exposes only implemented probes.
- The process smoke passed: a PRD-file digest was stored, retried with one effect,
  read and chain-verified by separate processes. Liveness and storage readiness
  returned 200; overall decision readiness returned 503 because no graph or
  verified bundle has been initialized. Unimplemented API paths remain absent.

### Generated clients and full race run

- Generated Go Protobuf and Connect bindings from the actual v1 schemas using
  local generators (Protobuf 1.36.12 / Connect 1.19.1). No RPC is mounted by
  generation alone.
- Reused the peer root `.gitignore` unchanged and isolated development artifacts
  behind `.local/.gitignore`, avoiding a competing root ignore file on merge.
- Full Linux `go test -race -tags=integration -count=1 ./...` passed against the
  real Compose PostgreSQL instance; canonical vectors and all core tests passed.

### Scope gates

Phase 1 has not started. Shared contract review remains a joint gate.
Full-outage revocation (R6/FR-X6) remains the documented peer-owned P2 limitation.

### CI and integration handoff

- Core vet, lint (zero issues), module verification, generated-file consistency,
  Buf lint and compatibility checks pass. CI jobs are `core-contracts` and
  `core-tests`; workflow syntax was validated with actionlint 1.7.12.
- Linux process smoke also passed. Credential env generation now writes LF so
  the same Windows-created private file can be consumed in Linux containers.
- Restored the unchanged Authority/Passkey/Overview proto sources byte-for-byte
  from the peer to avoid unnecessary formatting conflicts.
- An isolated combined race run compiled all peer/core packages. All tests passed
  except four subtests in the peer's `internal/audit` suite. The exact failures
  also reproduce on untouched `origin/sakar`: `time.Now()-12h` enrollment is later
  than the fixed 2026-11-03 approval event. Peer code was not changed.
- Proposed agreement, tested merge resolution and the peer-owned fixture action
  are recorded in `phase-0-handoff.md`. Shared review, the inherited test failure
  and hosted CI remain explicit acceptance gates; no later phase is started.
- The isolated combined frontend passes TypeScript checking, Vite production
  build and all 15 canonicalization tests. No frontend source was changed.
- Direct core module dependencies are annotated accurately; existing peer-only
  requirements are retained. `go list -mod=readonly ./...` passes.
