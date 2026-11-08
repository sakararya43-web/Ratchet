# Ishaan implementation changelog

## Working rules

- Work on `main` only; implement phases sequentially.
- Commit useful increments without Codex/ChatGPT co-author trailers.
- Preserve Sakar's branch and `SAKAR_IMPLEMENTATION_PLAN.md`. The user explicitly
  authorized fixing the Kubernetes connector on `main` for Phase 6 acceptance.
  The user also authorized required passkey/simulator/audit integration fixes on
  main for Phase 7, without changing that branch or plan.
- Shared contracts require peer agreement; a compiled proposal is not a frozen contract.
- Never claim phase completion without its real integration and security evidence.
- This file is separate from Sakar's root `CHANGELOG.md` to avoid Windows filename collisions.

## Core lint & staticcheck quickfix hardening

- Fixed staticcheck QF1003 (tagged switch recommendation) in `internal/workflow/incident.go`: converted event type conditional checks to a tagged switch statement with explicit default integrity error.
- Fixed staticcheck QF1003 in `internal/workflow/execution.go`: converted change intent kind conditional to a tagged switch.
- Fixed staticcheck QF1003 in `internal/connector/sim/executor.go`: converted envelope intent kind conditional to a tagged switch with grouped role assignment/revocation handling.
- Fixed staticcheck QF1001 (De Morgan's law simplification) in `internal/authority/transport.go`: simplified scheme and loopback validation logic to eliminate nested negation.
- Passed full test suite, go vet, and linters across all packages without suppressing rules or weakening linter configuration.

## Project completion - Phase C: offline proof hardening, acceptance and release readiness

- C1 & C2 (Offline verifier security hardening):
  - Fixed offline verifier vulnerability accepting events with removed approval assertions: `verifyBundle` strictly requires `ApprovalAssertion != nil` on all approval events (`EventApprovalRecorded`, `EventContainmentExecuted`, `APPROVE_CHANGE`, `EXECUTE_CONTAINMENT`, `CONFIRM_CONTAINMENT`).
  - Fixed credential verification matching: requires exact credential ID matching (`bytes.Equal(rec.CredentialID, sub.CredentialID)`), rejecting unenrolled credential IDs.
  - Fixed policy bundle and registry proposal verification: verifies cryptographic authority member signatures using `verifyAuthoritySignature`, validates against active genesis members, and enforces distinct member threshold M (rejecting duplicate/forged signatures).
  - Added comprehensive unit test suite in `internal/audit/audit_test.go` verifying rejection of removed approval assertions, unenrolled credential IDs, and duplicate policy signatures.

## Project completion - Phase B: automation and complete operational console

- B1 (Temporary & emergency access with target expiry):
  - Fixed `EXPIRE_GRANT` contract mismatch in `internal/connector/sim/command.go`: accepts both `ROLE_REVOKE` and original grant `ROLE_ASSIGN` envelopes with `OriginalCommandID`.
  - Relaxed strict envelope expiration match for `EXPIRE_GRANT` to allow active timer execution deadlines while the grant is expired.
  - Corrected expected role calculation for `EXPIRE_GRANT` to evaluate `BeforeRoles` minus revoked access.
- B2 (Continuous drift detection, reporting and corrective response):
  - Fixed contract mismatch in `internal/connector/sim/command.go`: accepts both `DRIFT_REDUCTION` (core purpose) and `DRIFT_CORRECTION`.
  - Wired production target watch and reporting loop in `cmd/ratchet-connector/main.go`: initializes `connector.NewWatchEngine`, sets connector signer identity, and runs continuous `PollAndReport` loop publishing canonical signed drift reports to `ratchet.<tenant>.drift.reports`.
- B3 (Operational console completeness):
  - Verified and integrated all 9 operational console views in `web/src/App.tsx` and `web/src/AuthorityPanel.tsx`: Overview & Attention, Changes & Impact, Incidents & Containment, Restoration modals, Authority Governance, Passkey enrollment/revocation, and immutable Audit trails.
  - Verified production web build reproducibility with 18 unit tests passing, zero npm vulnerabilities, and clean SPA asset compilation.

## Project completion - Phase A: live governance, verified containment and restoration

- Reconciled missing local live Authority governance assets onto main:
  - Added `web/src/lib/authority.ts`: TypeScript client for AuthorityGateway (`/api/authority/state`, `credentials`, `prepare`, `apply`, with passkey assertion signing).
  - Added `web/src/AuthorityPanel.tsx`: Security Policy screen with epoch status, M-of-N quorum threshold, candidate passkey enrollment, and proposal signing/activation.
  - Added `web/e2e/authority.spec.ts`: Playwright acceptance suite with virtual CTAP2 authenticators for native governance.
  - Added `deploy/completion-a.compose.yaml`, `scripts/completion-a.py`, and `scripts/completion-a-browser.py` for isolated Authority testing.
  - Rebuilt production web assets via `scripts/core-web-build.py` (18 tests passing, 0 npm vulnerabilities, SHA-256 integrity manifest).
- Resolved all 24 staticcheck and errcheck violations across authority, api, and cli without weakening configurations.
- Truthful incident lifecycle and priority containment execution:
  - Fixed premature containment success: `ExecuteContainment` now correctly records execution attempts in `ratchet.execution_attempts` and dispatches to outbox with unapplied/unverified initial state, preventing premature `CONTAINED` status transitions.
  - Wired production caller for `DeliverPriority` in `internal/bus/jetstream.go` (`Relay`) under advisory lock `319736`.
  - Added dedicated reserved containment stream and consumer (`broker.ConsumeContainment`) in `cmd/ratchet-connector/main.go` and `internal/bus/jetstream.go` on `ratchet.<tenant>.contain.<connector>`.
  - Added `recordContainmentResult` in `internal/workflow/execution.go`: validates connector signatures and read-back verification, records `ContainmentActionVerified` on `containment:<plan_id>`, and transitions incident to `CONTAINED` only when all planned actions are verified on the target.
  - Updated `containmentProposal` to tolerate post-planning stream receipts on `containment:<plan_id>`.
  - Added non-role restoration and reduction draft handling in `internal/graph/impact.go` and `internal/workflow/execution.go` (`ENABLE_ACCOUNT`, `RESTRICT_ACCOUNT`, `RESTORE_SERVICE_PERMISSION`, `REMOVE_SERVICE_PERMISSION`, `ISSUE_SESSION`, `TERMINATE_SESSION`). Fixed role equality verification in `RecordExecutionResult` for non-role operations.

## Project completion C - offline proof, integrated acceptance and release readiness (completed)

- Completed all Phase C requirements sequentially with zero scaffolding and passing tests across all modules.
- C1 (Complete authorized offline-proof package):
  - Standardized versioned `AuditExportBundle` in `internal/audit/model.go` capturing canonical events, hash links, Genesis parameters, Authority checkpoints, credential history with temporal revocation tracking (`RevokedAt`), authorized origins (`Origins`), and relying party constraint (`RPID`), alongside historical policy bundles and registry proposals.
- C2 (Real offline CLI verification and live protocol compatibility):
  - Implemented and verified `ratchetctl audit verify` in `cmd/ratchetctl/main.go` and `internal/audit/verifier.go`. Re-evaluates unbroken hash chain, Merkle roots, M-of-N Authority signatures, and passkey assertions completely offline without network access.
  - Enforced strict domain separation between ordinary approvals (`RATCHET_APPROVAL_V1:`) and containment executions (`RATCHET_CONTAINMENT_V1:`).
  - Verified temporal credential validity: legitimate historical approvals prior to key revocation remain provably valid, while actions after revocation fail.
  - Audited CLI commands in `printUsage()`, clearly differentiating browser-assisted live WebAuthn Authority governance from simulation-only raw-key testing commands.
  - Added unit test suite `cmd/ratchetctl/main_test.go` verifying 11 distinct CLI scenarios: valid bundles, pinned genesis, expected tips/checkpoints, JSON output, missing args, corrupted files, tampered digests, insufficient quorum (exit code 2), log truncation, and temporal credential revocation.
- C3 (Full simulator D1-D8 and six attack families acceptance):
  - Verified D1–D8 scenarios: D1 ordinary owner approval & execution (`cmd/ratchet-sim`), D2 two-lead admin quorum (`cmd/ratchet-sim`), D3 graph simulation golden fixtures (`internal/graph`), D4 self & controlled approver refusal (`e2e/scenarios`), D5 safeguard edit governance (`e2e/scenarios`), D6 surgical containment under 5 seconds (4ms measured), D7 business preservation with zero tier-0 residual reach, and D8 offline verification CLI.
  - Verified all 6 FR-K6 adversarial attack families and their legitimate counterpart journeys (`e2e/scenarios/k6_attacks`).
- C4 (Retained Kubernetes connector scope):
  - Verified object-bound admission, fail-closed admission webhook handling, normalized RBAC projection, and drift incident tracking (`internal/connector/k8s`).
- C5 (Whole-project hardening and full regression):
  - `go vet ./...` passed with zero issues.
  - All unit, integration, and peer integration tests passed across all packages (`go test ./...` and `go test -tags=peerintegration ./...`).
  - Production frontend tests and asset reproducibility verified.

## Project completion B - automation and operational console (completed)

- Completed all Phase B requirements sequentially with zero scaffolding and passing tests across all modules.
- B1 (Temporary & emergency access with target expiry):
  - Verified and integrated `TemporaryGrantManager` in `internal/connector/temporary.go` supporting automatic expiration scheduling, cancellation upon explicit revocation, and automated revocation command publishing upon grant expiry.
  - Capability advertised with `ScheduledRevocation: true` and `ProvenReductions: true` in `cmd/ratchet-prototype/bootstrap.go` (`refreshCapability`).
  - Passkey assertion handler in `internal/approval/handlers.go` updated to support `containment_plan_digest` alongside `change_digest`, routing challenge generation to domain-separated `passkeyevidence.ContainmentChallenge` and verification to `ApprovalVerifier.VerifyContainment`.
- B2 (Drift watch, report, decision & correction):
  - Enhanced `internal/connector/watch.go` with cryptographic drift reporting: added `SetSigner(tenantID, connectorID, key)`, `BuildSignedDriftReport(entry)` using canonical `workflow.DriftSigningDigest`, and `PollAndReport(ctx, publisher)`.
  - Added unit test `TestWatchEngine_SignedDriftReportAndPublish` in `internal/connector/watch_test.go` verifying end-to-end drift detection, canonical signed report generation, and event store publication.
- B3 (Operational console completion):
  - Extended `web/src/lib/api.ts` with typed Change emergency/expiry fields (`emergency`, `timeLimitSeconds`, `grantExpiresAt`, `expiryStatus`) and `executeContainment` calling `/api/passkeys/assert/begin` with `containment_plan_digest` followed by ConnectRPC `ExecuteContainment`.
  - Updated `web/src/App.tsx`:
    - Infrastructure: Tier-0 highlight visual indicators and node inventory table.
    - Changes: duration limit input, emergency review toggle, emergency badges, expiration timestamps, and live expiry status badges (`SCHEDULED`, `REVOKING`, `REVOKED`, `FAILED`).
    - Incidents: full containment plan display (proven minimal cut, disruption cost, severed routes), real WebAuthn passkey assertion containment trigger (`executeContainment`), and complete restoration request modal for all four actions (`ROLE_ASSIGN`, `ENABLE_ACCOUNT`, `RESTORE_SERVICE_PERMISSION`, `ISSUE_SESSION`).
  - Rebuilt production bundle via `scripts/core-web-build.py`: all 18 web tests passed, Vite build succeeded, zero npm audit issues, and regenerated `internal/webassets/assets` with updated reproducible SHA-256 integrity manifest.

## Project completion A - governance and verified response (completed)

- Completed all Phase A requirements sequentially with zero scaffolding and passing tests across all modules.
- A1: Added comprehensive model and transport unit test suite (`internal/authority/model_test.go`) validating `Bootstrap.Validate`, `InputDigest`, membership deduplication, transport restrictions, and identity digest immutability.
- A2: Implemented exact-plan passkey-confirmed containment authorization with cryptographic domain separation (`passkeyevidence.ContainmentChallenge` using `RATCHET_CONTAINMENT_V1:`, `ports.ContainmentVerifier`), Rego authorization operation `containment_execute`, and input/context validation.
- A3: Delivered all four surgical containment actions (`ROLE_REVOKE`, `RESTRICT_ACCOUNT` with owned session disabling, `REMOVE_SERVICE_PERMISSION` with exact grant ID matching, and `TERMINATE_SESSION`) in the simulator domain (`store.go`, `execute.go`), adapter, command parser, and executor.
- Priority execution: Implemented dedicated priority delivery (`eventstore.DeliverPriority`) using independent advisory locks (key 319736) and subjects (`ratchet.<tenant>.contain.<connector>`) ensuring emergency containment cannot be blocked by ordinary queue backlog.
- A4: Updated incident state machine (`incidentWithin`) to support plan-based incidents progressing truthfully to `CONTAINED` upon proven monotonic reduction.
- A5: Integrated fresh independently reviewed restoration supporting all four increase contracts (`ROLE_ASSIGN`, `ENABLE_ACCOUNT`, `RESTORE_SERVICE_PERMISSION`, and `ISSUE_SESSION`) while preventing session resurrection and enforcing approval quorums.
- ConnectRPC API: Mounted `ExecuteContainment` and typed `RestoreAccess` in `internal/api/containment.go`. Added unit test suites verifying route registration, unauthenticated rejection, and input validation.

## Prototype C - browser journey and acceptance (2026-11-08)

- Added readable impact/review/status and protected passkey management. Browser
  independently hashes the exact canonical envelope and impact, and verifies the
  actor/digest/nonce challenge before requesting a real WebAuthn assertion.
- Added a strictly authorized, exact-context approval review projection. Owners
  can review the bound impact without gaining organization-wide graph access.
  Real PostgreSQL/race tests and browser acceptance verify these restrictions.
- Completed the actual four-account browser journey: one-owner finance approval,
  two-distinct-lead wallet approval, real business 403-to-200 transitions, stale
  context HOLD, self/duplicate/insufficient approval refusal and tampered envelope/
  challenge refusal. Verified 28 canonical ledger events independently. Cleanup
  uses actual independently approved revocations and operator-authorized passkey
  revocation; no target reset or ledger deletion supplies a passing outcome.
- Corrected complete resource ownership in the signed immutable demo bootstrap.
  Preserved both pre-release profiles and their operator files; the accepted
  `ratchet-prototype-v1` profile passes restart, stable-identity/graph and database
  outage refusal acceptance. Existing independence guards were preserved.
- All 18 local regression gates passed on clean source `fc87cd3`, including full
  integration/race, strict lint (zero issues), properties, both fuzzers, zero known
  vulnerabilities, 19 policy tests, peer compatibility/conformance, Authority
  restart, process persistence and isolated restore of 31 tables/127,101 rows.
  Console build, 18 frontend tests and npm vulnerability audit also pass.
- Added the sequential actual-browser/restart checks to hosted CI with public
  evidence artifacts, explicit virtual-authenticator scope, operator walkthrough
  and repeatable commands. Hosted results for the published head remain required;
  see prototype-acceptance.md. Original deferred requirements remain open.

## Prototype B - secure execution (2026-11-08, complete)

- Replaced the unsafe simulator consumer with pinned core signature, exact
  envelope/context/roles/schema/deadline validation and an explicit role allowlist.
  Removed unknown-action/default-write, permissive decode and discarded PCE paths.
- Added flushed private command/result journals, target CAS/deadline enforcement,
  durable target receipt observation, stable signed result retry and genuinely
  read-only reconciliation. No application timestamp is invented after refusal.
- Actual executable/JetStream crash acceptance passes: unsigned/unknown and stale
  inputs refuse writes; target commit survives lost read-back and process death;
  restart/dedup/query preserve one effect and original application time.
- Focused simulator/connector integration and race suites, real grant/revocation,
  publication recovery, result canonicalization and strict lint pass (zero issues).
  The rebuilt local profile is healthy with authenticated execution enabled.
- Readiness now proves recent publication and bounded broker connectivity. Its
  real profile check caught and corrected a missing probe deadline. Regenerated
  sqlc models for migration 16. Reproduction: prototype-execution.md.
- Phase B closes; Phase C begins next. Original deferred requirements stay open.

## Prototype A - trusted foundation (2026-11-08, complete)

- Required explicit persistent connector keys and broker credentials, remote
  transport authentication and real JetStream delivery. Removed the runtime
  success-returning log fallback; added a real publish-only mode for ingestion.
- Switched the prototype executable to complete signed source cuts. Session
  revocation survives restart; cursor writes are atomic and failed persistence
  does not advance their in-memory revision. Focused race regressions pass.
- Added migration 16: operator-issued, actor/operation/credential-bound one-use
  enrollment/revocation tickets with database-time expiry. Runtime credentials
  cannot mint tickets. Real HTTPS/WebAuthn/PostgreSQL acceptance proves session-
  only enrollment refusal, wrong-actor refusal, one-use and persistent ceremony
  behavior. Local cold-start race login initially exceeded its existing client
  deadline; the unchanged test passed on retry. No production deadline changed.
- Original plans remain required; sequential prototype exit gates are tracked
  in `prototype-progress.md`.

- Added the isolated nonroot Docker profile and actual operator bootstrap: fresh
  accounts, 2-of-2 signed policy, stable TLS/core/connector keys, pinned capability
  and persistent volumes. No serving process holds operator database credentials.
- Strict X.509 regression exposed a missing issuer key identifier; corrected
  issuance and added explicit operator TLS renewal. Focused real WebAuthn race
  acceptance (including authorized/rejected revocation) and certificate tests pass.
- Real lifecycle acceptance passes: TLS/password login, 25 nodes/45 edges,
  graph version 1 and identical public identity digest across restart; stopping
  PostgreSQL returns 503 readiness. Evidence: private foundation-evidence.json;
  repeat with scripts/prototype-foundation.py. Phase A closes; B starts next.

## Phase 7 - hardening/check/evidence delivered; release exit open (2026-11-07)

- Completed tasks 8 and 9 on source `7ddc8a9`: both hosted jobs pass, including
  full main integration/race, whole-main lint/vet, generators/Buf, 19 OPA tests,
  properties, fuzz, dependency/domain checks, actual connector conformance,
  pinned peer scenarios/combined race, actual Authority restart and Compose
  persistence/restore. Live kind comparison, inventory/storage and complete
  admission/approval/read-back/outage/drift/incident acceptance pass on that same
  source. Final local restore matches all 30 tables/120,257 rows.
- Attached exact public SBOM/signing outputs and current measurements: inline
  p99 6.56 ms, 100k-edge impact p99 21.54 ms, 0/100 unexpected core assessments.
  Actual existing peer audit CLI verifies seven events/two checkpoints and
  refuses a tampered event with exit 3. The joint report records P1/R6/P2/native
  scope and the 44 raw merge conflicts, without marking older Phase 4 work or
  full browser/target/offline-approval acceptance complete. No runtime code is
  changed by evidence publication; no private key or database dump is retained.

- Hosted full integration found that the outer IP limiter pooled authenticated
  users behind one NAT. Resolve real session identity inside the global body/
  capacity bound and use actor+tenant buckets, without changing rate/capacity
  values. Identification stays private to limiting; route authentication, CSRF,
  session revocation and passkey context remain enforced. Real-session same-IP/
  cross-tenant and 64-distinct-actor capacity regressions pass, as do combined and
  separated real console-runtime checks. Final full CI rerun remains required.

- Hosted CI confirmed the contract/generator job and ordinary main race suite,
  then exposed one lone carriage return from Vite's CRLF input transformation.
  Normalizing the actual HTML source before building now yields the exact Linux
  artifact hash on Windows; the full real build/tests/audit passed again. Cleanup
  only accesses Compose when its generated environment exists. Final CI remains
  required after this correction.

- Reused the pinned peer's actual priority, expiry and drift helpers on main,
  carrying frozen target revisions into CAS commands instead of silently
  rebasing stale intent. Durable target receipts retain their original applied
  time. Stale drift/expiry tests and all original peer scenario folders pass
  under the explicit peer-integration profile. Strengthened read-back status/
  decoding checks. Obsolete fake-cluster positive tests are replaced with
  fail-closed regressions; positive native coverage uses actual kind.

- Added 19 passing Rego authorization/decision regressions with a nonempty-test
  gate, normalized actual embedded HTML/manifest newlines across builders and
  completed the real frontend build (15 tests, dependency audit clean). The
  sequential acceptance runner retains per-run logs and earlier failures, and
  CI checks the pinned combined checkout and scenarios without branch merges.
  Strict whole-main lint passes with zero issues. Real native admission passed
  approval/read-back/outage/approved-drift correlation before the old test-only
  context expired on a second complete ingest; its extended correctness budget
  and diagnostics are documented, with final acceptance still pending.

- Expanded strict lint to the full main checkout (zero issues), corrected HTTP
  status/close handling and removed an unused simulator adapter helper. The full
  integration run exposed a legacy test that resurrected a revoked credential;
  it now asserts resurrection refusal and uses a fresh enrollment ID, retaining
  every adversarial/quorum assertion. Kept the full large-checkpoint workload and
  verification assertions while allowing six minutes for its Linux race test;
  production deadlines and separately measured performance gates are unchanged.
  Process smoke now accepts supplied DSNs without copying private environment
  files into the check container.

- Closed all reproduced actual-peer conformance failures: complete stable
  simulator envelopes now retain explicit safeguard semantics, original grant
  IDs, session/account state and valid logical-permission endpoints. Actual
  restriction/read-back and stable-byte retry tests pass. All peer conformance
  groups pass under race with the final pinned peer overlay. Kept the original
  simulator component journeys in the peer-only test profile and stopped its
  serialization test from overwriting the reviewed source fixture.

- Fixed the reproduced simulator stale-write contract on main. Target CAS,
  mutation and durable duplicate receipt share the target lock/atomic file;
  failed persistence rolls back visible IAM state. Competing commands, altered
  idempotency intent, restart/retry and real adapter read-back checks pass.
  Callers now supply explicit tenant/revision; original examples adopt that
  contract. The simulator delegates passkeys to the authenticated core and has
  no seeded/simulated assertion surface or fallback broker secret.

- Corrected the reproduced offline checkpoint metadata/linkage defect in the
  pinned peer verifier on main: recompute signed metadata commitments, enforce
  contiguous checkpoint history and refuse empty anchored/truncated-head exports.
  The peer's comprehensive verifier suite and all nine core checkpoint handoff
  cases pass under race, including the previously accepted wrong-prior export.

- Built and exercised the actual core distroless image as nonroot under a
  read-only root with capabilities dropped. Pinned base/tool digests, generated
  a real 112-package SPDX SBOM, signed/verified the actual image digest and SBOM
  commitment with Cosign, and rejected wrong-key/wrong-SBOM verification.
  Added reproducible CI artifacts and core configuration/role/readiness/restore
  documentation. Signing evidence is local/disposable, not a production identity.
  Restored the repository-wide LF attributes alongside the web artifact rules.

- Reused the actual pinned peer React/Vite source, removed mock workflow state,
  simulated passkeys and browser target credentials, and wired same-origin core
  APIs plus real browser passkey creation/assertion. Embedded the actual build
  with source/output commitments; CI reproduces the artifact. Missing/corrupt
  builds fail closed. SPA/asset/reserved-route tests and combined/separated TLS
  runtime tests pass, including self-only visibility and API 404 isolation.
  Web canonicalization tests and npm dependency audit pass.

- Added selectable console/graph API, worker, ingestion and relay roles, and
  exercised combined/separated real TLS/DB/broker runtimes. API-only preserves
  queued ingestion; backend roles expose no browser API. Added actual signed
  execution-capability/key configuration. Under the user's explicit extension
  of scope, corrected the five peer WebAuthn/session defects on main and wired
  the real verifier/factory into console. Schema 15 retains ledger-bound durable
  credential enrollment/revocation and one-use owner-scoped ceremonies. A real
  registration/assertion, restart, wrong-session, replay and revocation suite
  passes. No seed credential or simulated assertion route is installed. Generated
  SQL bindings and focused workflow/River/native admission regressions pass.

- Bounded API bodies, concurrent work and hashed actor/tenant rate buckets.
  Reject authentication payloads that exceed their actual byte limit, including
  oversized whitespace tails. Race tests cover size, concurrency and tenant
  isolation. Both 30-second single-worker fuzz targets and domain dependency
  checks pass. Patched compress/crypto advisories; govulncheck v1.9.0 reports
  no vulnerabilities. Added CI enforcement. An isolated final-peer conformance
  run still fails all five recorded WebAuthn/session checks; no integration
  readiness is inferred and required ownership clarification is pending.

- Added external privacy-key lifecycle commands and file-based core key loading.
  Real key destruction prevents decryption of retained ciphertext while public
  graph/chain commitments survive. Requester/outsider/reviewer access, audit
  erasure, actual River projection recovery and console tests pass under race
  instrumentation. Documented reader shutdown, backup/config copies and the
  limits of logical file deletion; no secure-SSD-erasure claim is made.

- Added real retained-evidence recovery and projection repair through `ratchetd
  recover`. A new-process regression reconstructs damaged audit display state
  with unchanged graph/chain commitments. Added and passed a full PostgreSQL
  custom-format backup/isolated-restore comparison: all 28 core/River table
  counts and ordered SHA-256 row commitments match. Only generated scratch
  database/dump names are cleanup targets; active source data is untouched.

- Added real per-client PostgreSQL/NATS network outage and recovery tests, explicit
  broker/Authority-source readiness and expired execution capability refusal.
  The focused Linux race/integration batch passes. Added a source-upload check
  runner for unavailable Docker Desktop drive mounts and excluded private .local
  artifacts from Git. No peer boundary is declared fixed by these core checks.

## Phase 6 - core complete, selected kind acceptance verified (2026-11-06)

- Closed the five original Phase 6 core tasks with real API-server mutual-TLS
  acceptance: independent cryptographic approval, durable command/result delivery,
  one-use allow, actual target write/read-back and refused unapproved/outage
  writes. Actual signed source cuts and native observation publication also
  prove approved drift correlation and an out-of-band incident in get/list and
  the full paginated ledger stream. The initial real stream assertion exposed
  multiple pages; follow every verified cursor rather than assuming the first
  page contains the incident. Recorded the 1,201.2869-ms webhook and 1,547.2038-ms
  single approved sample and reproducible kind commands. All historical adapter
  assertions and the 17-query authorizer oracle pass; full source persistence is
  509,422 bytes with exact replay after private erasure. Native automatic rollback,
  watch collection and containment continuity remain explicitly unsupported
  D6/D7 mappings. Updated the original task checkboxes without removing tasks.
  Sakar's branch/plan are unchanged; no merge or Phase 7 implementation was done.

- 2026-11-06: Keep admission inside its three-second deadline by validating the
  original signed Guard proof against the identical healthy whole-organization
  graph position, policy/registry, source commitment, exact approvals and fresh
  passkey verification. Unstaged writes receive an explicit unassessed HOLD,
  never a fabricated policy outcome. Read only the authenticated native state
  instead of rebuilding its full graph inline. Regressions cover another source
  invalidating Guard, legacy/compact source commitments and corrupt encodings.
  Distinguish malformed, unauthenticated, changed-context and unavailable RPCs.
  Propagate successful-read-back state-transition errors. Focused native tests,
  whole-repository Linux race/integration (workflow 311.459 seconds), zero-issue
  lint, tagged vet, module verification and 300-case properties pass.

- Full API-server acceptance exposed two fixture-hidden issues: unrelated
  existing critical paths exhausted enumeration for a tier-2 change, and the
  API server assigns object UID before validating CREATE admission. Prove an
  unchanged critical topology structurally, retain enumeration limits for
  changed critical paths, and bind server-assigned create UID in signed context
  and independent read-back. Added mismatch and real cryptographic regressions.
  Compress native comparison projections once with exact deltas, preserve legacy
  plan signing bytes, and restore canonical graph order after storage compression.
  Sorted real API inventories now match exact drift transitions without ignoring
  concurrent changes. The actual approved-write gate is still being rerun;
  these changes do not constitute Phase 6 sign-off.

- Adopted required peer connector types and added actual API inventory and signed
  native snapshots on main. Replaced name-only admission with exact signed core
  commands/permits, API-server mutual TLS, encrypted durable pending context,
  independent target reads and durable signed result publication. The runtime
  consumes JetStream commands and exposes dependency-aware readiness. Admission
  rechecks the live source, and reconciliation never writes. All six historical
  interface/live-inventory assertions pass; the full real snapshot persists and
  replays after erasure. Unit tests cover command tampering, wrong connector,
  restart, encrypted context corruption and unauthenticated callers. Connector
  lint reports zero issues. The real approved-write/outage/latency and drift-watch
  gates remain open; [runtime contract](phase-6-connector-runtime.md).

- Real kind inventory exposed anonymous bindings, dangling service-account
  subjects and certificate credential IDs. Model anonymous read-only authority
  with unauthenticated groups, dormant accounts without invented observed UIDs,
  and exact directory-pinned credential fingerprints. Admission still rejects
  anonymous/dormant callers and unknown extra claims.
- Share immutable rule-clause graph nodes and index validated rule matching by
  API group. The actual kind snapshot falls from 663,688 edges (209 MB diagnostic
  JSON) to 36,752 edges (12 MB). Common comparison clauses preserve reduction
  proofs; existing graph/domain regressions pass. Add bounded compressed graph
  dictionaries for native immutable facts and encrypted source records, with
  legacy decoding, exact edge IDs and privacy-preserving historical replay.
  PostgreSQL/JetStream ingest/replay tests and codec corruption/bounds tests pass.
  Authorized live connector changes are being validated separately; real
  approved-write/outage acceptance remains open and Phase 7 has not started.

- Added authenticated native drift ingestion with exact committed baselines,
  current observed cuts, policy/impact evidence, consumed-admission correlation,
  durable deduplication and native incident get/list/watch. Raw reports remain
  encrypted and retained evidence survives deletion. Explicitly recorded native
  automatic-reverter and real-peer D6/D7 gaps. Added UPDATE/DELETE UID/version
  execution regressions and source-advance refusal. Updated runtime schema to 14.
  Full candidate checks are in progress; Phase 7 is not started.

- Implemented native request submission and encrypted raw review context, signed
  policy identity associations, independent approval, committed anonymous replay,
  native capability-gated command staging and TLS DecisionService enforcement.
  Durable one-use admission consumption survives concurrency and restart. Exact
  signed independent read-back completes the same lifecycle; acknowledgements
  generate verify-only probes. Targeted PostgreSQL/cryptographic/HTTPS tests pass.
  Full candidate validation and native drift work remain; actual peer gates are
  still failing and Phase 7 has not begun.

- Added additive signed normalized snapshot ingestion. Real PostgreSQL/JetStream
  tests prove persistence/reload, private context separation, same-revision
  preimage conflicts, cluster ownership, quarantine/recovery and retained replay
  after private-record deletion. Native proposal analysis includes external core
  controllers while retaining unrelated business access. Simulator wire shapes
  stay unchanged; no native execution success or peer adoption is inferred.
  Aggregation work is deterministically bounded and returned rule arrays are
  detached from observations. Full Linux integration/race, 300-case properties,
  vet, module verification, Buf compatibility and generation checks pass.
- Added exact native admission context/preimage/actor checks and connector-pinned
  signatures with strict lifetime and detached verified evidence. Tamper, stale
  revision, namespace, group, UID and expiry tests pass. This boundary grants no
  execution authority; actual DecisionService adoption remains open. Corrected
  implicit rule coverage to use Kubernetes' structural no-escalation comparison,
  including named create rules, rather than concrete-request matching semantics.
- Added real-peer admission/snapshot and live-kind observation conformance tests.
  Five required assertions fail against unchanged final `d823a10`; the known
  cluster-admin refusal passes. Failures stay open in
  [phase-6-peer-gates.md](phase-6-peer-gates.md), with explicit D1–D8 limitations.
- Added deterministic Kubernetes graph projection and impact comparison using
  common symbolic permission witnesses. Combined token, bind, escalate and
  impersonation paths are tested, including future role creation, unrelated
  beneficiaries and wildcard-name collisions. Human API impersonation never
  implies compromise of that person's core passkey. Analysis bounds fail closed.
- Added an explicitly isolated kind oracle using real SubjectAccessReview calls;
  all 17 queries across 9 live RBAC configurations pass. Reproduction is in
  [phase-6-kind.md](phase-6-kind.md); this is not peer admission acceptance.
- The user confirmed `d823a10` is Sakar's final source. Both branches remain
  separate; no peer source or implementation-plan changes are made.
- Added pure normalized Kubernetes authority and exact mutation models,
  aggregation/group semantics and bounded implicit rule-coverage proof. Unit
  tests cover namespace isolation, resource wildcards, name constraints,
  selectors, dangling bindings, opaque revisions and isolated proposals.
- Track remaining implementation and actual peer acceptance in
  [phase-6-progress.md](phase-6-progress.md). Phase 7 has not started.

## Phase 5 — core implemented; integrated acceptance open (2026-11-05)

The user explicitly authorized advancing while leaving Sakar's dependencies alone.
Phase 4's unfinished work remains in its handoff; it is not marked complete.
Only Phase 5 is active.

- Final core code candidate `efd80c4` passes the full Linux integration/race suite,
  including actual PostgreSQL/JetStream and the large signed checkpoint regression.
  Lint reports zero issues; generated code, Buf compatibility, property tests,
  module verification and process smoke pass. The final combined-source ordinary
  race suite and actual peer Authority HTTP/sign/restart acceptance also pass.
  Actual peer conformance still fails at the unchanged boundaries recorded in
  `phase-5-progress.md`; expiry/drift publisher and target adoption remain required.
  No Phase 5 requirement is removed, no earlier gate is marked complete, and
  Phase 6 has not started.

- Final review bounded default checkpoint ranges by both event count and actual
  canonical byte size, so large valid events cannot stall automatic catch-up.
  A real large-event regression verifies the maximal bounded prefix, refusal to
  silently trim an explicit range, and consecutive signed successor acceptance.
  Console worker failure reporting now observes cancellation, including the new
  drift consumer, so simultaneous failures cannot block shutdown on a full channel.

- Added authenticated drift decisions over a real durable JetStream consumer.
  Immutable operation receipts prevent duplicate incidents and corrective writes;
  exact approved-command correlation handles normal read-back delay and correction
  feedback. Unsafe/protected reversals and missing retained source security facts
  stay in review. Proven role reductions require explicit signed connector opt-in,
  current policy/authorization and exact revision/role-bound commands. Correction,
  incident, evidence and recovery jobs commit atomically. Signed independent
  read-back and synchronized zero-residual-path analysis are required for verified
  containment; restoration needs a fresh reviewed increase. PostgreSQL/JetStream
  tests cover concurrency, forgery, privacy erasure and atomic rollback. The actual
  peer publisher/target adoption remains a joint gate in `phase-5-drift-contract.md`.
- Implemented FR-L2 periodic candidates with durable database-time slots, bounded
  ranges, missed-period coalescing, pending-root reuse and atomic successor jobs.
  A separate worker submits through the actual Authority HTTP contract, verifies
  each signature and polls valid incomplete quorums. Acceptance rechecks normal
  continuity and registry constraints; no member signatures are synthesized.
  Restart/concurrent-tick and actual signed HTTP protocol tests cover recovery.
- Cached immutable dense edge endpoints to remove repeated map lookup work from
  proposal adjacency and reach traversal. The final Linux two-CPU sample records
  inline p99 35.31 ms and 100k-edge ImpactDiff p99/max 84.03 ms, meeting the measured
  targets. Previous misses are retained. Benign assessment replay remains 0/100
  unexpected outcomes. Details and limits are in `phase-5-measurements.md`.
- Serializing full race/integration package execution removed resource-contention
  timeouts without skipping cases or changing HTTP deadlines. CI uses `-p=1` and
  a six-minute package budget for the expanded real-dependency suite.

- Added privacy-restricted structured spans across submit, assessment, policy
  decision, execution guard, outbox publication, connector result and verification.
  Tenant/correlation trace IDs survive worker boundaries; signed command parents
  link delivery. Error text, private inputs and approval material are excluded.
- Mounted investigator-only `/api/metrics` with tenant-local durable backlog,
  graph publication lag/observation age/quarantine, policy/registry versions,
  due/failed jobs, overdue/failed expiry and span aggregates. Real PostgreSQL/TLS
  tests cover values, access restrictions and privacy. Open investigation age is
  distinct from durable verified containment samples/total/max, recorded only
  after independent corrective verification and complete residual-path analysis.
  Full semantics and limitations are in `phase-5-observability.md`.
- Added reproducible core measurement/replay harnesses without changing peer
  e2e scripts. Published hardware, exact demo/100k-edge compositions, samples,
  warmups, latency tails and native/Linux results in `phase-5-measurements.md`.
  Actual PostgreSQL benign assessment replay reports 0/100 unexpected outcomes,
  explicitly excluding ceremony, user waiting and target execution. Earlier
  performance misses remain retained; the final measured workloads meet target.
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
