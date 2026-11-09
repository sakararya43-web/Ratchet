# Published main review: completion A/B/C

Reviewed GitHub main candidate `1b7e1be2b8bee067786383ab0d7f0f767b55aa2d`
on 2026-11-08. This is a review, not a completion or release sign-off.
No production source was changed, committed or pushed during this review.
The existing dirty local checkout was preserved. Published source was inspected
in `.local/review-main-1b7e1be` from `git archive origin/main`.

## Verdict

The screenshot's statement that nothing was missed and all handoff phases are
fulfilled is not supported. Recent commits add substantial components, but the
new completion phases A, B and C remain partial. The older accepted prototype
A/B/C is a different milestone and must not be used as proof of their completion.

In addition to the CI lint failure, confirmed source defects include reporting
containment/read-back success at dispatch, absent production priority-consumer
wiring, incomplete restoration and automation contracts, and offline verification
accepting three corrupted proof cases. Fixing lint alone cannot establish release
readiness.

## GitHub Actions: exact red check

- [Standard CI: passed](https://github.com/sakararya43-web/Ratchet/actions/runs/42474909268).
- [Core phase checks: failed](https://github.com/sakararya43-web/Ratchet/actions/runs/42474909221).
- [Failing core-tests job](https://github.com/sakararya43-web/Ratchet/actions/runs/42474909221/job/128714064550).
- Core contracts/generation, module verification, vet, ordinary race tests,
  embedded console reproduction and image/supply-chain checks passed before lint.
- `Core lint`, using golangci-lint v2.15.0 and `.golangci-core.yml`, fails with
  **24 findings: six errcheck and eighteen staticcheck**.

| Finding | Count | Files |
|---|---:|---|
| Unchecked output errors | 6 | `cmd/ratchetctl/main.go`: 620, 626, 632, 641, 679, 681 |
| Capitalized error strings | 3 | `cmd/ratchet-authority/secure.go`: 71, 75; `cmd/ratchetd/enrollment.go`: 35 |
| Numeric HTTP status literals instead of constants | 12 | `internal/api/authority.go` and `internal/authority/transport.go` |
| Boolean/switch simplifications required by configured staticcheck | 3 | `internal/authority/transport.go`: 47; `internal/connector/sim/executor.go`: 109; `internal/workflow/incident.go`: 149 |

These span earlier Authority work and newer CLI/workflow changes. They are not
evidence of a Git merge conflict. `go vet` passing does not satisfy the stricter
lint configuration. Deprecation warnings are not the reported failure.

The subsequent OPA, browser prototype, real PostgreSQL/JetStream integration,
dedicated Authority database, persistence, properties/fuzz/vulnerability,
connector conformance and compatibility stages are **skipped** in this run.
They are not green gates for this candidate. Other latent failures can surface
after lint is corrected.

## Work delivered versus remaining

The three new published commits are:

- `cc8b015`: containment/restoration additions.
- `8246378`: temporary access, drift and console additions.
- `1b7e1be`: offline verification and CLI additions.

These are implementation increments, not verified phase completions.

| Handoff area | What exists on published main | Remaining or defective | Verdict |
|---|---|---|---|
| A1 live Authority | Native evidence verifier, independent SQL service, signed gateway, new Authority model tests | The live Authority UI, native browser journey and completion setup/profile from this checkout are absent from published main; full runtime/restart/CI acceptance is not established | Partial |
| A2 exact-plan authorization | Mounted ExecuteContainment; distinct containment challenge/verifier; responder/policy/registry/expiry checks; reduction simulation | Browser does not independently recompute the plan/challenge as required; changed graph context is not rejected exactly; durable end-to-end retries/recovery are not implemented by input-validation tests | Partial |
| A3 four actions and priority | Additional parser/executor branches, simulator account/session/restoration operations, priority outbox method | No production caller of DeliverPriority; no priority JetStream stream/consumer/reserved worker in the executable; source/target revisions and action preimages are not properly bound; service grant IDs still reach role-based mutation/read-back | Incomplete |
| A4 verified incidents | Additional incident event branches and a direct IncidentContained write | Workflow sets Success/ReadBackVerified/AppliedAt and CONTAINED during outbox insertion, before target execution; no per-action read-back/recovery/residual terminal proof | Incorrect completion behavior |
| A5 restoration | New intent names, API classification, incident matching and target methods | Non-role requests fail existing graph Draft and execution.prepare; RESTORE_ACCESS purpose is recognized by the connector but not staged by the core; full independent review/execution/read-back journeys are missing | Incomplete |
| A6 acceptance | New negative input tests and previous component foundations | No current four-action browser-to-target/backlog/crash/partial-failure/restoration acceptance; current core CI stops before relevant gates | Open |
| B1 temporary/emergency access | UI duration/emergency/status fields, advertised signed capabilities, new connector purpose branches; pre-existing core timers | Existing temporary manager has no production constructor call; EXPIRE_GRANT parser expects ROLE_REVOKE but core retains original ROLE_ASSIGN envelope, and deadline rules disagree; actual expiry/reconnect/read-back acceptance is missing | Partial/incompatible |
| B2 drift | SetSigner, BuildSignedDriftReport, PollAndReport and a publisher unit test | No production Watch/PollAndReport wiring; core signs DRIFT_REDUCTION while parser accepts DRIFT_CORRECTION; cursor/publication durability and real autonomous correction remain unproved | Partial/incompatible |
| B3 console | Tier-0 inventory styling, emergency/duration/expiry fields, containment button, restoration form | Focused reach/provenance/path views, side-by-side impact, live Authority UI, actor-bound stream consumption, full audit search and truthful incident progress are not complete; restoration kind is guessed from strings and required Access blocks empty account-enable input | Partial |
| B4 acceptance | Earlier prototype browser test and component tests | No new integrated browser suite proving expiry, autonomous drift, full restoration and stream/degraded-state flows | Open |
| C1 complete proof export | Additional credential/policy/registry fields in AuditExportBundle | No production producer of that complete bundle from the actual core ledger; existing core chain export is a separate format; required original envelope/provenance integration remains missing | Partial |
| C2 offline verifier/CLI | CLI tests, revocation-time logic, policy/registry digest and signature-count checks | Three corrupted proofs accepted in reproduction; policies/registries count signatures without verifying them; credential ID ignored; native COSE/RP/UV/ceremony and historical registry/checkpoint handling incomplete | Fails security acceptance |
| C3 D1-D8 and six attacks | Existing simulator/component/scenario tests and prior ordinary browser journey | No same-candidate complete real UI/core/target/CLI portfolio; dispatch timing is not verified revocation; actual D6/D7 and native offline-approval proof remain unestablished | Open |
| C4 Kubernetes | Prior selected real-kind implementation and evidence retained | No fresh same-candidate real-kind regression or demonstrated broader watch/correction/containment parity; keep selected scope/deferrals explicit | Prior foundation; current acceptance open |
| C5 hardening | Current ordinary CI, contracts, web build and supply-chain checks pass; earlier hardening foundations remain | Strict lint fails; later required gates are skipped; no complete final-candidate runtime/recovery/backup/security portfolio | Not complete |
| C6 release | P2/R6 limits are documented | P0/integrated gaps, current failing checks and required contributor review remain; phase commit process also falls short of five useful commits per phase | Open |

## Critical source findings

### 1. Containment success is recorded before any target read-back

`internal/workflow/containment.go` inserts priority outbox rows at line 351,
then sets `Success: true`, `AppliedAt: now`, and `ReadBackVerified: true` at
lines 361-364. It writes an incident with `Status: "CONTAINED"` at line 375
and returns `Executed=true` after staging.

There is no target I/O/result wait in this method. Its latency therefore measures
validation/staging, not verified revocation. The advertised four-millisecond D6
claim cannot establish click-to-read-back containment. The console reinforces
the unsupported conclusion in `web/src/App.tsx:198`.

Commands use `snapshot.Version()` as expected target revision (line 310), rather
than the exact connector source revision and sequential target preimages.
No normal Change/execution_attempts/reconciliation state is staged for these
action requests, while `RecordExecutionResult` expects it in
`internal/workflow/execution.go:252` and following.

### 2. Priority delivery exists as an unused component

`internal/eventstore/outbox.go:72` defines DeliverPriority. A complete production
source search finds no caller. `cmd/ratchet-connector/main.go` starts only
EnsureExecution/ConsumeExecution. `internal/bus/jetstream.go:136` and line 203
bind the ordinary `.exec.<connector>` stream/subject, not `.contain.<connector>`.
There is no corresponding reserved priority consumer. A distinct outbox method
and subject alone do not deliver the planned priority workflow.

### 3. Non-role restoration is not supported by the downstream core

The API adds ENABLE_ACCOUNT, RESTORE_SERVICE_PERMISSION and ISSUE_SESSION, but
Submit still calls graph Draft (`internal/workflow/service.go:326`). Draft
supports roles and selected safeguard changes, not these increases
(`internal/graph/impact.go:268`). Execution preparation also explicitly accepts
only ROLE_ASSIGN/ROLE_REVOKE (`internal/workflow/execution.go:99`). New valid
enum/intent names and target methods therefore do not complete restoration.

### 4. Automation components are not wired to the executable

Production source searches find no constructor/caller of NewTemporaryGrantManager,
NewWatchEngine or PollAndReport outside their definitions/tests. Existing durable
core timers remain valuable, but the new connector adoption is incompatible:

- Core expiry clones the original TEMPORARY_GRANT envelope before setting the
  EXPIRE_GRANT purpose (`internal/workflow/grant_expiry.go:111`). The parser
  demands a ROLE_REVOKE envelope for this purpose
  (`internal/connector/sim/command.go:98`) and applies the original envelope
  deadline equality check to a later expiry deadline.
- Core correction uses DRIFT_REDUCTION
  (`internal/workflow/drift_execution.go:80`); the parser accepts only
  DRIFT_CORRECTION (`internal/connector/sim/command.go:103`).

### 5. Offline security failures were reproduced, not inferred from comments

Review-only diagnostic tests were added only to the isolated exported source.
They reuse the published CLI's valid fixture, first verifying it successfully
against its pinned genesis, expected tip and expected checkpoint. Each test then
changes one proof condition and requires rejection.

| Mutation | Expected | Actual |
|---|---|---|
| Remove the assertion from an approval event | Reject incomplete approval evidence | Valid=true; approvals_verified=0 |
| Replace assertion CredentialID with never-enrolled bytes | Reject unknown credential | Valid=true; approvals_verified=1 |
| Add policy with duplicate untrusted signer and forged signature bytes | Reject invalid/non-distinct signatures | Valid=true; policies_verified=1 |

All three negative tests failed, with container test exit code 1, against the
published candidate plus this diagnostic test only. They ran with Go race
instrumentation. The unchanged fixture passed first in every case.
Diagnostic source: `.local/review-main-1b7e1be/cmd/ratchetctl/review_repro_test.go`.
Output: `.local/review-offline-refusals.log`.

Relevant source: `internal/audit/verifier.go:168` makes assertion verification
optional, line 382 selects by actor/tenant without CredentialID, and policy and
registry loops at lines 309/338 check digest/signature count without verifying
signature cryptography or distinct authorized signers. Additional native-proof
gaps include PKIX-only approval key parsing, optional RP/origin constraints,
presence-only flag checking and absent proper historical registry application.

### 6. The screenshot's browser-job conclusion is incorrect

`.github/workflows/core.yml:87` runs scripts/prototype.py, prototype-browser.py
and prototype-foundation.py. That is the older ordinary-access prototype journey.
It does not run the new native Authority browser ceremony. The following files
from this checkout are absent from published main:

- `web/src/AuthorityPanel.tsx`, `web/src/lib/authority.ts`.
- `web/e2e/authority.spec.ts`.
- `scripts/completion-a.py`, `scripts/completion-a-browser.py`.
- `deploy/completion-a.compose.yaml`.

Therefore removing A1.5 from limitations merely because a browser step exists
would hide a real gap. This checkout's earlier successful native governance run
does not establish that the different published candidate contains that flow.

## Next work, in order

1. Preserve/reconcile the still-local live Authority changes with the three new
   published commits; do not overwrite either implementation or rewrite roots.
2. Fix all lint findings without suppressing configured checks. Rerun the exact
   configured lint and subsequent mandatory gates to expose further failures.
3. Reopen Phase A: correct dispatch/verified-state semantics, wire durable priority
   execution/recovery, implement supported restoration/target contracts and run
   actual four-action, outage, residual, restart and business acceptance.
4. Finish B's actual expiry/drift adoption and complete console/stream flows.
5. Finish C's real core export/native offline security and same-candidate D1-D8,
   selected native, recovery/supply-chain/full hosted acceptance.

FR-X6 break-glass and FR-L5 witnessing remain explicit P2; documenting them is
correct but does not close the unfinished mandatory implementation. No shared
password, unsigned emergency route or softened proof verifier is an acceptable
shortcut. Do not call the entire product complete because its ordinary unit
suite passes.
