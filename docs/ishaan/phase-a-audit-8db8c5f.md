# Phase A follow-up audit: 8db8c5f

Reviewed published main `8db8c5f023d7d6f7a93dfdc407036dfbc35092c1` on
2026-11-08. Existing local uncommitted work was preserved. This review changed
no production source and made no commits or pushes.

## Current checks and delivered commits

Both hosted workflows pass on this exact commit:

- [CI](https://github.com/sakararya43-web/Ratchet/actions/runs/42502086670).
- [Core phase checks](https://github.com/sakararya43-web/Ratchet/actions/runs/42502086609).

Six commits follow the earlier reviewed `1b74684`:

| Commit | Change confirmed in source |
|---|---|
| `7d025d3` | Authority nested state/digest types, RP/origin enrollment, credential selector, policy UI, challenge verification; legacy listen flag |
| `1089ffe` | Connector-source CAS revisions, sequential revision numbers, replay lookup, pending rather than executed dispatch |
| `6791b89` | Per-command locks replace the global executor mutex; account restriction read-back includes zero active sessions |
| `e1e8609` | Distinct expected request IDs replace raw verification event counts; attempted residual check |
| `edfb570` | Execution preparation accepts the four restoration kinds; incident-aware restoration kind selection |
| `8db8c5f` | Checks every Phase A delivery box in the progress document |

The five implementation commits are meaningful progress. The all-complete
checklist is not supported by the remaining defects and missing acceptance.

## A1-A6 status

| Task | What improved | Still required | Verdict |
|---|---|---|---|
| A1 live governance | UI reads authority.genesis/proposals, sends active enrollment with RP/origin, handles array digests and checks the challenge; policy buttons added | Secure native bootstrap/profile, editable actual policy content, independent artifact hashing, working member removal/credential rotation and full browser ceremony/core-adoption acceptance | Partial |
| A2 exact-plan authorization | Uses connector source revision, serial action revision numbers and prior-dispatch lookup; Executed=false/latency=0 at staging | Reject/review changed graph context correctly; compute sequential semantic preimages; make exact retries recover after context/expiry changes; retain complete confirmation/recovery integration | Partial |
| A3 four real priority actions | Per-command locks permit different commands to progress independently; existing priority stream/consumer remains wired; account restriction checks sessions | Exact service grant removal fails; session planner/owner/command contract remains inconsistent; no new four-action/backlog/crash acceptance | Incomplete |
| A4 incident lifecycle | Distinct planned request IDs are checked; dispatcher/UI now describe pending work | Residual verification fails open on context/query/path errors, does not wait for the confirmed source cut, and result validation/recovery remains incomplete | Incorrect terminal proof |
| A5 restoration | Early role-only preparation guard is removed and RESTORE_ACCESS is reachable; incident-aware operation inference added | Explicit typed requests/original verified-action binding; exact grant/session semantics; replacement-session correctness and complete independent-review/read-back acceptance | Partial |
| A6 acceptance | Existing workflows remain green; browser spec has more rejection probes | No new Go integration tests; Authority spec still does not execute the full ceremony; no current four-action/restoration/recovery/business portfolio | Open |

## Critical remaining findings

### 1. Residual check fails open

`internal/workflow/execution.go:578` calls the ordinary authorization context
with synthetic actor `containment-verifier` and operation `containment_verify`.
The signed repository policy does not grant that operation, and the synthetic
actor has no established graph membership. The context call can therefore fail.

The code checks residual paths only if that call succeeds. On a context error,
nil snapshot or path-analysis error, it falls through to writing CONTAINED.
The quarantine query at line 572 also discards its error. It does not require a
source revision at or beyond the actual verified target effects.

Thus adding a residual-check block has not established fail-closed terminal
verification. Existing ordinary authorization must not simply be weakened to
make the synthetic actor work; implement a proper internal verified-state path.

### 2. Exact service-grant removal still does not remove the grant

`cmd/ratchet-sim/domain/execute.go:72` routes both REVOKE_ROLE and
REMOVE_SERVICE_PERMISSION through RevokeRole. The latter compares RoleID, while
the containment contract supplies the original grant ID.

A review-only test against the actual current simulator Store selected a seeded
service account and an actual grant, then executed REMOVE_SERVICE_PERMISSION
with its grant ID and exact current CAS revision. The method returned a receipt,
but the grant remained and the target revision did not advance:

`original service grant remains ... receipt revision=1001 before=1001`

The race-instrumented diagnostic failed with test exit 1. Source and output are
under `.local/review-main-8db8c5f/service_grant_test.go` and `diagnostics.log`.
It used isolated state and did not alter any running profile or production file.

Read-back still compares grant IDs against role-ID lists, so merely broadening
preimage boolean conditions cannot fix this semantic mismatch.

### 3. Secure Authority setup remains a legacy-server path

The formerly unsupported `--listen` flag now exists, but only the legacy server
path was extended. The unchanged Compose command still omits the `secure`
subcommand and its independent SQL/bootstrap configuration. The script still
starts PostgreSQL without completing the native enrollment/pin/core ceremony.

This fixes flag parsing, not the required secure setup. Simply allowing wildcard
binding in secure.go does not wire that mode into the profile.

### 4. Policy proposal is hardcoded and not independently hashed

`web/src/AuthorityPanel.tsx:176` submits a hardcoded authorization module with
`allow if { true }`, an empty data object and no complete change-decision module.
The user can edit version/description but cannot supply/review the actual desired
modules/data. It is neither the real selected signed policy nor a complete
working governance flow.

The new client verifies that the challenge binds the server's signing digest,
but does not independently reconstruct that digest from the actual canonical
input or policy/registry artifact. Credential allow-list descriptor IDs also
still need the proper native browser decoding path.

Candidate enrollment is hidden once the actor is already enrolled
(`!isEnrolled` at line 277), blocking replacement-key enrollment through the UI.
Registry proposal construction retains all current members and only appends a
new actor, providing no complete member-removal/key-replacement flow.

### 5. Fresh-context and sequential preimage gaps remain

`internal/workflow/containment.go:191` still allows a graph newer than the plan
rather than enforcing the promised fresh-review semantics. Although target CAS
numbers now increment from the correct connector source, each action's role
preimage is collected from the original merged snapshot. Multiple actions on
the same identity can therefore use preimages invalidated by earlier actions.

The replay lookup runs after expiry/context/proof/re-simulation checks. A true
retry after its original actions changed the graph may fail before it can return
the existing durable operation. There are still no dedicated containment
reconciliation jobs demonstrating the required uncertain/restart portfolio.

### 6. Restoration is broader but not fully typed or verified

The role-only guard fix is genuine. However, the API still infers operation kind
from strings/prefixes and falls back to those guesses. It has no explicit typed
operation plus original verified action ID. Validation for non-drift incidents
still matches the proposed actions, not proof that the referenced effect was
independently verified.

The UI still requires Access for all restoration requests, despite account
enable needing no role. Service-grant and session plan/target mapping and graph
postimage issues remain. No new full review-to-target restoration tests accompany
the allowlist changes.

### 7. Phase A acceptance is not established by current CI

The only changed test file in these six commits is web/e2e/authority.spec.ts.
No Go integration/recovery tests or hosted workflow steps were added.

The Authority spec still does not actually complete genesis, policy quorum,
activation, core adoption, member removal, threshold transition and credential
rotation. It accepts HTTP 404/503 among certain negative outcomes and conditionally
clicks enrollment followed by a sleep without asserting successful enrollment.
Those can pass when the expected service/operation is absent.

Hosted core CI still runs the ordinary prototype browser wrapper, not the
Authority browser wrapper. Green existing CI remains valuable regression
evidence, but it does not validate the new complete Phase A ceremony or all four
action/restoration/recovery flows.

## Conclusion

Phase A has five additional useful feature increments and a documentation commit.
Several earlier concrete defects are fixed: nested state contracts, the global
executor mutex, graph-version CAS misuse, raw action-count completion, the
role-only restoration guard, and dispatch-time verified success/latency claims.

It is not fully complete or ready for Phase A sign-off. Secure governance,
exact four-action semantics, fail-closed current residual verification, complete
restoration and actual new runtime acceptance still require work. No defensible
overall completion percentage follows from commit counts or checked boxes.
