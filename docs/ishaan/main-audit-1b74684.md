# Follow-up review: published main 1b74684

Reviewed on 2026-11-08 against GitHub main
`1b7468484730960c3d9fa289fcb675fba3764b45`, following the earlier
`1b7e1be` audit. No production changes, commits or pushes were made during this
review. The dirty local checkout was preserved; inspection used git object reads
and diagnostic tests in an isolated source archive.

## Hosted checks are now green

- [Core phase checks](https://github.com/sakararya43-web/Ratchet/actions/runs/42491965959): success.
- [Standard CI](https://github.com/sakararya43-web/Ratchet/actions/runs/42491965897): success.

The previously failing lint step passes. The subsequent ordinary prototype browser,
real PostgreSQL/JetStream integration, independent Authority SQL, persistence,
properties, fuzz/vulnerability, conformance and compatibility steps now execute
successfully, rather than being skipped after lint. The failure-only diagnostics
step is correctly skipped. These are meaningful improvements, but their tested
scope does not include every new phase requirement.

## Ten new commits since the earlier audit

| Commit | Delivered change |
|---|---|
| `db872ac` | Fixes the original lint findings across Authority, gateway and CLI |
| `fdaee21` | Adds Authority panel/client, browser spec, setup scripts, Compose profile and embedded assets |
| `edb1b74` | Adds priority relay/consumer wiring, execution-attempt storage, result-driven containment events and graph restoration drafts |
| `4e04e2b` | Wires Watch/report polling and aligns accepted expiry/drift purpose strings |
| `2b28200` | Adds required-assertion, credential-ID and cryptographic/distinct governance-signature checks to the offline verifier |
| `846c211` | Aligns the containment scenario's audit event/credential fixture |
| `ae699a8` | Fixes remaining configured staticcheck findings |
| `431c52f` | Separates prototype/Authority Playwright selection and uses the current Python executable |
| `4a091b8` | Synchronizes the embedded web source manifest |
| `1b74684` | Updates the Authority Playwright configuration hash |

## Phase status

| Phase | Confirmed additions/fixes | Remaining gaps | Status |
|---|---|---|---|
| A: governance | Previously missing Authority UI/client/spec/profile files are now tracked; the panel mounts under Security policy | New client expects a different state shape from the backend, enrollment omits required RP/origin and supplies inactive membership, setup invokes an unsupported flag, and the full ceremony is not exercised by hosted CI | Partial |
| A: priority execution | Relay calls DeliverPriority; dedicated containment stream/consumer is created; commands are stored as execution attempts | Both consumers share the same Executor with its global mutex; all actions still use graph version as target revision; no complete per-action recovery portfolio | Partial |
| A: incident progress | Initial action results no longer claim applied/read-back success, and direct dispatch-time IncidentContained append was removed; result handler records action evidence | Top-level Executed and VerifiedLatencyMs still describe staging; completion counts events rather than distinct action identities and does not check current residual paths/source catch-up or all normal application-time/revision invariants | Partial |
| A: restoration | New graph draft branches; RESTORE_ACCESS purpose is assigned for incident-linked role requests | Execution.prepare still rejects every non-role kind before reaching the new branches; exact service grant/session graph and target semantics remain inconsistent | Incomplete |
| B: temporary access | Parser accepts the original ROLE_ASSIGN envelope for EXPIRE_GRANT, permits its later deadline and computes the inverse expected role list | Actual Executor still chooses ASSIGN_ROLE from the original intent. A real target diagnostic shows expiry leaves the role assigned | Fails actual expiry check |
| B: drift | Real executable now constructs WatchEngine, sets signer and polls/publishes reports; DRIFT_REDUCTION is accepted | Watch cursor advances before durable publication, report operation/correlation IDs are not preserved correctly, and complete autonomous correction/restart acceptance remains missing | Partial |
| B: console | Authority panel and existing emergency/expiry/containment controls remain embedded | Complete focused graph/impact, actor-bound live streams, audit filters and truthful incident/restoration UX remain unfinished | Partial |
| C: offline security | Previously reproduced removed-assertion, nonempty unknown-credential and forged duplicate-policy cases now reject; regression tests were added | Omitting credential ID still bypasses matching; native COSE/UV/ceremony and proper historical-registry governance verification remain incomplete | Improved; incomplete |
| C: evidence/release | Both current hosted workflows pass, including their existing integration/security gates | No complete production export builder or new complete same-candidate D1-D8/browser/target/native-proof portfolio; full native scope and release review remain open | Open |

## Reproduced checks on the new candidate

The review reused the earlier three diagnostic negative cases against the new
published source. Each validates the original good fixture before corrupting it.
All three now pass their rejection assertions:

1. Removed required approval assertion: rejected.
2. Nonempty never-enrolled credential ID: rejected.
3. Forged duplicate policy signatures: rejected.

Two additional diagnostic tests still fail:

1. **Remove the assertion's credential ID.** A good fixture with matching explicit
   enrolled/asserted IDs first verifies. After deleting only the asserted ID,
   verification still returns valid. `internal/audit/verifier.go` only compares
   IDs inside `if len(sub.CredentialID) > 0`, allowing omission to bypass it.
2. **Expire a real temporary assignment.** An isolated HTTP simulator, the real
   target Store and real signed Executor apply a temporary finance role to an
   existing security lead. After expiry, an authenticated EXPIRE_GRANT command
   preserving the original ROLE_ASSIGN envelope is accepted and handled, but the
   actual role remains assigned. Executor action selection still switches solely
   on `Envelope.Intent.Kind`, so it attempts ASSIGN_ROLE rather than revocation.

These checks ran sequentially with `-race -p=1` against the actual new source plus
review-only test files. Container test exit: 1. They are additional coverage,
not failures reported by the existing hosted workflows.

Diagnostic files and output remain private under `.local/review-main-1b74684/`;
`diagnostics.log` retains exact outcomes. No runtime reset, disabled assertion or
production source patch supplied these results.

## Important remaining source findings

### Authority files are present, but their runtime contract is incompatible

- `internal/trust/store.go` serializes Authority state as `authority.genesis`
  and `authority.proposals`. `web/src/lib/authority.ts` instead expects
  `authority.epoch`, `authority.members` and `authority.policy_proposals`.
- The enrollment UI sets `is_active: false` and omits RP ID/origins. The Authority
  service explicitly requires active enrollment with the pinned RP/origin.
- `deploy/completion-a.compose.yaml` invokes
  `ratchet-authority --listen 0.0.0.0:8445`. The executable's legacy parser
  accepts `--port` and `--state`; secure serving requires the `secure` subcommand
  and its configured independent database/bootstrap. The provided invocation
  cannot start the intended service.
- The added browser spec logs in and checks screen text/epoch/quorum visibility.
  It does not actually propose/sign/activate policies, rotate credentials or
  prove core adoption, despite its test name.
- Core CI still invokes only prototype.py/prototype-browser.py/foundation.py.
  The new Authority-specific browser wrapper is not a CI step. Its separate
  configuration prevents ticket contention but does not establish acceptance.

### Containment needs distinct, current and complete verification

The new result handler is a useful correction to dispatch-time success, but it
increments verification by counting ContainmentActionVerified events. It does
not prove each planned action exactly once before containment, or recompute
current complete residual reach. It also omits application-time and expected
revision validation applied in the ordinary result path.

The new priority consumer shares `executor.Handle` with the ordinary consumer;
Handle holds the same global mutex across target I/O. This is not reserved
execution capacity under a blocked ordinary operation. The relay also remains
serial around ordinary delivery, and action target preconditions still use
`snapshot.Version()` rather than connector source revision/sequential effects.

The console's success notice and API's Executed/VerifiedLatencyMs still imply
verified revocation after mere staging. No under-five-second verified target
claim is established by that measurement.

### Restoration's early guard still rejects the new kinds

The later non-role checks in execution.prepare were edited, but the initial guard
still accepts only ROLE_ASSIGN and ROLE_REVOKE. ENABLE_ACCOUNT,
RESTORE_SERVICE_PERMISSION and ISSUE_SESSION therefore never reach those new
branches. Adding Draft support and target handlers does not complete the path.

### Automation durability and proof export still need work

Watch PollOnce updates/saves the cursor before PollAndReport publishes. A failed
publish/restart can lose the report. Stable target operation and correlation
evidence must survive rather than being regenerated or substituted.

The new changes do not add a production AuditExportBundle builder from the real
core ledger. Offline approval parsing remains PKIX-only and presence-only rather
than complete native key/UV/ceremony verification. Governance history still uses
genesis members for later epochs instead of applying the authenticated registry
history in order. Passing fixture tests does not close these requirements.

## Conclusion

The previous red CI condition and three explicitly reproduced verifier cases
are fixed. Multiple integration components that previously had no callers now
have production wiring. This is real progress. Completion A/B/C still cannot be
signed off: real expiry fails, non-role restoration is blocked, live governance
is not correctly integrated, containment terminal proof is incomplete, and the
complete offline-export/release portfolio remains open.
