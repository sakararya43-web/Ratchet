# A/B/C prototype acceptance

The sequential prototype implementation has passed local acceptance. It is a
demonstrable approval-to-target workflow, with persistent private identities and
real PostgreSQL, JetStream, signed commands, target receipts and WebAuthn checks.
The original implementation plans still include the deferred scope listed below.

## Recorded local results (2026-11-08)

| Gate | Result and evidence |
| --- | --- |
| Full core regression | All 18 `scripts/core-acceptance.py` gates passed on clean commit `fc87cd38c03dc6dccc2abf44afc8c7dbac8111e7`; logs and SHA-256 commitments in `.local/phase7-checks/results.json`. |
| Integration and race | Entire main integration/race suite; combined peer/core race; actual connector conformance and peer scenarios; actual Authority HTTP/checkpoint/restart passed. |
| Static, policy and protocol | Module verification, vet, zero lint issues, domain boundaries, zero known Go vulnerabilities, 19/19 OPA decisions, Buf lint and peer compatibility passed. |
| Adversarial checks | 300 property iterations, authentication fuzzing and native-state fuzzing passed; native fuzz run executed 305,837 inputs. Real executable crash/retry/read-only/CAS/refusal tests passed. |
| Persistence | New-process smoke passed. Isolated PostgreSQL restore matched all 31 core/job table commitments and 127,101 rows. The source database was retained. |
| Actual console artifact | 18 frontend tests, TypeScript/Vite build, npm audit and the embedded source manifest passed. All asset files are embedded, including underscore-prefixed chunks. |
| Browser journey | One sequential four-account test passed in 30.1 seconds, using actual HTTPS UI, native WebAuthn, signed policy, broker and simulator. No browser runtime errors. |
| Grants and refusal | Owner quorum one and distinct security-lead quorum two executed; target business access changed 403 to 200. Self-approval, duplicate/insufficient quorum, stale context and tampered envelope/challenge were refused. Owner review retained restricted graph scope. |
| Audit and cleanup | Independently verified 28 canonical ledger events. Actual approved role revocations restored business 403; exact operator-authorized passkey revocations succeeded. No target reset or ledger deletion was used. |
| Profile restart/outage | Graph version 44, 25 nodes/45 edges and identical public identity hash survived restart. Stopped database produced 503 readiness. Evidence: `.local/prototype/foundation-evidence.json`. |

The browser evidence completed at `2026-11-08T04:14:52.546Z` and is stored in
`.local/prototype/browser-evidence.json`. Chromium virtual CTAP2 authenticators
exercise real browser ceremonies and backend signature validation; this does not
certify physical authenticators. Passwords, tickets, private keys and raw reports
remain excluded from Git and image build contexts.

## Published main verification

Both hosted workflows must pass for the published main commit:
[CI](https://github.com/sakararya43-web/Ratchet/actions/workflows/ci.yml?query=branch%3Amain)
and [Core phase checks](https://github.com/sakararya43-web/Ratchet/actions/workflows/core.yml?query=branch%3Amain).
Their live status is authoritative; an older green commit does not validate a
newer commit. Core checks repeat the built-image browser journey and restart
acceptance on Linux, verify generated files/embedded assets, and retain public
prototype evidence as a seven-day artifact. The prototype steps run sequentially.

## Reproduce and demonstrate

1. Follow [prototype-runbook.md](prototype-runbook.md) to build/start the isolated
   profile and trust its local CA. Existing development dependencies are separate.
2. Follow [prototype-walkthrough.md](prototype-walkthrough.md) for four independent
   accounts and real grants/revocations. The console is `https://localhost:8444`.
3. Run `python scripts/prototype-browser.py`, then
   `python scripts/prototype-foundation.py`, sequentially. The former uses the
   installed pinned Playwright Chromium browser; the latter restarts the profile.
4. For the core suite, start the existing core development dependencies and load
   their private environment as described in the existing core runbook, then run
   `python scripts/core-acceptance.py`. This suite is separate from the prototype
   database and broker. See [prototype-execution.md](prototype-execution.md) for
   the command, result and recovery protocol.

Executable containment, full restoration, live Authority administration, automatic
expiry/drift, complete offline browser-approval proof and broader native parity
remain open original requirements. Completing A/B/C does not certify the entire
PRD or remove those tasks.
