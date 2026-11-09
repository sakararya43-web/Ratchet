# Focused prototype demo readiness

Started 2026-11-08 at 23:48 IST. Three-hour deadline: 2026-11-09 at 02:48 IST.
The scope is the real local access-review prototype, not full PRD completion.

## Sequential tasks

1. [x] Freeze the candidate and select one consistent runtime.
2. [x] Pass the real browser approval/target-access journey; fix blockers.
3. [x] Prepare persistent presenter browser profiles, passkeys, TLS and starting access.
4. [x] Resolve presentation blockers and explain supported scope in the console.
5. [x] Rehearse and record a complete walkthrough, with screenshots and evidence.
6. [x] Save a reproducible candidate, operator instructions and final validation.

## Candidate and preservation

- Starting HEAD: `2781fd2`, with existing tracked and untracked governance changes.
- Source-only pre-work snapshot and file hashes: `.local/demo-ready/source-before-demo.zip`
  and `.local/demo-ready/source-before-demo.json` (private local artifacts).
- Keep the existing prototype and completion Authority roots, databases and ledgers.
  Never reset data to make the demonstration pass.
- Demo profile: `ratchet-prototype-v1`; the separate `ratchet-completion-a-v2`
  profile is preserved while the prototype uses the shared localhost ports.
- Do not merge additional feature scope into this bounded demo candidate.

## Acceptance scope

Owner approval, two distinct security approvers, insufficient/self approval refusal,
browser-bound exact review, signed target commands, independently verified execution,
real finance/wallet access probes, audit evidence and reviewed role revocation.
Containment execution, complete restoration, automatic expiry/drift, complete offline
approval proof and broader Kubernetes parity are outside this demonstration.

## Results

The current source built successfully into `ratchet-prototype:local`. The original
image is retained as `ratchet-prototype:pre-demo-20261108`. Completion profile
containers were stopped without deleting volumes. The original prototype profile
started successfully with its existing identities, root and ledger.

The actual four-account browser acceptance passed in 48.0 seconds on this runtime.
Its evidence is `.local/prototype/browser-evidence.json`; this includes actual
finance/wallet deny-to-allow probes, self/duplicate/insufficient approval refusal,
stale-context holding, altered-envelope/challenge refusal, canonical ledger
continuity and reviewed role cleanup. No browser runtime errors were reported.

Four isolated presenter sessions and native virtual-authenticator passkeys were
prepared through real operator-ticket enrollment. Keys/cookies stay ignored in
`.local/demo-ready/presenter-private.json`; no private data is included in source
or demo evidence. `python scripts/demo.py present` rehydrates those devices.
The prepared browser trusts only the exact current localhost leaf SPKI; no global
certificate-verification bypass or system trust change is needed. Normal browser
use can follow the optional local-CA trust instructions in the original runbook.

The embedded console now explains the three-step review/verification flow and
demonstration boundaries, highlights request states, filters the current request
page, and displays readable server errors. All 20 frontend tests, TypeScript/Vite
build and npm audit passed; the built console was redeployed and the four existing
presenter sessions reopened successfully. Desktop visual QA uses the actual
embedded artifact. Final browser regression also passed on the rebuilt image.

The full fast rehearsal passed, followed by a successful captioned native-browser
recording. The final WebM is 331 seconds (5m 31s), 1440 x 1000, with 15 captured
scenes. Its actual run verified 245 canonical audit events, rejected self and
duplicate approvals, kept wallet access denied after one vote, enabled it after
two distinct votes, and restored both demonstration roles to absent through
reviewed revocations. No browser runtime errors were reported. Evidence:
`.local/demo-ready/recording-evidence.json`; recording:
`.local/demo-ready/ratchet-demo.webm`. The video is captioned and has no audio.

Final backend verification passed: module verification, vet, strict lint (zero
findings), the entire integration/race suite against real PostgreSQL/JetStream,
domain boundaries and 19/19 OPA tests. The dedicated independent Authority
scratch-database acceptance also passed. Existing 22 governance lint findings
were corrected without changing authorization decisions; one touched Go file was
formatted afterward.

The rebuilt final image passed the ordinary browser acceptance in 42.9 seconds.
Restart retained graph version 208, 25 nodes, 45 edges and the same public trusted
identity hash. Stopping the prototype database returned 503 readiness; restoring
it recovered full readiness. The final recording is bound to the exact runtime
image and embedded-source manifest. Chromium decoded and played the actual WebM.

All 16 selected final checks passed. Frozen startup, four isolated native-passkey
presenter sessions, duplicate-launch refusal and graceful closure were verified.
The frozen image tags are `ratchet-prototype:demo-ready` and
`ratchet-prototype-db:demo-ready`. Exact image IDs, source/archive digests and the
database platform manifest are in `.local/demo-ready/candidate.json`.

## Deliverables

- `.local/demo-ready/index.html`: offline player with video, notes and evidence.
- `.local/demo-ready/ratchet-demo.webm`: captioned 5m 31s backup recording.
- `.local/demo-ready/RATCHET-demo.zip`: 23 allowlisted public files; archive CRC
  and filename allowlist verified. Private credentials, cookies, tickets, keys and
  raw reports are excluded.
- `.local/demo-ready/source-final.zip` and `source-final-manifest.json`: the
  complete source-only candidate, including the preserved earlier local work.
- `.local/demo-ready/verification.json` and `package-receipt.json`: actual local
  check outcomes and package fingerprint.
- `docs/ishaan/demo-ready-walkthrough.md`: startup, presenter story, recovery and
  truthful limitations.

Completed within one hour of the 23:48 IST start, well before the 02:48 IST
deadline. The runtime remains ready at `https://localhost:8444`; start the four
prepared presenter windows with `python scripts/demo.py present`. Their credentials
and virtual devices remain private and reusable. The separate completion profile
and all existing data volumes remain preserved.

This is focused prototype/demo readiness, not full completion A/B/C, hosted CI,
production release, or physical authenticator certification. Full containment,
restoration, automation and complete offline authorization proof remain open.
