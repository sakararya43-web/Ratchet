# Phase 7 validation and completion evidence

Recorded 2026-11-07. Tasks 8 and 9 are complete for source candidate
`7ddc8a9da7f8deac9c8b58fa846a916f393ba979` on `main`.
The unchanged peer source is `d823a106bb4a64b0fe54e366c41029ccbd8dfda8`.
[Both hosted jobs passed](https://github.com/sakararya43-web/Ratchet/actions/runs/42387565655).
All required automated checks below passed; this is not full product sign-off.
The Phase 7 exit and the plan's deployment gate remain open because earlier
Phase 4 operations and joint D1–D8 acceptance remain unfinished. No requirement
is removed or reclassified to close those gates.

## Task 8: final-candidate checks

| Check | Evidence and result |
|---|---|
| Modules, vet, whole-main strict lint | Passed; zero lint issues |
| Ordinary main race suite | Passed across the checkout, packages serialized |
| Full main integration/race suite | Passed against real PostgreSQL/JetStream, including combined/separated console roles, crypto/passkeys, credential revocation, replay, expiry, privacy, outages and checkpoints |
| Properties | Passed with `rapid.checks=300`, seed `20261105` |
| Fuzzing and domain boundaries | Passed; both fuzz targets run sequentially for 30 seconds with one worker; authentication 947 executions, native normalization 398,164 executions |
| Dependencies | govulncheck v1.9.0 reports no vulnerabilities |
| Rego | 19/19 decision/authorization regressions pass; `--fail-on-empty` enforced |
| Buf and generation | Formatting/lint, breaking checks against pinned peer and preceding main, Go Protobuf/Connect and SQL generation consistency passed |
| Actual web build | 15 tests, TypeScript/Vite build, dependency audit and exact Linux embedded-asset reproduction passed |
| Containers and supply chain | Actual final distroless image, UID/GID 65532, read-only root/capability restrictions, 112-package SPDX SBOM, OCI signature/SBOM binding and wrong-key/wrong-SBOM refusal passed |
| Actual connector conformance | Real passkey, simulator CAS/dedup/read-back/snapshot and offline-checkpoint conformance passed under race |
| Pinned peer compatibility | All six original scenario folders and the complete ordinary combined-source race suite passed; no branch merge |
| Actual Authority | Real executable, HTTP checkpoint submission/signing, restart and durable core acceptance passed through the pinned overlay |
| Real Compose process smoke | Actual migrate, append, exact retry, new-process read/chain verification and honest health/readiness passed |
| Backup/restore | Hosted and local isolated restores passed all 30 core/job table commitments; local source contained 120,257 rows |
| Actual kind | Live inventory, sensitive-write refusal, complete source/ledger replay, graph comparison, independent approval, one-use command, API write/read-back, outage refusal and approved/unapproved drift with incident get/list/stream all passed |

The direct Authority step is intentionally conditional while the branches are
separate. It was not counted as passing when skipped; the required explicit
pinned-overlay Authority check passed. The two peer fixture-dependent scenario
files use `peerintegration` and are explicitly exercised, not omitted from
acceptance. Real native tests use Windows executables cross-compiled from this
candidate; they are not race-instrumented. Linux main and peer suites use `-race`.

Earlier failed runs exposed real issues: revoked-ID resurrection in a legacy
test, CRLF-dependent Vite output and an outer IP limiter pooling verified users
behind one NAT. The fixes preserve the security assertions and rate values.
Functional polling now respects the real ten-request/second limit. The larger
native correctness context preserves all full source cuts; it changes no
production RPC/webhook deadline. No failed assertion was inverted into success.

## Task 9: joint D1–D8 evidence

The peer scenario references below point to the original implementation at the
pinned commit. Their component results are combined with core evidence, without
claiming a complete browser-to-core-to-target journey where none was run.

| Scenario | Core and actual peer evidence | Remaining integrated verdict |
|---|---|---|
| D1 ordinary access | Durable submit/assessment, owner routing, current-context/passkey guards and signed execution/read-back boundaries pass. Real simulator target mutation/CAS/read-back passes. Selected native approval/write/read-back reaches EXECUTED. | Full simulator browser/core/real signed connector-CLI journey remains open. |
| D2 sensitive access | Real signed policy requires two independent leads for new tier-0 authority; over-grant, stale context, self/control-dependent approvals and bad read-back are refused. Peer attack/scenario suites pass. | Full simulator UI/transport demonstration remains joint acceptance. |
| D3 impact | Independent graph properties, 100k-edge impact measurement, committed exact-context replay and real native comparisons pass. The actual web consumes core graph/impact APIs. | Full UI/scenario comparison is not established by a build or JSON API test alone. |
| D4 independent review | Real registration/assertion cryptography, exact origin/RP/ceremony/UV, immutable credential enrollment/revocation, distinct quorum and takeover checks pass. Peer self-approval/controlled-approver scenarios pass. | Human browser ceremonies and their end-to-end timing remain unmeasured. |
| D5 critical rule | Tier-0 safeguard weakening is refused; governance uses signed Authority artifacts. Peer withdrawal-rule scenario and actual Authority signing/restart pass. | Full production browser/connector governance demonstration remains joint. Financial safeguards have no claimed native RBAC equivalent. |
| D6 containment | Core verified cut planning and all-identity reduction proofs pass. Peer containment component executes two target actions with read-back within its five-second test bound. Native drift evidence and incident views pass. | Confirmed four-action core execution/priority transport, complete incident terminal/recovery paths, backlog/restart portfolio and human click-to-verified timing remain open. Component execution timing is not human click latency. |
| D7 continuity | Core planner proves proposed finance preservation. Peer containment probes preserve Priya's finance permission and reject the compromised Rahul session, including HTTP 403 on its business read. | This does not demonstrate legitimate Rahul finance access after the complete core containment journey. The peer's 87.5% ratio is a constant, not a measured business-activity metric; it is not adopted here. |
| D8 audit | Public chain, decision replay, historical signed checkpoints, privacy deletion and corruption checks pass. Actual peer CLI accepts the pinned seven-event/two-checkpoint fixture and rejects a tampered event at sequence 1 with nonzero exit. | The CLI fixture has zero approval records. Complete original browser assertions, historical credential-ID/COSE/RP evidence and signed registry/bundle packaging remain required for full offline browser verification. |

Actual peer scenario implementation:
[containment/continuity](https://github.com/sakararya43-web/Ratchet/blob/d823a106bb4a64b0fe54e366c41029ccbd8dfda8/e2e/scenarios/contain_rahul/contain_rahul_test.go),
[self approval](https://github.com/sakararya43-web/Ratchet/blob/d823a106bb4a64b0fe54e366c41029ccbd8dfda8/e2e/scenarios/self_approval/self_approval_test.go),
[controlled approver](https://github.com/sakararya43-web/Ratchet/blob/d823a106bb4a64b0fe54e366c41029ccbd8dfda8/e2e/scenarios/controlled_approver/controlled_approver_test.go),
[withdrawal governance](https://github.com/sakararya43-web/Ratchet/blob/d823a106bb4a64b0fe54e366c41029ccbd8dfda8/e2e/scenarios/withdrawal_rule_edit/withdrawal_rule_edit_test.go),
[CLI](https://github.com/sakararya43-web/Ratchet/blob/d823a106bb4a64b0fe54e366c41029ccbd8dfda8/cmd/ratchetctl/main.go).
Their source is reused with the explicitly authorized corrections on main.
[Exact CLI commands/results](evidence/phase-7/checkpoint-cli/results.json) retain
the external genesis, tip and checkpoint pins and the expected negative exit.

## Measurements and P1 scope

Fresh hosted samples use Linux amd64, Go 1.27.3, four logical CPUs and
GOMAXPROCS=4, without race instrumentation:

| Workload | Samples/warmups | p95 | p99 | Target |
|---|---:|---:|---:|---:|
| Durable inline core, 26-node/41-edge demo | 100/5 | 6.34 ms | 6.56 ms | 50 ms |
| ImpactDiff, 22,000 nodes/100,000 edges | 50/3 | 20.83 ms | 21.54 ms | 100 ms |

These measure core service work, excluding browser/TLS/passkey/user waiting and
target execution. They are not a production capacity claim. Benign replay is
**0/100 unexpected outcomes**, with expected independent review counted as a
legitimate outcome. It measures real PostgreSQL Submit/Assess, not completed
approvals or target access. [Full distributions/datasets](evidence/phase-7/performance.json)
and [denominator/outcomes](evidence/phase-7/benign-replay.json) are retained.

The actual native sample measured webhook **1,934.3943 ms** and API write
**2,532.6388 ms**, with one approved write, one policy refusal and one dependency
refusal. These are single observations, not percentiles or the inline-core
benchmark. The complete admission/drift test took 788.48 seconds; comparison
took 106.34 seconds. [Raw native results](evidence/phase-7/actual-kind.json).

| Retained P1 | Completed core evidence | Integration/deferred status |
|---|---|---|
| FR-C10 privacy | Current-policy rendering, TLS access/redaction and self-only bootstrap | Actual artifact wired; full browser walkthrough remains joint |
| FR-C11 approval timeout | Durable database-time timer, late/stale/restart refusal | Core verified |
| FR-I3 over-grant | Explicit requested scope, complete role simulation and refusal | Core verified |
| FR-E1/E2/E3 emergency/temporary access | Independent routing, bounded scope/duration, atomic expiry scheduling and review data | Real signed simulator transport/target expiry adoption remains open; not silently deferred |
| FR-L2 checkpoints | Durable candidates, scheduling, real Authority HTTP/signing/restart and historical verification | Selected core/Authority boundary verified |
| FR-O2 live updates | Durable actor-bound resumable Change/Incident streams with privacy/reconnect checks | Complete browser consumption remains joint |
| FR-K4 drift correction | Authenticated core decisions/correlation, reduction proof and incident evidence | Real autonomous simulator publisher/corrector and native collector/reverter remain open |
| FR-K5 native adapter | Live inventory, exact authenticated fail-closed admission, committed source replay and drift incident evidence | Selected RBAC scope verified; automatic watch/correction and full D1–D8 parity are not claimed |

Selected native scope excludes external authorizers/identity providers,
admission-policy removal, financial safeguards, workload escape and automatic
native rollback. Unknown/unavailable context remains held. FR-X6 and FR-L5 are
the plan's P2 mechanisms. Full R6 is **not satisfied**: escalation fail-closed is
demonstrated, but outage-time independent break-glass reduction/recovery is not
implemented. This remains an explicit v1 limitation requiring release acceptance.
One local instance and a quiescent restore do not establish HA, RPO or RTO.

## Remaining release work and merge review

The Phase 4 continuation list remains required:
confirmed exact-plan four-action containment; durable priority attempts and
truthful terminal/residual/uncertain-restart evidence; non-role restoration
increase contracts; complete offline browser-approval packaging; and full
human/target/business/CLI D1–D8 acceptance. Immutable credential storage and all
historical negative conformance defects are now fixed on main; those fixes do
not implement the remaining orchestration. No fake success endpoint closes a gap.

The unchanged peer connector CLI still constructs `LogPublisher`. Logging is not
authenticated signed command/result delivery. Both contributors must accept the
integrated results before the deployment gate is checked.

A read-only `git merge-tree` found **44 shared-file conflicts**. It changed no
branch or worktree. The passing source overlay gives main precedence over the
pinned peer; it does not establish an automatic conflict-free GitHub merge.
During the later authorized merge:

- Preserve main's passkey/session, simulator CAS/snapshot, checkpoint and native
  admission corrections. Do not restore local-intent or simulated assertion paths.
- Resolve additive proto/module/build conflicts and regenerate bindings; retain
  the pinned peer-only Authority/CLI contributions.
- Preserve the deletions of mock web components and real same-origin integration from
  `f4bb68d`; keep signing fixtures in explicit test profiles, not production routes.
- Review the exact [conflict inventory](evidence/phase-7/verification.json), then
  rerun the full main/combined/native checks on the actual resolved merge.

## Retained evidence

[Verification index](evidence/phase-7/verification.json) records source/peer pins,
successful CI steps, native test durations, source-tree identity and file hashes.
The evidence includes the exact public SPDX SBOM, Cosign public key/verification
output, image digest/SBOM summary, local restore result, measurements and CLI
fixtures/reports. No private signing key, database dump, session or credential
secret is retained. OCI signing used a disposable local registry/key; the retained
verification output is not a production identity or standalone OCI signature
bundle. Reproduce with the checked-in scripts; the original hosted artifacts have
seven-day retention.

Evidence publication changes only documentation and Ishaan's status checklist;
the tested executable source stays unchanged. Sakar's branch and implementation
plan are untouched. “All checks green” means the checks listed here, not 100%
code coverage or completion of the explicitly open product requirements.
