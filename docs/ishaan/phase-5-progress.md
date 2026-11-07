# Phase 5 implementation and acceptance record

Work remains on `main`; Phase 6 has not started. No Phase 5 task has been removed
or shortened. Ishaan-owned implementation and local core checks are complete. Actual
peer acceptance remains open, so the complete integrated phase is not signed off.
Phase 4 and earlier handoff gates remain required under the user's instruction to
advance while leaving Sakar's work alone.

| Planned requirement | Core implementation and evidence | Joint acceptance |
|---|---|---|
| Requester privacy | Current-policy API rendering; direct TLS redaction and access checks | UI remains peer-owned |
| Approval expiry | Configurable lifetime; exact-envelope River timer; database time; stale/late/restart checks | Core verified |
| Temporary/emergency expiry | Atomic dispatch/timer; fixed scope/duration; restart recovery; exact revision-bound inverse; signed independent result verification; failures remain visible | Actual connector must advertise/support scheduled revocation and demonstrate target expiry |
| Emergency routing | Existing independent owner/two-lead review and passkeys; extra resources/actions held | Browser/target gates remain in the Phase 2 handoff |
| Temporary review | Stable temporary-only lists, expiry/failed-revocation attention, explicit scope review | Peer UI consumes real APIs |
| Change/Incident Watch | Durable events; stable list boundary; authenticated actor-bound resume cursors; reconnect/privacy tests | Core verified |
| Drift decisions | Signed observations through actual JetStream; exact command correlation; proven safe reduction; current policy/responder checks; atomic incident/corrector evidence | Actual peer publisher and target contract adoption required |
| Drift safety | Concurrent deduplication; normal read-back delay; correction-loop prevention; protected/erased evidence held; rollback and residual-path tests | Core verified; actual target demonstration pending |
| Inline decisions | Session-authenticated durable DecisionService; exact object/context/revision; one-use command authorization; concurrent/restart checks | Kubernetes adapter is Phase 6, not silently included |
| Performance | Final two-CPU Linux sample: inline p99 35.31 ms; 100k-edge ImpactDiff p99/max 84.03 ms; complete dataset/sample/tail evidence | Targets met for the published workloads and hardware |
| Benign replay | Actual Submit/Assess on PostgreSQL and signed policy; 0/100 unexpected results; expected review/quorum and causes retained | Core assessment scope; actual browser/user/target timing requires integration |
| Traces/metrics | Correlated structured spans; tenant-local restricted backlog, graph lag, policy/job/expiry and verified containment duration | Core verified; no external collector is claimed |
| FR-L2 candidate scheduling | Database-time durable singleton slot; pending-root reuse; bounded catch-up; separate real HTTP delivery; verified partial/full quorum; restart/concurrency tests | Actual member signing remains Authority-owned |

Read [expiry](phase-5-expiry-contract.md), [drift](phase-5-drift-contract.md),
[checkpoint scheduling](phase-5-checkpoints.md), [observability](phase-5-observability.md)
and [measurement scope](phase-5-measurements.md) before resuming. Signed protocol
fixtures exercise the core boundary; they are never production target substitutes.

The production console still refuses privileged readiness without the secure
peer passkey/execution dependencies. No runtime flag, fake approval, placeholder
target or fixture-backed response bypasses that dependency.

The full integration/race suite is executed with packages serialized (`-p=1`)
because they share local CPU/database capacity. All test cases remain enabled;
HTTP/application deadlines remain unchanged. The six-minute package budget covers
the expanded restart/replay/expiry/drift suite. Performance evidence is collected
separately without race instrumentation and preserved in CI artifacts.

## Validation record

Core code candidate: `efd80c46da0ebaf1bc7ba296f4dc32633ef31120`.
Peer source remains `origin/sakar d823a10`. All work is committed under Ishaan's
configured Git identity, with no Codex/ChatGPT co-author trailers.

Passing on the core candidate:

- Full Linux `go test -race -p=1 -tags=integration -count=1 -timeout=6m ./...`
  against actual PostgreSQL and JetStream. The workflow package passed in 218.861
  seconds, including the large-evidence signed checkpoint regression.
- Core lint: zero issues. Module verification and 300-case graph/domain/workflow
  properties at seed `20261105` pass. Current signed Rego behavior is exercised
  by the policy and workflow suites.
- Owned-schema formatting, Buf lint and breaking checks against both the peer
  baseline and preceding `main`; reproducible protobuf/SQL generation; actionlint.
- Final combined-source ordinary race suite (`-p=1 -count=1 -timeout=6m ./...`)
  with the pinned peer archive and exact final core files.
- Actual peer Authority executable checkpoint HTTP submission, member signing,
  process restart and signature-preserving acceptance: passed in 5.881 seconds.
- Full vet including integration-tagged code, and real new-process
  append/retry/read/chain/liveness/honest-readiness smoke.

The large-byte regression retains over 16 MiB of actual stored evidence, refuses
silent trimming of an explicit oversized range and independently accepts two
consecutive signed checkpoints. Its test-only three-minute budget accommodates
repeated race-instrumented canonicalization. Production deadlines are unchanged;
this is not a latency claim for arbitrarily large payloads.

The hosted core jobs passed on the preceding `26a5806` candidate. Final source CI
is checked after pushing the completed record. Actual-peer steps are conditional
and absent from separate `main`; a green core workflow is not proof of those gates.

## Remaining integrated acceptance

No Sakar branch, implementation-plan file or owned production source was changed.
An isolated unversioned archive overlays core files onto the pinned peer source;
ordinary combined race tests pass with the final `efd80c4` core files. The actual peer conformance suite
still reproduces the previously recorded failures:

- Wrong WebAuthn origin/RP/ceremony accepted, normal COSE key rejected and
  unauthenticated credential management exposed.
- Stale expected target revision mutates actual IAM.
- Snapshots lack complete authenticated envelopes, safeguard/session semantics,
  original grant provenance and complete endpoints.
- Offline checkpoint verification accepts an altered prior-checkpoint digest.

These tests remain enabled. See [the existing peer handoff](phase-4-peer-handoff.md)
for exact closure requirements. Phase 5 additionally needs actual signed capability
adoption, a real drift publisher and real target expiry/correction plus independent
read-back. Protocol fixtures do not satisfy this target acceptance. Those two
integrated checklist items remain unchecked; no requirement has been cut or silently
deferred. The raw branch merge still needs reviewed shared-file conflict resolution;
a successful archive overlay does not imply an automatic conflict-free Git merge.
