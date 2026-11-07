# One-day prototype: sequential A / B / C

The user authorized these three milestones on 2026-11-08. All work stays on main;
Sakar's branch and plan remain unchanged. No original requirement is removed.

## A - trusted local foundation (complete)

- [x] Persistent signing identities; explicit transport/credentials; no logging fallback.
- [x] Reliable signed complete snapshots for the prototype target.
- [x] Controlled, one-use operator-authorized credential enrollment/revocation.
- [x] Real signed demo policy, independent approvers and persistent local configuration.
- [x] Repeatable local startup/shutdown, persistence/restart and honest health checks.

## B - secure verified execution (complete)

- [x] Strict authenticated exact-context command validation and allowlist.
- [x] Durable command/result handling and CAS/idempotent receipt recovery.
- [x] Read-only reconciliation and truthful canonical result evidence.
- [x] Real executable/NATS/target adversarial, retry and restart regressions.

## C - browser demonstration and validation (in progress)

- [ ] Readable request/impact/review/status console and browser envelope digest check.
- [ ] Ordinary owner and sensitive two-approver browser journeys.
- [ ] Self-approval, insufficient quorum, stale context and bad-command refusal.
- [ ] Actual business access and audit evidence, browser acceptance and walkthrough.
- [ ] Required regression/CI checks on the same final candidate and operator runbook.

Containment execution, full restoration, live Authority administration, automated
expiry/drift, complete offline browser-approval proof and broader native parity
remain outside this prototype milestone and stay required by the original plans.
