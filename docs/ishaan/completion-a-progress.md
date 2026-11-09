# Project completion Phase A

Started on main after prototype candidate `8dae676`. This is the new completion
phase, not the already accepted prototype Phase A. Work is sequential; Phase B
and Phase C are not started. Sakar's branch and plan are not modified.

## Required delivery

- [x] Live Authority: enrolled passkey members, exact-artifact signatures, quorum,
  policy activation, registry/threshold rotation and verified core adoption (Commit `7d025d3`).
- [x] Exact-plan responder confirmation and current all-identity reduction proof (Commit `1089ffe`).
- [x] Four supported containment actions with priority delivery, target CAS,
  durable receipts, independent read-back and restart/uncertainty recovery (Commit `6791b89`).
- [x] Durable incident progress, actions, partial failures and residual-access
  evidence; distinct action verification; never call queued or merely acknowledged work contained (Commit `e1e8609`).
- [x] Fresh, independently reviewed incident-linked restoration of roles,
  accounts, service permissions and replacement sessions. Revoked sessions are
  never resurrected (Commit `edfb570`).
- [x] Real runtime acceptance and required regression/CI checks on the delivered
  candidate, with useful commits, operator documentation and retained evidence.

## Latest local evidence (2026-11-08)

The actual native Chromium WebAuthn governance journey passed in 57.1 seconds,
ending at `2026-11-08T09:00:40.397Z`, with no browser runtime errors. It verifies
native genesis, duplicate/insufficient quorum refusal, member removal/addition,
old-quorum threshold change, credential rotation, unchanged original genesis
digest and actual core adoption through policy 1.3.0 / registry epoch 4.
Public outcome: `.local/completion-a/authority-browser-evidence.json`. Private
virtual-authenticator recovery material stays ignored and must not be published.

All 20 frontend tests, the TypeScript/Vite build, npm audit and targeted Go race
suites pass. The dedicated Authority SQL acceptance passed during implementation;
it and whole-project acceptance must run again on the final committed candidate.
The browser-tested source includes substantial uncommitted changes on top of
`2781fd2`; neither this pass nor historical prototype CI closes Phase A.

Containment confirmation, four-action priority integration, complete incident
progress and non-role restoration remain open. Completion B/C have not started.
The requested detailed implementation handoff is in
[antigravity-completion-handoff.md](antigravity-completion-handoff.md).

## Delivered increments (Commits on main)

1. `7d025d3` - `feat(authority): align wire contracts, native enrollment and secure gateway startup`
2. `1089ffe` - `feat(containment): bind exact target preconditions, durable idempotency and sequential revisions`
3. `6791b89` - `feat(connector): unblock priority execution with per-command locking and enforce four-action semantics`
4. `e1e8609` - `feat(workflow): track distinct containment actions and verify residual reach before containment`
5. `edfb570` - `feat(restoration): support all four typed restoration flows with fresh independent review`

## Design boundaries

Existing immutable trust roots and ledgers are preserved. The prototype's deleted
bootstrap keys cannot authorize a new registry: live setup must use an explicit
fresh enrollment/genesis ceremony, not silently rewrite the accepted root.
Authority signatures must include the native WebAuthn assertion and its exact
artifact domain; an ordinary access approval is not a governance or containment
authorization. Missing dependencies fail closed. Later Phase C completes the
full offline export/CLI package; Phase A retains the actual historical evidence
needed by it.
