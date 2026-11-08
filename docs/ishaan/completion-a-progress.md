# Project completion Phase A

Started on main after prototype candidate `8dae676`. This is the new completion
phase, not the already accepted prototype Phase A. Work is sequential; Phase B
and Phase C are not started. Sakar's branch and plan are not modified.

## Required delivery

- [ ] Live Authority: enrolled passkey members, exact-artifact signatures, quorum,
  policy activation, registry/threshold rotation and verified core adoption.
- [ ] Exact-plan responder confirmation and current all-identity reduction proof.
- [ ] Four supported containment actions with priority delivery, target CAS,
  durable receipts, independent read-back and restart/uncertainty recovery.
- [ ] Durable incident progress, actions, partial failures and residual-access
  evidence; never call queued or merely acknowledged work contained.
- [ ] Fresh, independently reviewed incident-linked restoration of roles,
  accounts, service permissions and replacement sessions. Revoked sessions are
  never resurrected.
- [ ] Real runtime acceptance and required regression/CI checks on the delivered
  candidate, with useful commits, operator documentation and retained evidence.

## Design boundaries

Existing immutable trust roots and ledgers are preserved. The prototype's deleted
bootstrap keys cannot authorize a new registry: live setup must use an explicit
fresh enrollment/genesis ceremony, not silently rewrite the accepted root.
Authority signatures must include the native WebAuthn assertion and its exact
artifact domain; an ordinary access approval is not a governance or containment
authorization. Missing dependencies fail closed. Later Phase C completes the
full offline export/CLI package; Phase A retains the actual historical evidence
needed by it.
