# Phase 5 temporary access contract

This is the implemented core contract extension. Peer connector adoption and
real-target acceptance remain outstanding; no Sakar source or branch is changed.
The existing signed `RATCHET_EXEC_V1` capability must additionally advertise
`scheduled_revocation: true` before a temporary grant can be dispatched. Absence
of that signed capability holds the grant. It is never enabled by a runtime flag.

The approved envelope binds the exact resources, permissions, role and fixed
duration. Signed command purpose `TEMPORARY_GRANT` freezes `grant_expires_at` to
database dispatch time plus that duration. Application must occur before both
that bound and the approval deadline. An already-existing assignment cannot
become timer-owned. Emergency requests retain impact analysis, independent
reviewer eligibility, quorum and passkey verification. Missing explicit scope or
additional effective authority is held; justification text is not scored.

Dispatch, immutable execution evidence, outbox delivery and the expiry River job
commit in one tenant transaction. Restart does not remove scheduled or overdue
jobs. An uncertain original write continues read-only reconciliation. Its timer
cannot assert that no grant was made or that access was revoked.

At expiry, purpose `EXPIRE_GRANT` carries the original approved envelope,
`original_command_id`, exact post-grant target revision and expected role set with
only the timer-owned assignment removed. The core signature authorizes only this
bounded inverse after the frozen expiry; the original approval assertion must
never authorize a new grant or arbitrary role replacement. The connector must
verify this relationship and atomically compare the target revision. Independent
changes cause refusal and review, including independently renewed access.

The core records `REVOKING` while access remains `EXECUTED`. Only an authenticated
result with exact target/roles/revision, application after expiry and independent
read-back changes it to `REVOKED`. A write acknowledgement is insufficient. Lost
results trigger durable verify-only probes; an authenticated CAS refusal records
expiry `FAILED`, retains active access state and appears in attention. No blind
write is retried against a changed target. Operator follow-up uses a new reviewed
request and current target state.

`ListChanges.temporary_grants_only` lists temporary requests, including expired,
revoked and failed revocations, at the same stable boundary as normal lists.
Responses include fixed expiry, expiry status and requested scope. Extra-resource
and extra-permission details remain reviewer/investigator restricted.

Approval validity is independently configurable with `approval_lifetime_seconds`
(1..86400; zero selects 900). Its exact-envelope job uses database time; it never
revokes an executed grant. Facts version 3 records deterministic scope evidence;
historical facts version 2 still replay under their original signed policy.

Core evidence: real PostgreSQL/River restart and late-job tests, actual approval
cryptography, signed command/result fixtures, uncertain read-back, mismatched-role
refusal, changed-revision refusal and post-expiry review/attention. These fixtures
test the core protocol boundary; they are not peer simulator acceptance evidence.
