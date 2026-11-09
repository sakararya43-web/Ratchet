# Completion A: implementation boundaries

This supplements completion-a-progress.md; it does not close unchecked gates.

## Live Authority

The separate Authority database has immutable settings and event receipts, plus a
rebuildable checked mutable head. Core gateway transport signs actor, tenant,
method/path, exact body digest and a short expiry. Each operation additionally
requires native passkey evidence. Current registry membership and current quorum
are independent Authority authorization policy; changing target Rego cannot grant
an Authority vote. Governance remains usable while target decisions are held
between registry rotation and adoption of a newly signed bundle.

Candidate enrollment only proves ownership of an operator-enrolled credential.
It grants no vote. Nonmembers receive only their own enrollment context, not
member-only proposals or other candidates. Current quorum must authorize member
addition/removal, credential rotation and threshold changes. Core always verifies
the original pinned root and full rotation history before using a new policy.

The original prototype root and discarded bootstrap keys are not replaced. The
new profile has an explicit enrollment-only server, which mounts no target-change
API. The operator pins the resulting native-member genesis after the first actual
quorum policy and starts the full core. Existing localhost TLS can be transferred
without changing trust. Pre-acceptance data/keys remain preserved separately.

## Remaining containment implementation design

- Reuse the existing durable Change, execution-attempt, outbox, target-receipt and
  read-only reconciliation paths, rather than accepting the old unsigned priority
  component as an authorization boundary.
- Add signed semantic before/after digests for supported simulator operations,
  preserving structural grant provenance while excluding display/timestamp-only
  metadata. Compare the actual complete target observation with that binding.
- For a confirmed plan, verify its canonical digest, purpose-separated responder
  proof, expiry, graph/policy/registry and current responder permission; re-simulate
  the full action set and prove all-identity monotonic reduction before staging.
- Each action has a stable command/request identity and exact target CAS preimage.
  Stage all action records, the incident link, priority outbox and recovery jobs in
  one tenant transaction. A separate priority relay and consumer reserve capacity;
  normal backlog must not block priority behind an old outbox head.
- Preserve original service grant IDs. Service permission removal targets that
  original grant, not an invented permission edge or an unrelated role string.
  Account restriction includes session revocation; termination targets an exact
  session. All four action kinds require actual receipt/read-back evidence.
- Incident projections record each action, uncertain/failed outcomes and remaining
  paths. Verified action receipts alone do not establish complete containment.
  Wait for corresponding signed source cuts, then recompute residual critical
  reach before CONTAINED. Restart probes never write or invent application time.
- Keep the minimum-cut planner. Explicit responder actions may need a separately
  labeled verified proposal with honest residual reach/optimality scope; ending
  one session need not isolate the entire owner account.

## Remaining restoration implementation design

Restoration is a fresh incident-linked normal review with no reuse of the
containment assertion. Bind it to a verified original action and current impact,
policy/registry, target preconditions and independent quorum. Roles reuse normal
ROLE_ASSIGN. Other supported increases enable the account, restore an exact
service grant, or issue a new session linked to its revoked predecessor. Never
revive the old session or implicitly re-enable sessions with the account.

The responder who requests sensitive restoration must leave enough independent
security leads to approve it. A signed policy can explicitly nominate a responder
outside the approver group; this is not an identity-header or application bypass.
Keep global graph/investigator permission separate from incident-scoped response.

Phase B owns automation/full console completion. Phase C owns complete offline
export/CLI proof and full project acceptance. Phase A must still retain all real
assertions, historical keys, contexts and outcomes those later checks require.
