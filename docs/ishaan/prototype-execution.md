# Prototype execution acceptance

The simulator executable accepts only schema-1 commands from its pinned core
Ed25519 key. It checks tenant/connector/UUIDs, dispatch/deadline, format-2 envelope
hash and exact role preconditions. The allowlist is ROLE_ASSIGN / ROLE_REVOKE
without temporary grants, containment, native payloads or unknown purposes.
There is no unsigned decoding fallback or default action.

A private per-command journal is flushed and atomically replaced before target
I/O. The target atomically commits its own CAS mutation and command receipt.
Independent read-back recovers that receipt after a crash, with its original
application time. Signed results are flushed before JetStream publication and
ACK. Redelivery preserves the result ID and bytes. A changed command identity
cannot reuse the journal. Verify-only messages never call Execute, including
after the approval deadline. A failed/unchanged observation has zero AppliedAt;
changed/uncertain state stays unverified for core reconciliation.

The real target also refuses expired writes under its mutation lock. Observation
roles use the core's sorted-role canonical digest and actual target revision.
The connector readiness endpoint requires recent confirmed source publication
and a bounded live broker probe. It is internal loopback, without target secrets.

Repeat executable acceptance against the real local NATS dependency:

```powershell
. ./scripts/core-env-load.ps1
python scripts/core-check.py go test -race -p=1 -tags=integration ./cmd/ratchet-connector ./internal/connector/... ./cmd/ratchet-sim/... -count=1
```

TestExecutableAuthenticatedCASAndCrashRecovery builds and launches the actual
connector executable. It proves unsigned/unknown refusal, no verify-only write,
stale preimage refusal, target commit followed by read outage/process death,
receipt recovery through JetStream redelivery, subsequent restart and dedup.
HTTP race tests additionally prove failed publication recovery, exact signed
result bytes/timestamps, sorted multi-role evidence, real revocation, expired
write refusal and conflicting command-ID refusal. No production test endpoints
or synthetic target receipts are used.
