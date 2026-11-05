# Periodic checkpoint candidates

FR-L2's core candidate scheduler uses ordinary open-source River jobs. Configure
tenant `checkpoint_actor`, `checkpoint_authority_url` and optionally
`checkpoint_interval_seconds` (default 900; permitted 1 through 86400). The actor
must remain eligible under current `checkpoint_manage` policy. Invalid schedule
configuration fails startup. No background identity bypass is introduced.

The database retains one next-run slot per tenant. Startup restores that exact
slot and inserts its unique durable job. Each tick locks the tenant head, checks
database time and current authorization, and either retains the existing pending
candidate for the current registry/range or prepares a bounded successor. It
atomically commits the candidate, next deadline, next job and delivery job.
Concurrent and stale ticks cannot create extra roots. Missed periods coalesce
after downtime; event coverage still starts after the last accepted checkpoint
and catches up in consecutive ranges of at most 4096 events/16 MiB.

Delivery is a separate durable worker. It uses the real Authority HTTP boundary
outside the tenant write lock, looks up an existing frozen candidate before any
create request and preserves member signatures after lost acknowledgements.
Every returned signature is verified against the frozen root-verified registry.
An unsigned or valid partial quorum remains pending and is polled again; malformed
metadata or signatures fail. Only a complete independently verified quorum reaches
normal checkpoint acceptance. The core never signs for Authority members. Registry
rotation cancels stale delivery; the next tick binds the new registry.

Core tests use actual PostgreSQL/River, actual cryptographic member signatures and
an HTTP protocol harness to verify restart, missed deadlines, pending-root reuse,
concurrent ticks, authorization, signature waiting and idempotent acceptance after
service replacement. Existing actual-peer Authority executable acceptance remains
separate evidence; a protocol harness is not a claim of deployed peer integration.
