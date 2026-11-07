# Phase 7 hardening record

Started 2026-11-07 on main. Work follows the nine original tasks sequentially.
Phase 7 is not signed off. Earlier Phase 4 and peer integration gates remain
required; the final peer is d823a10, not an assumed corrected implementation.

1. Failure handling: added real TCP disconnect/recovery checks for PostgreSQL
   atomic writes and NATS durable outbox publication. Broker and Authority-source
   availability now appear separately in decision readiness, and expired
   execution capabilities degrade workflow readiness. Graph lag/quarantine,
   policy/registry changes, credential revocation and slow Authority handling
   retain their existing negative tests. The targeted Linux race/integration
   batch passes. This is local single-instance recovery, not HA. Actual peer
   connector and passkey acceptance must still be checked, not inferred.
2. Restart/replay, migrations and backup/restore: the real `recover --tenant`
   command verifies chain/schema, replays public graph facts and reconstructs
   change/audit projections without privacy keys or execution. A new-process
   test repairs a damaged audit projection and compares graph/chain commitments.
   A custom-format PostgreSQL dump restores into an owned scratch database;
   all 28 core/River table counts and ordered SHA-256 row commitments match.
   The original database is never a restore/drop target. Historical checkpoint
   verification retains its existing signed-history tests.
3. Privacy key deletion and sensitive access: real external-key creation/load/
   destruction and `graph_key_file` configuration are implemented, with no key
   material in CLI output. Deleting a real key after stopping/clearing its reader
   prevents private decryption while retained graph/chain commitments match.
   Existing requester/outsider/reviewer visibility and erasure tests pass with
   the new recovery checks. [Procedure and limits](core-recovery.md) explicitly
   require stopping readers and deleting backup/config copies; logical file
   deletion does not promise physical SSD erasure.
4. Resource limits, fuzzing, dependencies and domain boundaries: pending.
5. Selectable runtime roles: pending.
6. Actual peer web artifact embedding: pending.
7. Containers, SBOM, signatures and core runbooks: pending.
8. Full final-candidate checks including actual peer conformance: pending.
9. Joint D1-D8 evidence and release limitations: pending.

Docker Desktop's D-drive bind mount is unavailable in this session. The
`scripts/core-check.py` runner uploads only source into an owned temporary Linux
container, passes dependency credentials via environment, and cleans up that
container. It excludes .local and Git credentials. Existing dependencies are not
stopped by fault injection or runner cleanup.
