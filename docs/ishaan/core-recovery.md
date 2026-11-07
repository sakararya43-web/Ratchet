# Core recovery and privacy keys

Stop core writers before taking a recovery measurement. Keep migration and
runtime credentials separate. This is local single-instance recovery, not HA.

`ratchetd recover --tenant TENANT` checks the runtime role, schema, retained
chain, public graph replay, changes and audit projections. It returns only
counts and commitments. Add `--rebuild` to reconstruct mutable change/audit
display rows from retained events. It neither executes target actions nor needs
the privacy key. Concurrent tenant advancement refuses the measurement; quiesce
writers and retry. Existing checkpoint-history verification remains mandatory
for a release export; chain verification alone is not external witnessing.

Run `python scripts/core-backup-smoke.py` against the existing local Compose
dependencies to rehearse custom-format dump and restore. It restores into its
own generated database and compares every core/River table by count and ordered
SHA-256 row commitments. It cleans up only that database and temporary dump.
Keep actual recovery backups in protected storage; this smoke deliberately does
not leave a private-data archive behind. A deployment restore must first restore
the configured non-superuser roles, restore into a new database, run migrations
with the migrator DSN, then verify retained evidence and rebuild projections
with the runtime DSN before directing any core process to it. Never restore over
the only evidence-bearing database or disable the append-only triggers.

For an external graph/privacy key, create a private parent directory and run:

```text
ratchetd privacy-key create --file ABSOLUTE_PRIVATE_KEY_PATH
```

Set `graph_key_file` in graph/console configuration. It is mutually exclusive
with legacy `graph_key_hex`; the command never prints the generated key. On
POSIX the file must be private (0600); on Windows protect its directory/file ACL.
The same key must be available to the core roles that decrypt this source.

To retire a key, stop **all** its readers and remove every inline-config and
backup copy before running `privacy-key destroy --file ABSOLUTE_PRIVATE_KEY_PATH`.
Restart without that retired key. Existing retained ciphertext cannot be
decrypted; public graph/decision replay and chain verification remain available.
Raw review context is intentionally unavailable after destruction. Individual
records can instead be removed with the existing tenant-scoped private-record
deletion operation; that operation does not destroy a shared key.

This is logical key-file deletion. It cannot erase another process's memory,
old copied configuration, independently retained backups or remapped SSD blocks.
Do not claim cryptographic erasure while such key copies still exist. The
external-key test creates a real file, reads retained private context, stops its
reader, clears the loaded key, destroys the file, and proves public replay and
chain commitments survive while private decryption fails.
