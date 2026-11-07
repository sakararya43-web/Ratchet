# Phase 7 hardening record

Started 2026-11-07 on main. Work follows the nine original tasks sequentially.
All nine hardening/check/evidence tasks are delivered. Final required checks
pass on `7ddc8a9`; [completion evidence and open release gates](phase-7-completion.md).
The Phase 7 exit/full product sign-off remain open because earlier Phase 4
operations and integrated D1-D8 acceptance remain required. The peer stays d823a10.

1. Failure handling: added real TCP disconnect/recovery checks for PostgreSQL
   atomic writes and NATS durable outbox publication. Broker and Authority-source
   availability now appear separately in decision readiness, and expired
   execution capabilities degrade workflow readiness. Graph lag/quarantine,
   policy/registry changes, credential revocation and slow Authority handling
   retain their existing negative tests. The targeted Linux race/integration
   batch passes. This is local single-instance recovery, not HA. Actual peer
   connector and passkey conformance now pass in the final required checks.
2. Restart/replay, migrations and backup/restore: the real `recover --tenant`
   command verifies chain/schema, replays public graph facts and reconstructs
   change/audit projections without privacy keys or execution. A new-process
   test repairs a damaged audit projection and compares graph/chain commitments.
   A custom-format PostgreSQL dump restores into an owned scratch database;
   all 30 core/River table counts and ordered SHA-256 row commitments match in
   the final schema-15 restore (120,257 local rows; earlier sample had 28 tables).
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
4. Resource limits, fuzzing, dependencies and domain boundaries: per-instance
   request limits enforce 1 MiB bodies, 64 concurrent requests, 8 per authenticated
   actor/tenant (or authenticated certificate/actual peer IP), burst 60/refill 10
   per second and at most 10,000 hashed buckets. Forwarded headers are not identity.
   Size, rate, concurrency and tenant-isolation tests pass. Two sequential
   30-second single-worker fuzz runs pass (authentication and normalized native
   state/mutation; native run 136,579 executions). Domain direct-I/O/outward
   dependency checks pass. Updated advisory-bearing compress/crypto versions;
   govulncheck v1.9.0 now reports no vulnerabilities. CI enforces these checks.
   Reproduced five real passkey conformance failures in the unchanged final peer
   overlay. The authorized corrections in task 5 close them; final conformance
   asserts the required behavior directly, without expected-failure inversion.
5. Selectable runtime roles: console supports `--roles api,worker,relay`; graph
   supports `--roles api,ingest,relay`. Individual/composed roles are validated,
   and combined and separated real PostgreSQL/JetStream/TLS runtime tests pass.
   API-only does not consume queued graph work; backend roles expose no browser
   API. Every process refreshes its own graph cache. Console configuration can
   load actual signed connector capabilities and core signing keys; missing
   execution capability remains degraded, not a success substitute.
   User authorization on 2026-11-07 permits required peer integration fixes on
   main. Corrected origin/RP/ceremony/UV/COSE passkey verification and session-bound
   routes; all five historical conformance checks pass. Schema 15 persists
   credential enrollment/revocation and owner-scoped one-use ceremonies. Key
   commitments are ledger-bound; a separate read pool prevents tenant-lock/pool
   starvation during approval. A complete WebAuthn registration/assertion using
   real cryptography passes with wrong-session/replay/revocation/restart checks.
   There is no simulated assertion endpoint or seeded production credential.
6. Actual peer web artifact embedding: peer React/Vite source is reused from
   d823a10, with the authorized integration fixes replacing mock requests,
   simulated assertions and browser broker credentials with authenticated core
   APIs and actual browser WebAuthn ceremonies. The actual built assets and
   source/output SHA-256 manifest live in `internal/webassets/assets`; the build
   script and CI reproduce them. `serve_web` mounts the console on the HTTPS
   core origin. Missing/corrupt builds fail startup, API/health/metrics are
   reserved, and missing assets return 404. Combined and separated real TLS
   runtime tests pass, including self-only visibility and authenticated API 404.
   All 15 TypeScript canonicalization tests pass; npm audit finds no advisories.
7. Containers, SBOM, signatures and core runbooks: final 37,220,177-byte
   distroless image runs as 65532:65532 with read-only root/capabilities dropped.
   Pinned Syft generated an SPDX SBOM with 112 packages. Pinned Cosign signed and
   verified the actual OCI image digest with the SBOM hash; wrong key and wrong
   SBOM hash were rejected. The registry/keys were local/disposable, without a
   public transparency or production identity claim. CI reproduces and uploads
   the evidence. Core role/configuration, readiness, build and recovery procedures
   are in [core-runtime.md](core-runtime.md) and [core-recovery.md](core-recovery.md).
8. Complete: both hosted jobs passed on `7ddc8a9`, including full main race/
   integration, whole-main lint/vet, properties/fuzz, nonempty OPA tests, Buf/
   generators, actual conformance, real Compose process smoke and pinned peer
   scenarios/combined race/actual Authority/restore. Real kind comparison,
   inventory/storage and admission/approval/outage/drift/incident checks also
   pass on that candidate. The IP-pooling defect found in CI is fixed without
   increasing rates or weakening authentication; all guards retain regressions.
9. Complete: [joint evidence report](phase-7-completion.md) attaches current
   D1-D8 scope, actual peer scenario/CLI results, exact public artifacts, measured
   performance/benign outcomes, P1 status, native boundaries and R6/P2 limits.
   It explicitly retains unfinished Phase 4 and full integrated release gates.

Docker Desktop's D-drive bind mount is unavailable in this session. The
`scripts/core-check.py` runner uploads only source into an owned temporary Linux
container, passes dependency credentials via environment, and cleans up that
container. It excludes .local and Git credentials. Existing dependencies are not
stopped by fault injection or runner cleanup.
