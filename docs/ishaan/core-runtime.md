# Core runtime, artifacts and readiness

Use the same migration version, tenant pins, policy history and privacy key for
all core roles. Keep private configuration outside the image and source checkout.
Supply `RATCHET_DATABASE_DSN` for the non-superuser runtime role; only the separate
`migrate` and `provision-users` operations receive `RATCHET_MIGRATION_DSN`.
`scripts/core-env.ps1` creates local credentials, and `core-env-load.ps1` loads
them without printing them. Never put credentials in command arguments or logs.

The supported console combinations are:

```text
ratchetd console-serve --config ABSOLUTE_PRIVATE_CONFIG --roles api,worker,relay
ratchetd console-serve --config ABSOLUTE_PRIVATE_CONFIG --roles api
ratchetd console-serve --config ABSOLUTE_PRIVATE_CONFIG --roles worker,relay
```

Choose distinct listen addresses for separate processes. The graph surface uses
`graph-serve --roles api,ingest,relay`, or separate `api` and `ingest,relay`
processes. Backend roles expose health only. Each API process maintains its own
graph cache from the durable database; API-only graph roles never consume broker
input. These are local role combinations, not an HA/cell routing implementation.
Tenant identity remains explicit in every retained event and broker message.

Console configuration requires a canonical HTTPS `origin`, `server_cert`,
`server_key`, distinct 32-byte `session_key_hex` and `cursor_key_hex`,
`graph_key_file` (or legacy `graph_key_hex`), `nats_url`, and `tenants`.
Remote NATS additionally requires TLS and a private `nats_credentials` file.
Each tenant pins `tenant_id`, `authority_file`, `genesis_digest` and its signed
`bundle_file`. Optional `containment_costs` are explicit action-cost integers.
Set `serve_web: true` to serve the actual embedded React build on this HTTPS
origin; authentication and browser passkeys must use that exact origin.
Provision password users separately; register passkeys through authenticated
HTTPS sessions. No browser target token, default credential or simulated
assertion endpoint is installed.

To enable execution, each tenant's `execution` supplies `connector_id`,
`connector_public_key_hex`, `core_signing_key_file` and `capability_file`.
Files must be absolute paths. The key must be a valid Ed25519 private key, and
the capability must be signed, tenant/connector-bound and unexpired. Missing
execution credentials keep decision readiness degraded; assessment and durable
read APIs do not imply permission to execute. Native connector pins additionally
specify connector, cluster and public key. Do not silently reuse credentials
across tenants. Authority refresh never substitutes an unverified bundle.

`/livez` reports process liveness. `/readyz/storage` checks DB, migrations and
runtime privileges. `/readyz` additionally checks graph freshness, verified
policy, workflow/execution, broker and Authority-source availability. A 503 is
an operational dependency report, not a reason to disable guards. Console APIs
are under `/api/` with secure sessions and CSRF; graph ingress uses its separate
mutual-TLS identity. Health, metrics and API errors never fall back to SPA HTML.

Build and check artifacts sequentially:

```text
python scripts/core-web-build.py
docker build -f deploy/core.Dockerfile -t ratchet-core:phase7 .
python scripts/core-supply-chain.py
```

The Dockerfile packages the actual embedded build and both core binaries, pins
base-image digests, and runs distroless as UID/GID 65532. Run with read-only root,
all capabilities dropped and `no-new-privileges`; mount only required private
configuration read-only. Key creation/destruction is an explicit operator action
outside a read-only service container. This is a build/test procedure, not a
deployment blueprint.

The supply check runs the actual image under those restrictions, generates an
SPDX SBOM using pinned Syft, signs its immutable OCI digest plus the SBOM hash
using pinned Cosign, verifies both, and rejects a wrong key and wrong SBOM hash.
Its loopback registry and signing keys are disposable local test resources.
`.local/phase7-supply` retains the SBOM, public key, verified claims and summary;
CI uploads them. No public transparency log, production identity, production
signing key or published release is claimed. A release must use the chosen
release identity and independently pinned public key.

Follow [core recovery and privacy keys](core-recovery.md) for real backup/restore,
replay verification, projection rebuild and key retirement. Never recover by
turning off append-only/RLS checks or restoring over the only retained database.
