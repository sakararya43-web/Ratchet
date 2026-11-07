# Local access-review prototype

This is the sequential A/B/C milestone, not completion of the original plans.
The profile publishes real signed complete organization cuts and consumes only
core-signed ordinary role assignments/revocations through a persistent journal.
Reconciliation is read-only; unsupported purposes fail closed.

## Start and stop

Requirements: Docker Engine/Desktop with Compose, Python 3, an available local
port 8444 and 58085, and a browser with an existing platform authenticator.
No host Go/Node installation, paid service, domain or new hardware key is needed.

Run `python scripts/prototype.py start` from the repository. The first build can
take several minutes. Open `https://localhost:8444`. The local CA is exported to
`.local/prototype/ca.pem`; explicitly trust that local CA for manual browser
ceremonies. Do not disable certificate verification in production. Automated
browser tests use isolated test browser settings and do not modify OS trust.

Operator-issued passwords and initial one-use enrollment tickets are exported to
`.local/prototype/users.json`. Keep that file and `prototype.env` private. They
are excluded from Git and image build contexts. The running core has no operator
database credential and cannot mint credential tickets.

`python scripts/prototype.py stop` removes only this profile's containers/network,
retaining its named data volumes. `restart --no-build` preserves identities,
accounts, ledger, target state and cursors. Omit `--no-build` after code changes.
The profile uses its own database/NATS; existing core development containers are
not removed or reused. Ports bind only to loopback.

The four demo accounts are the finance intern, finance owner and two security
leads. All passwords/keys are freshly generated. Policy is the actual repository
Rego, signed by two local operator bootstrap keys. This is an explicitly read-only
genesis setup, not a claim of completed live passkey-backed Authority governance.
Root bootstrap signing keys are not retained in serving containers.

## Credential management

Enrollment/revocation needs both an authenticated session and a separate one-use
operator ticket. The operator verifies the intended recipient independently.
Initial tickets expire after one hour by database time; new ones can be issued:

`python scripts/prototype.py invite --actor user:sec-lead-1`

For revocation use `--operation revoke --credential <exact-credential-hex>`.
The result goes to `.local/prototype/credential-authorization.json`, not a public
endpoint. Treat tickets as secrets; an intercepted session is not sufficient.
Cancelled registration consumes its ticket and needs a fresh operator issuance.

Capabilities last at most 23 hours. A normal operator-backed restart refreshes
the capability with the same pinned key; the serving core never signs its own
connector capability. Re-run startup before a demo on another day. Certificates
are local development artifacts, not production deployment identities.
`python scripts/prototype.py renew-tls` explicitly replaces only the local TLS
certificate/CA; import the exported CA again after renewal. Ordinary restart
never rotates TLS or command signing identities.

## Phase gates and evidence

`python scripts/prototype-foundation.py` proves real TLS/password login,
organization ingestion/readiness and preserved identities/graph across restart.
Evidence is written under `.local/prototype/` with no passwords or tickets.
Current milestone gates and unfinished original scope are in
`prototype-progress.md`.
