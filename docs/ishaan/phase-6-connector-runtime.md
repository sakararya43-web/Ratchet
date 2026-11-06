# Native Kubernetes connector runtime

The user authorized connector fixes on `main`; the `sakar` branch and its plan
remain unchanged. `cmd/ratchet-k8s-webhook` now runs the native protocol. It uses
the selected cluster's real API through `kubectl`, not a seeded cluster model.
The shared simulator model file is reused only as a dependency of the peer's
generic connector types; it does not install a simulator server on main.

Build with `go build ./cmd/ratchet-k8s-webhook` and run with `-config` pointing
to a private JSON file. All file paths in the configuration are absolute. The
accepted fields are documented by `k8s.RuntimeConfig`; unknown fields fail.
Required inputs include tenant/connector/cluster IDs, private kubeconfig and
state directory, attested directory file, listener address, server certificate
and key, dedicated API-server client CA, core HTTPS URL and CA, pinned core
Ed25519 public key, connector Ed25519 private key, AES-256 storage key, NATS URL
and output capability path. Optional NATS credentials use the native NATS
credentials file. Public/private/storage key files contain hexadecimal bytes
of lengths 32/64/32 respectively; secret files must remain outside Git.

The directory document contains `complete: true` and a `principals` array of
normalized native principals. It attests the selected human identity/group
roster, because Kubernetes has no enumerable human directory. Actual service
accounts and UIDs come from the API. The kind checks use actual `auth whoami`
profiles, including an exact certificate credential fingerprint. Unknown extra
claims and admission callers absent from the attested directory fail closed.

The HTTPS listener requires client certificates trusted by the dedicated
API-server CA. `/validate` accepts bounded v1 AdmissionReviews. Configure the
API server's admission-controller credential kubeconfig for the exact webhook
host and port; a client able to post arbitrary userInfo must not be trusted.
The mechanism follows the [Kubernetes API-server authentication instructions](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#authenticate-api-servers).
There is no insecure transport option or caller-supplied local approval route.

Preflight obtains two equal complete API cuts, persists a source revision,
publishes a signed normalized snapshot to JetStream and creates the native
command stream. The runtime then writes a signed one-hour native capability.
It claims no scheduled revocation or arbitrary reduction capability. The core
must explicitly trust its key and capability; the runtime does not configure
core approval or execution factories for an operator.

Each admission checks live inventory against the cached published source cut,
then sends the complete exact context to the authenticated core endpoint. Only
a staged core-signed command and an exact core-signed one-use permit can allow.
DELETE also requires UID/resource-version DeleteOptions preconditions. Pending
context is sealed before contacting core, and the permit is persisted before
returning allow. Failed/ambiguous outcomes never trigger a connector write.

The runtime consumes durable commands, reconciles every 100 ms, and publishes
independently read signed results from encrypted durable pending records. A
lost result acknowledgement republishes the same result. Once an unadmitted
command expires, complete actual inventory may prove an unchanged target and
report failure. A changed/recreated target is held for review. Application first
observed after permit expiry is held; no earlier write timestamp is invented.

Inventory refresh runs separately every 15 seconds. `/readyz` requires recent
snapshot publication, a connected broker and a successful HTTPS core readiness
probe; the endpoint itself requires the same client TLS authentication. Incoming
requests, outbound API output and native message sizes are bounded.

Selected real API-server mutual-TLS admission, approved write/read-back, outage
refusal and latency acceptance pass on main. Actual signed post-write source
cuts and `PublishDrift` observations also prove approved correlation and native
incident get/list/stream evidence. See [results and reproduction](phase-6-kind.md).
The drift publication method signs and transports a supplied actual observation;
the runtime does not automatically collect cluster-wide watch/audit reports.
Automatic native correction and live containment continuity are unsupported
selected D6/D7 mappings. Full standalone runtime restart/outage hardening belongs
to Phase 7; encrypted context restart and durable command/result retries already
have focused tests. No success is inferred for ambiguous application outcomes.
