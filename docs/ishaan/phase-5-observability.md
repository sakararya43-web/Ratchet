# Core observability

The running console emits structured `core_span` log records for submit,
assessment, prepared policy decision, execution guard, outbox publication,
connector result and result verification. Each includes duration, failure flag,
opaque correlation UUID, trace/span/parent IDs and a hashed tenant reference.
No payload, justification, credential, approval signature, actor ID or error text
is accepted as a span attribute. Tests deliberately put secrets in errors and
request text and verify that they do not appear in the telemetry.

Trace IDs are derived from tenant plus correlation UUID so independent workers
join the same trace after restart. Synchronous operations retain parent IDs.
Signed execution commands persist a W3C-shaped `traceparent`; outbox publication
resumes it only if its trace matches the trusted tenant/correlation. It cannot
authorize a command or change its approved intent. This is structured-log tracing,
not an OpenTelemetry exporter, and it does not claim an external collector exists.
Async records without a persisted parent still share the correct trace ID.

`GET /api/metrics` returns tenant-local diagnostic JSON behind the existing HTTPS
session. The current signed investigator policy is checked in the read transaction;
requesters and anonymous clients are refused. The response is not cached. It
contains actual durable outbox backlog/oldest age/attempts, due/failed River jobs,
policy version/registry epoch, graph source quarantine/observation age, durable and
published graph positions, expired grants still awaiting verified removal, failed
expiry counts, open investigation age, and bounded per-operation span counts,
errors and total durations. It contains no identities, approval material or
private content. Span counters are tenant-isolated and process-local; durable
backlog/job/expiry values recover from PostgreSQL after restart.

Graph publication lag is the difference between ledger positions of the durable
graph and the graph currently published to API readers. It is named in positions,
not target mutations or milliseconds. A missing publication measurement is null,
not a false zero. Graph observation age is time since the oldest source's last
recorded observation; target freshness cannot be invented without connector data.
Open incident age is distinct from verified containment duration. Drift incidents
contribute durable sample count, total seconds and maximum seconds only after
signed independent corrective read-back, synchronized target roles and complete
zero-residual-path analysis mark them CONTAINED. Pending and failed corrections
do not contribute success samples. Durations run from incident opening to verified
containment, using database timestamps; the source observations are replayed from
the durable incident events after restart.

Real PostgreSQL and TLS tests verify actual queue/backlog/version values,
publication lag, trace correlation, privacy and investigator-only access. A
recorder can be supplied through the immutable workflow Config; the console wires
its configured logger, while library tests can use a private test sink.
