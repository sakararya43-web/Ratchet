# Phase 5 core measurements

Measured on 2026-11-05, Intel Core i7-1260P, 16 logical CPUs, Go 1.27.3.
The Linux run used Docker Desktop, amd64 Debian bookworm, a two-CPU quota and
GOMAXPROCS=2, with the real local PostgreSQL service on host networking. The native
Windows run used GOMAXPROCS=16. These are single-host measurements, not production
capacity or high availability evidence. Timing uses monotonic elapsed time;
percentiles use nearest rank. Race instrumentation is excluded from timing runs.

The checked-in JSON includes exact node/edge compositions, sample and warmup
counts, p50/p95/p99/max/mean, targets and whether each measured target was met.
Before-final-profile files retain the earlier measurements; they are not deleted
when an optimization improves the result. The current Linux run is:

| Workload | Samples / warmups | p50 | p95 | p99 | Max |
|---|---:|---:|---:|---:|---:|
| Durable inline core, exchange demo | 100 / 5 | 19.60 ms | 27.81 ms | 33.65 ms | 38.35 ms |
| ImpactDiff, 100,000 shared edges | 50 / 3 | 29.69 ms | 44.90 ms | 104.06 ms | 104.06 ms |

The inline sample meets the 50 ms core p99 target for its measured branch. The
ImpactDiff tail still exceeds 100 ms; performance work is not marked complete.
The earlier Windows sample missed both targets (85.90 ms / 204.08 ms p99) before
the final profiling improvement. Neither machine's result is generalized to all
supported operations, concurrent load, network latency or very large fan-out.

The inline workload includes database graph loading, verified policy and registry
floor checks, prepared OPA evaluation, impact analysis, hash-chain append, audit
projection and durable outbox commit. It evaluates fresh unapproved wallet-role
requests on the actual exchange-v1 fixture compiled with the explicitly reviewed
core semantics. It does not measure TLS, browser passkeys, an allow's credential
reverification, target writes or remote admission. It returns the real two-lead
approval requirement and never labels that result an executed grant.

The demo has 26 nodes and 41 edges, including six humans, two service accounts,
five roles, five resources, two safeguards and three sessions. The large workload
has 22,000 nodes: 800 humans, 200 service accounts, 1,000 shared roles and 20,000
resources; exactly 100,000 edges comprise 89,960 grants, 10,000 assignments and
40 control relations. The tested assignment affects the target and its controller.
The existing 100,000-resource fan-out benchmark remains available separately and
is not substituted with the easier shared-role case.

Profiling identified redundant all-edge structural proof allocation after an
increase had already been proved. That proof now runs only while a reduction is
still possible. Edge-only overlays share immutable node indexes and merge sorted
relations, preserving isolated proposal state. Analysis derives a conservative
reverse dependency closure in both snapshots and reuses each traversal result.
The 300-seed property suite compares the resulting impact with full-principal
analysis, including controllers, denials, disabled identities and safeguards.
The shared-edge one-CPU native benchmark improved from approximately 163 ms to
45 ms after the profiled allocation was removed. This average is not a p99 claim.

The benign replay uses 100 distinct target identities: 80 ordinary finance
requests, five temporary finance requests, five emergency finance requests and
ten tier-0 requests. Expected legitimate outcomes explicitly include independent
owner/lead review with the required quorum. Actual Submit and Assess run against
PostgreSQL and the real signed policy. Both measured runs report **0/100 (0%)**
unexpected assessment outcomes, with denominator, outcome counts and cause bins.
This is core intake/assessment evidence. Approval completion, user waiting time
and actual target execution remain outside its scope and require peer acceptance.
Expected review is not counted as a false rejection; observed HOLD/error or wrong
quorum is counted and cannot be omitted from the denominator.

Reproduce core measurements from the repository root after loading the private
local dependency environment:

```powershell
. ./scripts/core-env-load.ps1
$env:RATCHET_EVALUATION_DIR = 'D:\Ishaan projects\Ratchet\docs\ishaan\evidence\phase-5'
go test -tags=integration -count=1 -v ./internal/workflow -run 'TestPhase5MeasuredPerformance|TestPhase5BenignCoreReplay' -timeout=2m
go test ./internal/evaluation -run '^$' -bench '^BenchmarkImpactShared100k$' -benchtime=15x -benchmem -cpu=1
```

Linux uses the same test command inside `golang:1.27.3-bookworm` with `--cpus 2`,
the existing Go cache volumes and source mount, host networking, and the runtime/
migration DSNs passed by environment variable name. No credentials are written to
the evidence. The harness is Ishaan-owned; peer `e2e/` scripts remain untouched.
