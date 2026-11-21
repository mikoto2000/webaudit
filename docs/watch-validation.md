# Watch validation

## Environment and scope

2026-11-21 JST. Local Windows NT 10.0.26300.0 amd64, Go 1.27.4,
24 logical processors; PROCESSOR_IDENTIFIER = Intel64 Family 6 Model 151
Stepping 2, GenuineIntel. No external test services. Dependencies use vendor/.
Temporary files and Go caches are inside the allowed workspace.

The local sandbox's default TEMP rejects directory rename in existing GeoIP tests.
Using workspace TEMP/TMP/GOTMPDIR resolves that environmental failure without
changing existing tests. Local race execution reports `-race requires cgo`; no C
compiler is installed here. Linux CI runs `CGO_ENABLED=1 go test -race ./...`.
Local Windows execution and Linux CI are distinct; cross-build is not runtime testing.

## Automated behavior coverage

- Reader: append, EOF/beginning, existing partial tail, partial concatenation,
  multi-line append, delete/recreate, rename, old backlog priority, copytruncate,
  rewrite anchors, multi-file directory selection, include/exclude, oversized lines,
  repeated rotation, handle limits and context cancellation.
- Detection: shared native signatures/behavior, normal requests, out-of-order and
  rejected late/future logs, correlation, outcome transition, severity escalation,
  count-only update suppression, close/finalization and retention.
- State: initial/missing snapshot, partial-line and rotated-ID restart, revision
  continuity, duplicate suppression, checksum/envelope validation, invalid/incomplete
  snapshot refusal, atomic replacement retaining previous state on validation error,
  reset, no-state, concurrent lock, pending detection recovery and path scope.
- Hooks: no hook, direct executable, JSON stdin, argument spaces/quotes/metacharacters,
  nonzero exit, timeout, process-tree cancellation, multiple hooks, concurrency 1/2,
  bounded queue/drop accounting, severity/event filters and persisted dedup history.
- Integration: CLI JSONL contains no diagnostics, optional local MMDB, explicit reset,
  checkpoint precedence, context cancellation, bounded repeated diagnostics.
  Existing GeoIP tests cover IPv4/IPv6, miss/corruption and cache behavior.
- Linux seccomp test denies network syscalls during actual watch startup, detection,
  JSONL and SIGINT both with and without local GeoIP. CI also retains all existing
  batch tests, evaluation, vet, parser fuzz and offline batch checks.

TDD Red/Green commits are retained in the six Phase PRs. Small additional tests
characterize integration and platform behavior. Test JSON and count summary are
under [measurements/watch](measurements/watch/). CI results are in the Phase PRs.

Final local result: 143 top-level tests passed, 333 passes including subtests,
0 failures, 11 existing Hub source-golden subtests skipped because they require
other products' acquisition/parsers. `go vet ./...` passed. Windows/Linux/macOS
amd64/arm64 release-style builds succeeded; build hashes and source are recorded
in builds.json. Only Windows binaries were executed locally.

Sample notify.ps1 was executed with synthetic stdin. Local PowerShell's script
policy rejected the default -File launch; the fixture test uses process-scoped
ExecutionPolicy Bypass only for its own temporary script. WebAudit neither adds
that option nor changes machine/user policy. notify.sh is checked in Linux CI.

## Component measurements

Measured source: fd57bae (recorded in each JSON; before the subsequent transient
discovery-failure fix). Reproduce from repository root with `go build -o watch-benchmark ./tools/watch-benchmark`,
then invoke modes below. Windows CPU/working-set sampling can be reproduced with
`pwsh tools/measure-watch.ps1 -Mode engine -BenchmarkPath ./watch-benchmark`
(or the other modes/options). Measurements use default 8192 retained events, 256-event
engine flush batches, one repeated public IP and tiny synthetic logs. This workload
does not estimate all production distributions. Memory/CPU include the benchmark
producer and process startup, but exclude Go compilation and checkpoint writes.
Hook process memory/CPU are excluded from the parent metrics.

Windows process CPU comes from Process.TotalProcessorTime; peak working set is
sampled with .NET every 50ms. CPU % is relative to **one core**, so parallel GC can
exceed 100%; it is not whole-machine utilization. Go heap samples and post-GC heap
are separate values in raw JSON. These are single runs, not confidence intervals.

| Mode and options | Result | CPU seconds / one-core % | Peak working set |
|---|---|---|---|
| engine, 10000 events | 0.953s, 10493 events/s | 2.2031s / 219.547% | 44.56MB |
| engine -geoip, repeated IP/test DB | 0.923s, 10830 events/s | 1.6094s / 161.754% | 44.78MB |
| reader -files 64, 10000 appends, 10 rotations | 1.880s, all 10000 lines | 1.2188s / 63.217% | 20.16MB |
| idle -files 1 -duration 10s | no events | 0.0625s / 0.617% | 17.75MB |
| soak -files 64 -duration 60s | 11100 lines, 11 rotations, 60.52s | 9.4844s / 15.658% | 45.17MB |
| simulated -lines 86400 (24h event time) | 24h horizon in 2.339s | 4.5938s / 188.854% | 27.52MB |
| hooks, 100ms child, 2 workers, queue 8 | hook completed=10 failed=0 dropped=990 | 0.0781s / 7.362% | 20.17MB |

MB means decimal bytes / 1,000,000. Raw measured numbers and environment are in
engine.json, engine-geoip.json, reader.json, idle.json, soak.json, simulated.json,
hooks.json. Comparing the two short GeoIP runs cannot establish CPU speedups;
process scheduling and GC vary. The GeoIP fixture is not a production-size DB.

The burst engine tests hit the retention count limit 1808 times; soak hit it 2908
times. They verify bounded storage and warning behavior, **not lossless detection
under overload**. Soak retained 8192 records, 4 incidents; post-GC heap 8.16MB.
The simulated 24-hour test retained 900 records and 9 incidents with no count-limit
warnings. It exercises expiration but is not a 24-hour wall-clock endurance run.
The longest wall-clock run here is 60 seconds; multi-day endurance and production
traffic distributions remain unverified. Polling/copytruncate/notification delivery
limitations are documented in [watch guide](watch.md).

