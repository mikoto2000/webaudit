# Watch design

## Existing implementation (Phase A)

Base: origin/main b575c7b (local starting HEAD a26ee0f, clean main).
CLI: cmd/webaudit/main.go, standard flag package with interspersed arguments.
audit.Stream reads regular/gzip files and directories; audit.Parse normalizes
Apache/Nginx access and other supported formats. audit.Detect/Normalize provide
signature detection. Analysis.Observe/Finish implement two overlapping five-minute
partitions, leaky buckets and robust response/peer statistics. Correlator.Add,
AddSignal and Finish provide deterministic five-minute incident grouping and infer
outcomes. Upstream/Aura source-parity alerts are separate batch report collections.
GeoIP uses local verified MMDB snapshots with bounded LRU caches; no network is
required. Reports are HTML/JSON/CSV. There is no watch checkpoint store.

## Approach

Only `watch` starts monitoring. A bounded polling reader (250ms default) discovers
nonrecursive directory access-log candidates, checks identity, drains open old
handles before replacements, buffers partial lines and warns on truncation. Polling
also handles lost filesystem notifications without adding a dependency. Filename
selection is conservative, with include/exclude globs and parser validation.
Symlinks, compressed and nonregular files are rejected. Each poll has a byte budget
for fairness and cancellation. A maximum file count bounds handles and state.

The watch adapter retains a bounded event-time horizon, replays the same Detect,
Analysis and Correlator components at flush boundaries, and compares incident
snapshots. This avoids copying private batch accumulators or duplicating rules.
Replay is intentionally bounded; benchmarks determine its practical throughput.
Replays sort event time stably for multi-file arrival. Received time is separate.
Watermark = maximum observed event time minus allowed lateness; events older than
the retention horizon are rejected with diagnostics. Inactive incidents close after
the partition and lateness have elapsed (wall-clock idle timeout also permits close
when no logs arrive). Closed partitions are not reopened. Memory/count limits warn
when coverage is reduced. Retention must cover at least five minutes plus lateness.

Events use a watch-specific, redacted versioned schema, leaving batch reports
unchanged. Revision changes only when observable incident content changes; event
sequence and IDs persist. No raw URLs, headers or logs leave the adapter by default.

## Validation strategy

Phases B–F add failing behavior tests before production changes, verify Red/Green,
then review and refactor. Reader tests use temporary files and explicit poll calls
instead of timing-sensitive sleeps. Integration tests cover cancellation and CLI.
State corruption/restart and hook subprocess tests use no external services.
Existing batch tests, vet and race checks guard compatibility. Linux CI and Windows
local execution distinguish verified behavior from cross-compilation.

## Limitations

Polling cannot observe a file created and deleted entirely between polls. Concurrent
copytruncate can lose producer data, and truncate-and-regrow may evade size checks;
checkpoint anchors reduce but cannot eliminate this risk. Filesystem IDs can be
reused; identity plus content anchors are heuristic. Exactly-once hook execution
across crashes is impossible without a transaction with the external command.
Batch sees complete history; watch sees a bounded horizon and excludes finalized
late events. Source-parity Aura/Hub report collections remain batch-only; native
signature, behavioral, statistical and outcome logic is shared.
