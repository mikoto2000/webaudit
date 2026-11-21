# Watch state design

Schema 1 snapshot contains canonical targets, file identity and offset, partial line,
discard status, whether original line numbering is known, content anchor, bounded normalized event horizon, incident snapshots,
watermark, sequence and per-hook notification revision. Store under absolute
XDG_STATE_HOME/webaudit/watch, otherwise ~/.local/state/webaudit/watch on Unix or
LOCALAPPDATA/webaudit/watch on Windows. Target-set hash selects the snapshot.

Use an exclusive session lock; concurrent watchers of the same targets must fail
instead of corrupting state. Snapshot envelope carries SHA-256 for corruption
detection (not authentication). Reject unknown schema, mismatched targets, invalid
offsets, oversize snapshots and incomplete JSON. Do not silently restore portions.
Write a private temporary file, sync, close, atomically replace snapshot. Retain old
snapshot on failure. Checkpoint after output/dispatch, on interval and cancellation.
Crashes can replay events after the last checkpoint; stable IDs permit downstream
deduplication. Hook side effects and checkpoint commits are not transactional.

Store only bounded minimal event fields required for replay, not raw lines. Sensitive
query/header fragments necessary for matching are reduced to matching rule IDs;
replay consumes these IDs instead of retaining secret strings. Retain source path,
line, time, IP, status/size and hashed grouping fields. Partial lines necessarily
contain untrusted log fragments; keep the checkpoint private. --no-state disables
all persistence; --reset-state explicitly ignores the saved snapshot. Expired state
inside the active snapshot is pruned; inactive target snapshots are not automatically
deleted because they may be intentional checkpoints.
