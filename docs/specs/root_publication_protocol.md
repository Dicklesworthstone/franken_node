# Root Publication Protocol (bd-nwhn)

## Purpose

`root_pointer.json` is the canonical durability anchor for control-plane truth.  
Publication must be crash-safe and unambiguous: after any failure, the root is
either the previous committed value or the new committed value, never a partial.

## RootPointer Schema

```json
{
  "epoch": 42,
  "marker_stream_head_seq": 9001,
  "marker_stream_head_hash": "abc123...",
  "publication_timestamp": "2026-02-20T18:00:00Z",
  "publisher_id": "control-plane-node-a"
}
```

Field requirements:
- `epoch`: monotonic `u64` wrapper (`ControlEpoch`)
- `marker_stream_head_seq`: `u64`
- `marker_stream_head_hash`: non-empty deterministic hash string
- `publication_timestamp`: RFC3339 timestamp
- `publisher_id`: non-empty publisher identity

## Atomic Publication Algorithm

Given directory `dir` and candidate root `R`:

1. Serialize `R` to JSON bytes.
2. Write bytes to a unique temp file in `dir`.
3. `fsync(temp_file)` to guarantee temp durability.
4. `rename(temp_file, root_pointer.json)` (atomic replacement on POSIX).
5. `fsync(dir)` to guarantee durable directory entry update.

The implementation records ordered protocol steps:
- `write_temp`
- `fsync_temp`
- `rename`
- `fsync_dir`

## Crash-Safety Argument

Crash outcomes by boundary:

1. After `write_temp`: canonical root still points to old committed file.
2. After `fsync_temp`: canonical root still points to old committed file.
3. After `rename`: canonical path points to new file.
4. After `fsync_dir`: canonical path and directory entry are durable for new file.

Therefore canonical reads return either old or new root, never torn intermediate.

## Regression Rejection

Publishing `epoch <= current_epoch` is rejected with:
- error code: `EPOCH_REGRESSION_BLOCKED`
- no canonical root mutation

## Signed Control Event

Successful publish emits `ROOT_PUBLISH_COMPLETE` with:
- `old_epoch` (optional)
- `new_epoch`
- `marker_stream_head_seq`
- `manifest_hash`
- `timestamp`
- `trace_id`
- `signature`

Signature is keyed SHA-256 over canonical event payload for tamper-evident binding.

## Logging Contract

Event codes:
- `ROOT_PUBLISH_START`
- `ROOT_PUBLISH_COMPLETE`
- `ROOT_PUBLISH_CRASH_RECOVERY`

## Verification Surface

- Unit tests inside `crates/franken-node/src/control_plane/root_pointer.rs`
- Integration tests: `tests/integration/root_pointer_crash_safety.rs`
- Crash matrix artifact: `artifacts/10.14/root_publication_crash_matrix.csv`
- Gate evidence: `artifacts/section_10_14/bd-nwhn/verification_evidence.json`
