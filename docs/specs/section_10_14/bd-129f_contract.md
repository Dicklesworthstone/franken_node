# bd-129f: O(1) Marker Lookup and O(log N) Timestamp Search

## Purpose

Provide efficient access patterns for the append-only marker stream (bd-126h).
O(1) sequence lookup enables instant access to any marker by position.
O(log N) timestamp-to-sequence search enables temporal queries ("find the marker
active at time T") using binary search over the monotonically-ordered stream.

## Dependencies

- **Upstream:** bd-126h (provides the `MarkerStream` data structure)

## Operations

### `marker_by_sequence(seq: u64) -> Option<&Marker>`

O(1) lookup. Since the stream is dense (sequence N = array index N), this is
a direct index operation. Returns `None` for out-of-range sequences.

### `sequence_by_timestamp(ts: u64) -> Option<u64>`

O(log N) binary search. Because INV-MKS-MONOTONIC-TIME guarantees non-decreasing
timestamps, binary search is valid. Returns the sequence of the rightmost marker
with timestamp <= ts.

- Empty stream -> `None`
- ts before first marker -> `None`
- ts at or after last marker -> last sequence
- ts between markers -> sequence of the marker just at or before ts

### `first() -> Option<&Marker>`

Returns the first marker (sequence 0), or `None` if empty.

## Complexity Guarantees

| Operation | Complexity | Mechanism |
|-----------|-----------|-----------|
| `marker_by_sequence` | O(1) | Vec index |
| `sequence_by_timestamp` | O(log N) | Binary search |
| `first` / `head` | O(1) | First/last element |

## Performance Targets

- Sequence lookup: < 1 microsecond for any stream size
- Timestamp lookup: < 100 microseconds for streams up to 10M markers

## Edge Cases

- Empty stream: all lookups return `None`
- Single marker: exact, before, and after timestamp cases
- Duplicate timestamps: returns rightmost marker at that timestamp
- Out-of-range sequence: returns `None` (no panic)
- Maximum u64 sequence/timestamp: no overflow

## Artifacts

- Implementation: `crates/franken-node/src/control_plane/marker_stream.rs` (extended)
- Spec: `docs/specs/section_10_14/bd-129f_contract.md`
- Evidence: `artifacts/section_10_14/bd-129f/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-129f/verification_summary.md`
