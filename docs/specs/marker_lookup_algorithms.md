# Marker Lookup Algorithms — bd-129f

> O(1) marker lookup by sequence and O(log N) timestamp-to-sequence search.

## Overview

The marker stream (bd-126h) is a dense, append-only, hash-chained log of
high-impact control events. This specification defines two lookup primitives
that make the stream operationally viable at scale.

## Algorithms

### 1. `marker_by_sequence(seq: u64) -> Option<&Marker>`

**Complexity:** O(1)

Because the marker stream enforces a dense sequence invariant (marker N lives
at index N with no gaps), sequence-to-marker lookup is a direct array index
operation:

```
if seq < markers.len() then markers[seq] else None
```

No search is required. The cost is one bounds check and one pointer
dereference, independent of stream size.

**Proof sketch:**
- The dense sequence invariant (INV-MKS-DENSE-SEQUENCE) guarantees
  `marker[i].sequence == i` for all `i` in `0..len`.
- Vec indexing in Rust is O(1) (pointer arithmetic).
- Therefore `marker_by_sequence(seq)` is O(1).

### 2. `sequence_by_timestamp(ts: u64) -> Option<u64>`

**Complexity:** O(log N)

Because the monotonic time invariant (INV-MKS-MONOTONIC-TIME) guarantees
that timestamps are non-decreasing, binary search is valid over the
timestamp-ordered sequence.

The algorithm finds the rightmost marker whose timestamp is <= the query
timestamp (upper-bound binary search):

```
if markers is empty: return None
if ts < markers[0].timestamp: return None

lo = 0, hi = len
while lo < hi:
    mid = lo + (hi - lo) / 2
    if markers[mid].timestamp <= ts:
        lo = mid + 1
    else:
        hi = mid
return markers[lo - 1].sequence
```

**Proof sketch:**
- The loop maintains the invariant that all markers in `[0, lo)` have
  timestamp <= ts and all markers in `[hi, len)` have timestamp > ts.
- Each iteration halves the search space: O(log N) iterations.
- Each iteration performs O(1) work (one comparison, two assignments).
- Therefore `sequence_by_timestamp(ts)` is O(log N).

**Edge cases:**
| Condition | Result |
|---|---|
| Empty stream | `None` |
| `ts` before first marker | `None` |
| `ts` exactly matches a marker | That marker's sequence |
| `ts` between two markers | Sequence of the earlier marker |
| `ts` at or after last marker | Last marker's sequence |
| Multiple markers with same timestamp | Sequence of the last such marker |

## Performance Targets

| Operation | Target (p99) | Stream size |
|---|---|---|
| `marker_by_sequence` | < 1 microsecond | any |
| `sequence_by_timestamp` | < 100 microseconds | up to 10M markers |

These targets are enforced by benchmark tests in
`tests/perf/marker_lookup_complexity.rs`.

## Data Structures

The lookup functions operate on `MarkerStream` from bd-126h, which stores
markers in a `Vec<Marker>`. The dense sequence invariant means no auxiliary
index is needed for O(1) sequence lookup. The monotonic time invariant means
no auxiliary index is needed for O(log N) timestamp lookup.

## Implementation Location

- `crates/franken-node/src/control_plane/marker_stream.rs`
  - `MarkerStream::marker_by_sequence()`
  - `MarkerStream::sequence_by_timestamp()`

## Structured Log Events

| Event Code | Level | Fields |
|---|---|---|
| `MARKER_LOOKUP_SEQ` | DEBUG | seq, found (bool), elapsed_ns, trace_id |
| `MARKER_LOOKUP_TS` | DEBUG | timestamp, result_seq, elapsed_ns, trace_id |

Debug-level only to avoid log volume impact in production.

## Dependencies

- **Upstream:** bd-126h (append-only marker stream provides the data structure)
- **Downstream:** bd-3epz (section gate), bd-5rh (plan gate)
