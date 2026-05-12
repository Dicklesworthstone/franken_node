# bd-129f: Verification Summary

## O(1) Marker Lookup by Sequence and O(log N) Timestamp-to-Sequence Search

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (37/37 checks)
**Agent:** SnowyBeaver (codex-cli, GPT-5)
**Date:** 2026-05-12

## Implementation

- **Module:** `crates/franken-node/src/control_plane/marker_stream.rs` (extended from bd-126h)
- **Spec:** `docs/specs/section_10_14/bd-129f_contract.md`
- **Verification:** `scripts/check_marker_lookup.py`
- **Test Suite:** `tests/test_check_marker_lookup.py` (26 tests)

## Operations Implemented

| Operation | Complexity | Mechanism |
|-----------|-----------|-----------|
| `marker_by_sequence(seq)` | O(1) | Base-adjusted Vec index (`markers.get(sequence_offset(base, seq)?)`) |
| `sequence_by_timestamp(ts)` | O(log N) | Binary search over monotonic timestamp order |
| `first()` | O(1) | `markers.first()` |

## Performance Targets

| Operation | Target | Mechanism |
|-----------|--------|-----------|
| Sequence lookup | < 1 microsecond | Vec index = single pointer arithmetic + bounds check |
| Timestamp lookup | < 100 microseconds (10M markers) | Binary search: ~23 comparisons for 10M entries |

## Algorithm Details

### marker_by_sequence (O(1))

Since `MarkerStream` enforces the dense sequence invariant (INV-MKS-DENSE-SEQUENCE), every retained marker lives at a stable offset from the first retained sequence. The lookup computes that offset and performs a single `.get(sequence_offset(base, seq)?)` call, which is O(1) and returns `None` for evicted or out-of-range sequences.

### sequence_by_timestamp (O(log N))

Since `MarkerStream` enforces monotonically non-decreasing timestamps (INV-MKS-MONOTONIC-TIME), binary search is valid. The algorithm finds the rightmost marker with `timestamp <= ts`:
- `lo = 0`, `hi = len` (exclusive)
- At each step: if `markers[mid].timestamp <= ts`, move `lo = mid + 1`; else `hi = mid`
- Result: `markers[lo - 1].sequence`

### Edge Case Handling

| Case | Result |
|------|--------|
| Empty stream | `None` |
| Out-of-range or evicted sequence | `None` (no panic) |
| Timestamp before first marker | `None` |
| Timestamp after last marker | Last sequence |
| Duplicate timestamps | Rightmost marker at that timestamp |
| `u64::MAX` sequence | `None` |

## Unit Tests (Rust)

14 bd-129f-specific tests embedded in `marker_stream.rs`:

| Test | Coverage |
|------|----------|
| `marker_by_sequence_first` | First marker lookup |
| `marker_by_sequence_last` | Last marker in 10-element stream |
| `marker_by_sequence_middle` | Middle marker |
| `marker_by_sequence_out_of_range` | Beyond stream bounds + u64::MAX |
| `marker_by_sequence_empty_stream` | Empty stream returns None |
| `sequence_by_timestamp_exact_match` | Exact timestamp hits |
| `sequence_by_timestamp_between_markers` | Between-marker interpolation |
| `sequence_by_timestamp_before_first` | Before first timestamp |
| `sequence_by_timestamp_after_last` | After last + u64::MAX |
| `sequence_by_timestamp_empty_stream` | Empty stream returns None |
| `sequence_by_timestamp_single_marker` | Single-element edge case |
| `sequence_by_timestamp_duplicate_timestamps` | Multiple markers at same timestamp |
| `sequence_by_timestamp_large_stream` | 10,000 markers correctness |
| `marker_by_sequence_matches_get` | Consistency: matches existing `get()` |

## Verification Results

- **Python verification script:** 37/37 checks pass
- **Python unit tests:** 26/26 tests pass
- **Rust marker-stream filter:** `rch exec -- cargo test -p frankenengine-node marker_stream -- --nocapture` passed; the filter exercised `e2e_marker_stream_lifecycle` (4/4 tests) and compiled the marker stream surface successfully.

## Downstream Unblocks

This bead supports:
- bd-3epz: Section 10.14 verification gate
- bd-5rh: PLAN 10.14 FrankenSQLite execution track
