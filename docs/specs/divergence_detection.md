# Divergence Detection Contract (bd-xwk5)

## Purpose

Detect the exact fork point between two append-only marker streams so
control-plane reconciliation can be deterministic and auditable.

The detector returns:
- greatest common prefix
- first divergence sequence
- local/remote hash evidence at the divergence point
- comparison trace proving how the boundary was selected

## API

`find_divergence_point(local: &MarkerStream, remote: &MarkerStream) -> DivergenceResult`

### `DivergenceResult` fields

- `has_common_prefix: bool`
- `common_prefix_seq: u64`
- `has_divergence: bool`
- `divergence_seq: u64`
- `local_hash_at_divergence: Option<Hash>`
- `remote_hash_at_divergence: Option<Hash>`
- `evidence: DivergenceEvidence`

### `DivergenceEvidence` fields

- `comparison_count: usize`
- `comparisons: Vec<DivergenceComparison>`

Each `DivergenceComparison` includes:
- `sequence`
- `matched`
- `local_hash_prefix`
- `remote_hash_prefix`

## Algorithm

1. Let `shared_len = min(local.len(), remote.len())`.
2. If `shared_len == 0`, divergence is at sequence 0 when lengths differ.
3. Otherwise binary-search range `[0, shared_len)` for the first mismatching
   marker hash.
4. If no mismatch exists in shared range:
   - same lengths -> no divergence
   - different lengths -> divergence at `shared_len`
5. Derive:
   - `common_prefix_seq = divergence_seq - 1` when `divergence_seq > 0`
   - no common prefix when `divergence_seq == 0`

## Complexity

- Marker-hash comparisons are `O(log N)` for shared prefix size `N`.
- Additional work outside comparisons is `O(1)`.
- Evidence recording is bounded by the number of comparisons.

## Determinism and Symmetry

For fixed input streams, output is deterministic. Calling with reversed inputs
preserves:
- `has_divergence`
- `has_common_prefix`
- `common_prefix_seq`
- `divergence_seq`

Only side-specific hashes swap (`local_*` <-> `remote_*`).

## Edge Cases

- Identical streams -> `has_divergence=false`, divergence sequence is shared length.
- Divergence at first marker -> `has_common_prefix=false`, `divergence_seq=0`.
- One empty stream -> divergence at sequence 0.
- Length mismatch with shared prefix -> divergence at shorter length.

## Test Matrix

Covered in:
- unit tests in `crates/franken-node/src/control_plane/marker_stream.rs`
- integration tests in `tests/integration/marker_divergence_detection.rs`

Normative scenarios:
- exact boundary at sequence 1000
- divergence at sequence 0
- no divergence
- asymmetric length divergence
- logarithmic comparison bound checks
