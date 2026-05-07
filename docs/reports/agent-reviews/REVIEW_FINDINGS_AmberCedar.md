# REVIEW_FINDINGS_AmberCedar

## Pass 1 - Control-plane marker stream

- Reviewed `crates/franken-node/src/control_plane/marker_stream.rs`.
- Found unchecked marker-stream length and sequence-offset conversions:
  `field.len() as u64`, `trace_id.len() as u64`, `local.len() as u64`,
  `remote.len() as u64`, and `(sequence - base) as usize`.
- Fixed with `len_to_u64` and checked sequence-offset conversion before indexing.
- Added inline negative-path tests for hash domain separation, length-prefix ambiguity,
  evicted-window lookup rejection, huge future sequence rejection, and range clamping.

## Coordination Notes

- MCP Agent Mail health reported a corrupt/degraded schema, so mail reservations and
  swarm broadcasts were skipped.
- No unclaimed ready bead was available; `bd-18nr6` remained assigned to LavenderValley.
