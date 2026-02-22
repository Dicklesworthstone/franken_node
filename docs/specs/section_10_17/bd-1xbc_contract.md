# bd-1xbc: Deterministic Time-Travel Runtime Capture/Replay

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-1xbc |
| Section | 10.17 |
| Title | Add deterministic time-travel runtime capture/replay for extension-host workflows |
| Type | task |

## Purpose

Extension-host workflows in the franken_node radical expansion track must be
fully reproducible for incident analysis, regression testing, and audit.
This bead implements a deterministic time-travel runtime that captures every
control decision made during an extension-host workflow execution and replays
them byte-for-byte under the same seed and input.

The time-travel runtime provides:
- Frame-by-frame capture of all extension-host control decisions.
- A deterministic clock that eliminates wallclock non-determinism from replays.
- Stepwise state navigation (forward and backward) during incident replay.
- Divergence detection and explanation when replayed execution deviates from
  the captured trace.
- Workflow snapshot serialization for offline analysis and long-term archival.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-1xbc_contract.md` |
| Rust module | `crates/franken-node/src/runtime/time_travel.rs` |
| Check script | `scripts/check_time_travel_replay.py` |
| Test suite | `tests/test_check_time_travel_replay.py` |
| Evidence | `artifacts/section_10_17/bd-1xbc/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-1xbc/verification_summary.md` |

## Invariants

- **INV-TTR-DETERMINISTIC**: Given identical seed and input, replay produces
  byte-for-byte equivalent control decisions. No non-determinism leaks into
  the replay path.
- **INV-TTR-FRAME-COMPLETE**: Every captured frame contains the full state
  required to reconstruct the control decision at that point. No implicit or
  ambient state is omitted.
- **INV-TTR-CLOCK-MONOTONIC**: The deterministic clock advances monotonically
  within a session. No time reversal occurs during capture or replay.
- **INV-TTR-DIVERGENCE-DETECTED**: When replayed execution diverges from the
  captured trace, the runtime halts and produces a structured divergence
  explanation before any further frames are emitted.
- **INV-TTR-SNAPSHOT-SCHEMA**: Workflow snapshots carry a schema version.
  Format changes are backward-detectable and forward-compatible within the
  same major version.
- **INV-TTR-STEP-NAVIGATION**: During replay, the session supports stepping
  forward and backward by individual frames without corrupting state.

## Event Codes

| Code | Description |
|------|-------------|
| TTR_001 | Capture session started |
| TTR_002 | Frame captured |
| TTR_003 | Replay session started |
| TTR_004 | Replay step advanced |
| TTR_005 | Replay step reversed |
| TTR_006 | Divergence detected |
| TTR_007 | Snapshot serialized |
| TTR_008 | Snapshot deserialized |
| TTR_009 | Capture session completed |
| TTR_010 | Replay session completed |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_TTR_EMPTY_TRACE | Replay attempted on a trace with zero frames |
| ERR_TTR_DIVERGENCE | Replayed decision does not match captured decision |
| ERR_TTR_CLOCK_REGRESSION | Deterministic clock moved backwards |
| ERR_TTR_STEP_OUT_OF_BOUNDS | Step navigation moved past trace boundaries |
| ERR_TTR_SNAPSHOT_CORRUPT | Snapshot deserialization failed integrity check |
| ERR_TTR_SEED_MISMATCH | Replay seed does not match capture seed |

## Acceptance Criteria

1. Captured executions replay byte-for-byte equivalent control decisions under
   same seed/input.
2. Incident replay includes stepwise state navigation (forward + backward)
   and divergence explanation.
3. Module contains >= 20 inline `#[test]` functions covering all invariants,
   error codes, and edge cases.
4. All event codes (TTR_001..TTR_010) and error codes (ERR_TTR_*) are present
   as constants in the Rust source.
5. BTreeMap is used for all map types to guarantee deterministic ordering.
6. Schema version constant is present and prefixed `ttr-v`.

## Dependencies

- bd-274s: Bayesian adversary graph (blocker, in progress)
