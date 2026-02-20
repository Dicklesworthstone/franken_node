# bd-126h: Verification Summary

## Append-Only Marker Stream for High-Impact Control Events

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (45/45 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/control_plane/marker_stream.rs`
- **Spec:** `docs/specs/section_10_14/bd-126h_contract.md`
- **Conformance:** `tests/conformance/marker_stream_invariants.rs`
- **Verification:** `scripts/check_marker_stream.py`

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-MKS-APPEND-ONLY | PASS | No mutation/deletion operations exist; only `append()` |
| INV-MKS-DENSE-SEQUENCE | PASS | Sequence = Vec index, enforced on every append |
| INV-MKS-HASH-CHAIN | PASS | Each marker's prev_hash = predecessor's marker_hash |
| INV-MKS-MONOTONIC-TIME | PASS | timestamp >= prev timestamp, enforced in `append()` |
| INV-MKS-TORN-TAIL | PASS | `recover_torn_tail()` deterministically removes corrupt last marker |
| INV-MKS-INVARIANT-ALERT | PASS | All violations produce stable MKS_* error codes |

## Types Implemented

- `MarkerEventType` — 6 event categories (trust_decision, revocation_event, quarantine_action, policy_change, epoch_transition, incident_escalation)
- `Marker` — Immutable stream entry with sequence, event_type, payload_hash, prev_hash, marker_hash, timestamp, trace_id
- `MarkerStream` — Append-only container with invariant enforcement
- `MarkerStreamError` — 7 stable error codes (MKS_SEQUENCE_GAP, MKS_HASH_CHAIN_BREAK, MKS_TIME_REGRESSION, MKS_EMPTY_STREAM, MKS_INTEGRITY_FAILURE, MKS_TORN_TAIL, MKS_INVALID_PAYLOAD)

## Operations

| Operation | Purpose |
|-----------|---------|
| `append()` | Add marker with invariant enforcement |
| `head()` | Get most recent marker |
| `get(seq)` | O(1) lookup by sequence number |
| `len()` / `is_empty()` | Stream size queries |
| `range(start, end)` | Slice of markers by sequence range |
| `verify_integrity()` | Full chain walk validating all invariants |
| `recover_torn_tail()` | Deterministic torn-tail recovery |

## Test Results

- **27 unit tests** — all passing
- **45 verification checks** — all passing
- **Coverage:** happy path, error paths, edge cases, large stream (1000 markers), all event types, all error codes, deterministic hashing, torn-tail recovery

## Downstream Unblocks

This bead unblocks:
- bd-nwhn: Root pointer atomic publication protocol
- bd-1dar: MMR checkpoints and inclusion/prefix proof APIs
- bd-xwk5: Fork/divergence detection via marker-id prefix comparison
- bd-129f: O(1) marker lookup and O(log N) timestamp-to-sequence search
- bd-2ms: Rollback/fork detection in control-plane state propagation
