# bd-126h: Append-Only Marker Stream for High-Impact Control Events

## Purpose

Implement an append-only marker stream that records high-impact control events with
dense sequence invariant checks. Every marker is hash-chained to its predecessor,
forming a tamper-evident log. Torn-tail recovery is deterministic. Invariant breaks
trigger hard alerts via structured error codes.

## Invariants

- **INV-MKS-APPEND-ONLY**: Markers can only be appended; no mutation or deletion of existing markers.
- **INV-MKS-DENSE-SEQUENCE**: Sequence numbers are dense (no gaps); sequence N+1 follows N.
- **INV-MKS-HASH-CHAIN**: Each marker's `prev_hash` matches the hash of the preceding marker.
- **INV-MKS-TORN-TAIL**: If the last marker is incomplete/corrupt, it is deterministically discarded and the stream truncated to the last valid marker.
- **INV-MKS-MONOTONIC-TIME**: Marker timestamps are monotonically non-decreasing.
- **INV-MKS-INVARIANT-ALERT**: Any invariant violation produces a hard alert with a stable error code.

## Types

### MarkerEventType

Enum of high-impact control event categories:
- `TrustDecision` — trust card evaluation or override
- `RevocationEvent` — artifact or publisher revocation
- `QuarantineAction` — quarantine enact/lift
- `PolicyChange` — runtime policy modification
- `EpochTransition` — control epoch boundary crossing
- `IncidentEscalation` — severity escalation of an incident

### Marker

A single entry in the append-only stream:
- `sequence`: u64 (dense, starting at 0)
- `event_type`: MarkerEventType
- `payload_hash`: String (SHA-256 hex of the event payload)
- `prev_hash`: String (SHA-256 hex of the preceding marker, or genesis sentinel for seq 0)
- `marker_hash`: String (SHA-256 hex of this marker's canonical serialization)
- `timestamp`: u64 (unix epoch seconds, monotonically non-decreasing)
- `trace_id`: String (distributed tracing correlation ID)

### MarkerStream

The stream container:
- Maintains the ordered sequence of markers
- Enforces all INV-MKS-* invariants on every append
- Provides head/tail queries, range reads, and integrity verification

## Operations

### `append(event_type, payload_hash, timestamp, trace_id) -> Result<Marker, MarkerStreamError>`

Appends a new marker. Computes sequence, prev_hash, and marker_hash. Validates
dense sequence and monotonic time invariants.

### `head() -> Option<&Marker>`

Returns the most recent marker.

### `get(sequence) -> Option<&Marker>`

Returns marker at given sequence number. O(1) lookup.

### `len() -> usize`

Returns the number of markers in the stream.

### `verify_integrity() -> Result<(), MarkerStreamError>`

Walks the entire chain and validates dense sequence + hash chain invariants.

### `recover_torn_tail() -> Option<Marker>`

If the last marker is corrupt (hash mismatch), removes it and returns the
discarded marker. Returns None if stream is healthy.

## Error Codes

- `MKS_SEQUENCE_GAP` — dense sequence invariant violated
- `MKS_HASH_CHAIN_BREAK` — prev_hash does not match preceding marker hash
- `MKS_TIME_REGRESSION` — timestamp older than predecessor
- `MKS_EMPTY_STREAM` — operation requires non-empty stream
- `MKS_INTEGRITY_FAILURE` — full-chain verification found corruption
- `MKS_TORN_TAIL` — last marker corrupt, needs recovery
- `MKS_INVALID_PAYLOAD` — payload hash is empty or malformed

## Artifacts

- Implementation: `crates/franken-node/src/control_plane/marker_stream.rs`
- Conformance tests: `tests/conformance/marker_stream_invariants.rs`
- Verification script: `scripts/check_marker_stream.py`
- Evidence: `artifacts/section_10_14/bd-126h/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-126h/verification_summary.md`
