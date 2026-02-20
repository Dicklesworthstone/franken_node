# bd-vll: Deterministic Incident Replay Bundle Generation

## Bead: bd-vll | Section: 10.5

## Purpose

Define a deterministic, self-contained replay bundle format for incident
forensics. Bundles capture ordered incident timeline events, policy/state
snapshots, integrity metadata, and chunk manifests for large incidents.

## Invariants

| ID | Statement |
|----|-----------|
| INV-RB-DETERMINISTIC | Given identical incident input events, generated bundle bytes are identical. |
| INV-RB-INTEGRITY | `integrity_hash` is SHA-256 over canonical serialization of all bundle fields except `integrity_hash`. |
| INV-RB-SEQUENCE-MONOTONIC | `TimelineEvent.sequence_number` is strictly monotonic and starts at `1`. |
| INV-RB-TIMESTAMP-RFC3339 | All timeline timestamps are RFC-3339 normalized at microsecond precision. |
| INV-RB-SELF-CONTAINED | Bundle contains all data required for replay: timeline, state snapshot, policy version, and sequence hash. |
| INV-RB-CHUNKING | Bundles whose canonical timeline exceeds 10 MiB produce numbered chunks with shared `bundle_id`. |
| INV-RB-REPLAY-EQUIVALENCE | Replay recomputes sequence hash and must match manifest `decision_sequence_hash` for success. |

## Types

### `EventType`
- Enum:
  - `state_change`
  - `policy_eval`
  - `external_signal`
  - `operator_action`

### `RawEvent`
- `timestamp: String` (RFC-3339 input)
- `event_type: EventType`
- `payload: serde_json::Value`
- `causal_parent: Option<u64>`
- `state_snapshot: Option<serde_json::Value>`
- `policy_version: Option<String>`

### `TimelineEvent`
- `sequence_number: u64`
- `timestamp: String` (RFC-3339 micros, normalized UTC)
- `event_type: EventType`
- `payload: serde_json::Value` (canonicalized, no floating-point numbers)
- `causal_parent: Option<u64>`

### `BundleManifest`
- `event_count: usize`
- `first_timestamp: Option<String>`
- `last_timestamp: Option<String>`
- `time_span_micros: u64`
- `compressed_size_bytes: u64`
- `chunk_count: u32`
- `decision_sequence_hash: String`

### `BundleChunk`
- `bundle_id: Uuid` (shared with parent bundle)
- `chunk_index: u32` (0-based)
- `total_chunks: u32`
- `event_count: usize`
- `first_sequence_number: u64`
- `last_sequence_number: u64`
- `compressed_size_bytes: u64`
- `chunk_hash: String`
- `events: Vec<TimelineEvent>`

### `ReplayBundle`
- `bundle_id: Uuid` (v7 layout, deterministic seed)
- `incident_id: String`
- `created_at: String` (RFC-3339)
- `timeline: Vec<TimelineEvent>`
- `initial_state_snapshot: serde_json::Value`
- `policy_version: String`
- `manifest: BundleManifest`
- `chunks: Vec<BundleChunk>`
- `integrity_hash: String`

### `ReplayOutcome`
- `incident_id: String`
- `expected_sequence_hash: String`
- `replayed_sequence_hash: String`
- `matched: bool`
- `event_count: usize`

## API Surface

- `generate_replay_bundle(incident_id, event_log) -> Result<ReplayBundle, ReplayBundleError>`
- `validate_bundle_integrity(bundle) -> Result<bool, ReplayBundleError>`
- `replay_bundle(bundle) -> Result<ReplayOutcome, ReplayBundleError>`
- `write_bundle_to_path(bundle, path) -> Result<(), ReplayBundleError>`
- `read_bundle_from_path(path) -> Result<ReplayBundle, ReplayBundleError>`
- `to_canonical_json(bundle) -> Result<String, ReplayBundleError>`
- `synthetic_incident_events(incident_id) -> Vec<RawEvent>`

## Error Classes

| Class | Trigger |
|-------|---------|
| `EmptyIncidentId` | `incident_id` is empty/whitespace |
| `TimestampParse` | Any event timestamp cannot be parsed as RFC-3339 |
| `NonDeterministicFloat` | Payload/state snapshot includes floating-point number |
| `IntegrityMismatch` | Replay attempted on bundle with invalid integrity hash |
| `Json` / `Io` | Serialization or filesystem persistence failures |

## CLI Surface

- `franken-node incident bundle --id <incident_id> [--verify]`
  - Generates deterministic replay bundle and writes to:
    - `artifacts/section_10_5/bd-vll/<incident_id>_bundle.json`
- `franken-node incident replay --bundle <bundle_path>`
  - Replays bundle and verifies sequence equivalence hash

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/tools/replay_bundle.rs` |
| Module export | `crates/franken-node/src/tools/mod.rs` |
| CLI integration | `crates/franken-node/src/main.rs` |
| Verification script | `scripts/check_replay_bundle.py` |
| Verification unit tests | `tests/test_check_replay_bundle.py` |
| Verification evidence | `artifacts/section_10_5/bd-vll/verification_evidence.json` |
| Verification summary | `artifacts/section_10_5/bd-vll/verification_summary.md` |
