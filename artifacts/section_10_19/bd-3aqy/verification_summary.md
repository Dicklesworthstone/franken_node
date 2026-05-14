# bd-3aqy — Canonical Federated Signal Schema

## Verdict

PASS

## Concrete Implementation

The canonical ATC federated signal schema is implemented in
`crates/franken-node/src/federation/atc_signal_extractor.rs` and exported by
`crates/franken-node/src/federation/mod.rs:8`.

Key schema and extraction symbols are present at concrete source locations:

| Symbol | Evidence |
| --- | --- |
| `SignalKind` | `crates/franken-node/src/federation/atc_signal_extractor.rs:121` |
| `ExtractionPolicy` | `crates/franken-node/src/federation/atc_signal_extractor.rs:161` |
| `AtcLocalSignal` | `crates/franken-node/src/federation/atc_signal_extractor.rs:195` |
| `ExtractionError` | `crates/franken-node/src/federation/atc_signal_extractor.rs:221` |
| `extract_signal` | `crates/franken-node/src/federation/atc_signal_extractor.rs:273` |
| `ExtractionAuditLog` | `crates/franken-node/src/federation/atc_signal_extractor.rs:391` |
| `compute_signal_id` | `crates/franken-node/src/federation/atc_signal_extractor.rs:478` |
| `compute_payload_hash` | `crates/franken-node/src/federation/atc_signal_extractor.rs:489` |

## Invariants Covered

- Four stable signal discriminants cover anomaly, trust-card, revocation, and
  quarantine intelligence.
- Canonical IDs and payload hashes are domain-separated and length-prefixed.
- Redacted payload fields are stored in `BTreeMap` order for deterministic
  serialization and replay.
- Extraction fails closed for unknown kinds, policy-filtered kinds, malformed
  payloads, oversized fields, and max-payload violations.
- The public integration suite is wired through
  `crates/franken-node/Cargo.toml:962` as `atc_signal_extractor_integration`.
- The module and integration harness provide 20 tests total: 13 inline unit
  tests and 7 integration tests covering determinism, redaction, replay,
  fail-closed policy, fixture replay, and serde round trips.

## Verification

- `python3 scripts/check_section_10_19_gate.py --json` reports section verdict
  PASS and keeps `bd-3aqy` in the signal-schema coverage group.
- Source evidence was inspected directly with `rg` over
  `crates/franken-node/src/federation/atc_signal_extractor.rs` and
  `crates/franken-node/tests/atc_signal_extractor_integration.rs`; the artifact
  now cites concrete implementation and test surfaces instead of a generic
  `src/atc` path.
