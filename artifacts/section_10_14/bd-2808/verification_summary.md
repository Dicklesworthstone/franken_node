# bd-2808: Verification Summary

## Deterministic Repro Bundle Export

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (97/97 checks)
**Agent:** CopperCompass (codex, gpt-5)
**Date:** 2026-03-29

## Implementation

- **Module:** `crates/franken-node/src/tools/repro_bundle_export.rs`
- **Spec:** `docs/specs/section_10_14/bd-2808_contract.md`
- **Verification:** `scripts/check_repro_bundle_export.py`
- **Schema Artifact:** `artifacts/10.14/repro_bundle_schema_v1.json`
- **Test Suite:** `tests/test_check_repro_bundle_export.py` (26 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `ReproBundle` | Self-contained bundle: seed, config, trace, evidence refs, and full failure context including failure timestamp |
| `TraceEvent` | Event in control-plane trace (seq, type, timestamp, payload) |
| `TraceEventType` | 6 variants: EpochTransition, BarrierEvent, PolicyEvaluation, MarkerIntegrityCheck, ConfigChange, ExternalSignal |
| `EvidenceRef` | Reference to evidence with portable relative path |
| `FailureContext` | Failure condition: type, error, trigger, timestamp |
| `FailureType` | 4 variants: EpochTransitionTimeout, BarrierTimeout, PolicyViolation, MarkerIntegrityBreak |
| `ConfigSnapshot` | Key-value config snapshot with portability checks |
| `ReplayOutcome` | Match (same failure) or Divergence (replay differed) |
| `SchemaError` | Validation errors: MissingField, InvalidVersion, NonPortablePath, EmptyEventTrace |
| `ReproBundleExporter` | Manages auto/manual export with configurable triggers |

## Event Codes

| Code | Trigger |
|------|---------|
| REPRO_BUNDLE_EXPORTED | Bundle exported |
| REPRO_BUNDLE_REPLAY_START | Replay started |
| REPRO_BUNDLE_REPLAY_COMPLETE | Replay matched original |
| REPRO_BUNDLE_REPLAY_DIVERGENCE | Replay diverged |

## Invariants

| ID | Status |
|----|--------|
| INV-REPRO-DETERMINISTIC | Verified (100-run determinism test) |
| INV-REPRO-COMPLETE | Verified (portable JSON now preserves `failure_timestamp_ms` alongside export time) |
| INV-REPRO-VERSIONED | Verified (schema_version=1, validated on replay) |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 46 | All pass |
| Python verification checks | 97 | All pass |
| Python unit tests | 26 | All pass |

## Fresh-Eyes Fix

- `ReproBundle::to_json()` now includes `failure_timestamp_ms`, so the portable JSON artifact preserves the full `FailureContext` already used in bundle derivation.
- The checker and schema artifact now require `failure_timestamp_ms`, which prevents future regressions where exported JSON silently omits canonical replay state.

## Downstream Unblocked

- bd-3i6c: Conformance suite for ledger determinism
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
