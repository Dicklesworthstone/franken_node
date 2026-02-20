# bd-2808: Verification Summary

## Deterministic Repro Bundle Export

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (93/93 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/tools/repro_bundle_export.rs`
- **Spec:** `docs/specs/section_10_14/bd-2808_contract.md`
- **Verification:** `scripts/check_repro_bundle_export.py`
- **Test Suite:** `tests/test_check_repro_bundle_export.py` (25 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `ReproBundle` | Self-contained bundle: seed, config, trace, evidence refs, failure context |
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
| INV-REPRO-COMPLETE | Verified (self-contained bundles, no external state) |
| INV-REPRO-VERSIONED | Verified (schema_version=1, validated on replay) |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 39 | All pass |
| Python verification checks | 93 | All pass |
| Python unit tests | 25 | All pass |

## Downstream Unblocked

- bd-3i6c: Conformance suite for ledger determinism
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
