# bd-18ud: Verification Summary

## Durability Modes (Local and Quorum)

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (94/94 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/connector/durability.rs`
- **Spec:** `docs/specs/section_10_14/bd-18ud_contract.md`
- **Verification:** `scripts/check_durability_modes.py`
- **Test Suite:** `tests/test_check_durability_modes.py` (26 tests)
- **Claim Matrix:** `artifacts/10.14/durability_mode_claim_matrix.json`

## Architecture

| Type | Purpose |
|------|---------|
| `DurabilityMode` | Local or Quorum(min_acks) |
| `WriteOutcome` | LocalFsyncConfirmed or QuorumAcked/QuorumFailed |
| `DurabilityClaim` | Deterministic claim from (mode, outcome) pair |
| `ModeSwitchPolicy` | Controls authorized mode transitions |
| `DurabilityController` | Per-class controller with write + switch operations |
| `ReplicaResponse` | Simulated replica ack/nack |

## Key Properties

- **End-to-end enforcement**: Local requires fsync, Quorum requires M acks
- **Fail-closed quorum**: Writes rejected when acked < min_acks
- **Policy-gated switching**: Downgrades require operator auth, upgrades allowed by default
- **Deterministic claims**: Same (mode, outcome) always produces same claim string
- **Auditable events**: All operations logged with stable event codes

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 50 | All pass |
| Python verification checks | 94 | All pass |
| Python unit tests | 26 | All pass |

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
