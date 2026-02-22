# bd-cvt Verification Summary

## Result
PASS

## Delivered
- `crates/franken-node/src/connector/capability_guard.rs`
- `crates/franken-node/src/connector/mod.rs` (wiring)
- `capabilities/trust_fabric.toml`
- `capabilities/migration_engine.toml`
- `capabilities/epoch_guard.toml`
- `capabilities/artifact_signing.toml`
- `capabilities/network_guard.toml`
- `docs/specs/section_10_11/bd-cvt_contract.md`
- `scripts/check_capability_profiles.py`
- `tests/test_check_capability_profiles.py`
- `artifacts/section_10_11/bd-cvt/verification_evidence.json`
- `artifacts/section_10_11/bd-cvt/verification_summary.md`

## Gate Results
- `python3 scripts/check_capability_profiles.py --json` -> PASS
- `python3 scripts/check_capability_profiles.py --self-test` -> PASS
- `python3 -m pytest tests/test_check_capability_profiles.py -v` -> PASS

## Highlights
- Capability profiles enforce least-privilege narrowing (Section 9G.1).
- 12-capability taxonomy with hierarchical `cap:` naming scheme.
- `CapabilityGuard` enforces deny-default: undeclared capabilities are rejected.
- `CapabilityAuditEntry` records every grant/deny decision.
- `ProfileChange` detects capability changes for security review flagging.
- 5 product subsystem profiles in `capabilities/` directory.
- BTreeMap used throughout for deterministic output (INV-CAP-DETERMINISTIC).
- Event codes CAP-001 through CAP-008 defined.
- 5 error codes and 5 invariants defined and tested.
- Schema version cap-v1.0.
