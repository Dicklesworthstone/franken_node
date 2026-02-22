# bd-3vm Verification Summary

## Result
PASS

## Delivered
- `crates/franken-node/src/runtime/authority_audit.rs`
- `crates/franken-node/src/runtime/mod.rs` (wiring)
- `config/security_critical_modules.toml`
- `docs/specs/section_10_11/bd-3vm_contract.md`
- `scripts/check_ambient_authority.py`
- `tests/test_check_ambient_authority.py`
- `artifacts/section_10_11/bd-3vm/verification_evidence.json`
- `artifacts/section_10_11/bd-3vm/verification_summary.md`

## Gate Results
- `python3 scripts/check_ambient_authority.py --json` -> PASS
- `python3 scripts/check_ambient_authority.py --self-test` -> PASS
- `python3 -m pytest tests/test_check_ambient_authority.py -v` -> PASS

## Highlights
- Ambient-authority audit gate enforces Architecture Invariant #10.
- `AuthorityAuditGuard` with strict and advisory enforcement modes.
- `CapabilityContext` provides explicit capability threading.
- 10-capability taxonomy covers all system trust boundaries.
- 8 security-critical modules registered in default inventory.
- BTreeMap used throughout for deterministic audit output (INV-AA-DETERMINISTIC).
- Event codes FN-AA-001 through FN-AA-008 defined.
- 5 error codes and 5 invariants defined and tested.
- Schema version aa-v1.0.
