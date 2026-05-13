# bd-1qp — Compatibility envelope and divergence ledger

## Verdict: PASS

## Implementation
- Actual compatibility policy modules:
  - `crates/franken-node/src/policy/compat_gates.rs`
  - `crates/franken-node/src/policy/compatibility_gate.rs`
  - `crates/franken-node/src/api/compat_gate.rs`
- Divergence ledger and verifier:
  - `docs/DIVERGENCE_LEDGER.json`
  - `schemas/divergence_ledger.schema.json`
  - `scripts/check_divergence_ledger.py`
  - `tests/test_check_divergence_ledger.py`
- The stale nonexistent initiatives-module citation has been removed.
- The divergence ledger now contains 6 policy-backed entries and the checker enforces a minimum corpus size with `DIV-COUNT-FLOOR`.

## Verification
- `python3 scripts/check_divergence_ledger.py --json` passes **8/8** checks.
- `python3 -m pytest tests/test_check_divergence_ledger.py` passes **12/12** tests.
