# bd-38l: Divergence Ledger — Verification Summary

## Verdict: PASS

## What was delivered

1. **Divergence ledger** `docs/DIVERGENCE_LEDGER.json`:
   - 2 initial entries (process.binding, vm.runInNewContext)
   - Each entry: id, api_family, api_name, band, node/franken behavior, signed rationale, risk tier, status, timestamp, reviewer

2. **JSON schema** `schemas/divergence_ledger.schema.json`:
   - Validates entry structure with enum constraints on band, risk_tier, status
   - ID pattern: `DIV-NNN`
   - Non-empty rationale required

3. **Spec document** `docs/specs/section_10_2/bd-38l_contract.md`

4. **Verification script** `scripts/check_divergence_ledger.py` with 7 checks:
   - DIV-EXISTS, DIV-SCHEMA, DIV-TRACEABILITY, DIV-STRUCTURE, DIV-FIELDS, DIV-RATIONALE, DIV-UNIQUE

5. **Unit tests** `tests/test_check_divergence_ledger.py`: 11 tests

6. **Traceability closure** for `bd-38l.1`:
   - Canonical source module: `scripts/check_divergence_ledger.py`
   - Git xref is recorded in `verification_evidence.json` for the ledger, schema, verifier, tests, and evidence artifacts.

## Unit tests

- 11/11 passed, 0 failed
