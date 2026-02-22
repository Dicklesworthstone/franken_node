# bd-274s Support API-Contract Notes (PurpleHarbor)

## Scope
Non-overlapping support slice on checker surfaces only:
- `scripts/check_bd_274s_bayesian_quarantine.py`
- `tests/test_check_bd_274s_bayesian_quarantine.py`

## What changed
- Added explicit API-contract checks between:
  - `crates/franken-node/src/security/adversary_graph.rs`
  - `crates/franken-node/src/security/quarantine_controller.rs`
- New checker signals:
  - `adversary_graph_exports_for_controller`
  - `graph_method_contract_compat`
  - `graph_new_constructor_compat`
- Added metrics:
  - `graph_export_missing_count`
  - `graph_method_missing_count`
- Added helper-level unit tests for method-call extraction and constructor-signature parsing.
- Fixed a parser bug where constructor-signature detection could accidentally match unrelated `pub fn new(...)` definitions.

## Validation
- `python3 -m py_compile scripts/check_bd_274s_bayesian_quarantine.py tests/test_check_bd_274s_bayesian_quarantine.py`
- `pytest -q tests/test_check_bd_274s_bayesian_quarantine.py`
  - Result: `16 passed`
- `python3 scripts/check_bd_274s_bayesian_quarantine.py --json`
  - Result: `PASS (20/20)`

## Remote compile telemetry (rch)
- Command run: `rch exec -- cargo test -p frankenengine-node --test bayesian_risk_quarantine -- --nocapture`
- Exit code: `101`
- Observed errors included cross-bead in-flight compile breakages at run time (e.g. unresolved/mismatched symbols across newly introduced modules).
- Posted full condensed error signal to `bd-274s` thread for core implementers.
