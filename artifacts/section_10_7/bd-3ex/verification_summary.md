# bd-3ex Verification Summary

## Scope Delivered
- Extended verifier CLI surface with contract-facing subcommands:
  - `verify module`
  - `verify migration`
  - `verify compatibility`
  - `verify corpus`
- Added machine-readable verifier contract:
  - `spec/verifier_cli_contract.toml`
- Added snapshot fixtures for contract outputs:
  - `tests/contract/snapshots/verify_module_default.json`
  - `tests/contract/snapshots/verify_migration_default.json`
  - `tests/contract/snapshots/verify_compatibility_default.json`
  - `tests/contract/snapshots/verify_corpus_default.json`
  - `tests/contract/snapshots/verify_module_invalid_compat.json`
- Added contract checker + tests:
  - `scripts/check_verifier_contract.py`
  - `tests/test_check_verifier_contract.py`
- Follow-up `bd-fz53c` replaced simulated checker output with explicit subprocess runner evidence:
  - runner resolution via `--binary`, `FRANKEN_NODE_VERIFY_BIN`, or `target/debug/franken-node`
  - fail-closed behavior when no executable runner is available
  - JSON `exit_code` equality with the actual subprocess return code

## Contract Gate Result
- `artifacts/section_10_7/bd-3ex/check_report.json` verdict: `PASS`
- Checks passed: `47/47`
- Coverage includes:
  - exit code taxonomy (`0/1/2/3`)
  - required command IDs
  - CLI/main wiring markers
  - verifier runner availability
  - per-scenario subprocess execution
  - JSON/process exit-code equality
  - scenario/snapshot integrity
  - additive-field snapshot policy and breaking-change enforcement

## Validation Runs
- `python3 -m py_compile scripts/check_verifier_contract.py tests/test_check_verifier_contract.py` => `PASS`
- `python3 scripts/check_verifier_contract.py --self-test` => `PASS`
- `python3 -m unittest tests.test_check_verifier_contract` => `PASS` (`11 tests`)
- `python3 scripts/check_verifier_contract.py --json --binary <subprocess fixture harness>` => `PASS` (`47/47`)
- `python3 scripts/check_verifier_contract.py --json` with no local binary => `FAIL` by design (`verifier_runner_available`)

## Required Cargo Gates via `rch`
- `rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo build -p frankenengine-node --bin franken-node` => exit `0`
- `rch exec -- cargo fmt --check` => exit `1`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_bd3ex_check_<ts> cargo check --all-targets` => exit `101`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_bd3ex_clippy_<ts> cargo clippy --all-targets -- -D warnings` => exit `101`

Notable blocker from both `check` and `clippy` logs:
- missing remote path dependency manifest:
  - `/data/tmp/rch_bolddesert/franken_node/franken_engine/crates/franken-engine/Cargo.toml`

Current local real-binary runner blocker:
- the focused `rch` build succeeded, but artifact retrieval could not materialize `target/debug/franken-node` because local `target/` is immutable (`lsattr target` shows `i`); the checker therefore proved subprocess behavior through the explicit fixture harness and fails closed without a runner.

## Artifacts
- `artifacts/section_10_7/bd-3ex/check_report.json`
- `artifacts/section_10_7/bd-3ex/check_self_test.txt`
- `artifacts/section_10_7/bd-3ex/unit_tests.txt`
- `artifacts/section_10_7/bd-3ex/verification_evidence.json`
- `artifacts/section_10_7/bd-3ex/rch_cargo_fmt_check.log`
- `artifacts/section_10_7/bd-3ex/rch_cargo_check.log`
- `artifacts/section_10_7/bd-3ex/rch_cargo_clippy.log`
