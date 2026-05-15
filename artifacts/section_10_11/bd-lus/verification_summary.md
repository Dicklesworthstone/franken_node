# bd-lus Verification Summary

## Result
PASS (bead scope) with pre-existing workspace baseline cargo failures.

## Delivered
- `crates/franken-node/src/runtime/lane_router.rs`
- `crates/franken-node/src/runtime/bulkhead.rs`
- `crates/franken-node/src/config.rs` (runtime lane/bulkhead config integration)
- `docs/specs/section_10_11/bd-lus_contract.md`
- `scripts/check_scheduler_lanes.py`
- `tests/test_check_scheduler_lanes.py`
- `artifacts/section_10_11/bd-lus/check_report_scheduler_lanes.json`
- `artifacts/section_10_11/bd-lus/check_scheduler_lanes_self_test.exit`
- `artifacts/section_10_11/bd-lus/pytest_check_scheduler_lanes.exit`
- `artifacts/section_10_11/bd-lus/rch_cargo_check_all_targets.exit`
- `artifacts/section_10_11/bd-lus/rch_cargo_clippy_all_targets.exit`
- `artifacts/section_10_11/bd-lus/rch_cargo_fmt_check.exit`
- `artifacts/section_10_11/bd-lus/verification_evidence.json`

## Gate Results
- `python3 scripts/check_scheduler_lanes.py --json` -> PASS (`18/18` checks).
- `python3 scripts/check_scheduler_lanes.py --self-test` -> PASS.
- `pytest -q tests/test_check_scheduler_lanes.py` -> PASS (`10 passed`).
- `rch exec -- cargo check --all-targets` -> `101` (baseline workspace failures).
- `rch exec -- cargo clippy --all-targets -- -D warnings` -> `101` (baseline workspace failures).
- `rch exec -- cargo fmt --check` -> `1` (baseline workspace formatting drift).

## Highlights
- Product lane taxonomy implemented: `cancel`, `timed`, `realtime` (`ready` alias), `background`.
- Per-lane concurrency + overflow policy support (`reject`, `enqueue-with-timeout`, `shed-oldest`).
- Global bulkhead integrated with fail-fast `BULKHEAD_OVERLOAD` + retry hint.
- Runtime reload path for lane/bulkhead config (`LANE_CONFIG_RELOAD`).
- Deterministic lane/global metrics snapshot includes `p99_queue_wait_ms` and `bulkhead_rejections`.
- Gate validation now ignores Rust comments and requires real public constants, items, functions, enum variants, and the registered integration test shape before accepting marker coverage.
