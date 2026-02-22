# bd-31l3 verification summary

## Scope
Exploratory deep audit + targeted bugfixes in:
- `crates/franken-node/src/security/interface_hash.rs`
- `crates/franken-node/src/runtime/optimization_governor.rs`

## Fixes landed
1. `interface_hash` verification now:
   - accepts uppercase hexadecimal hash strings (case-insensitive compare)
   - rejects mismatched `data_len` metadata vs provided payload length
   - includes regression tests for both behaviors
2. `optimization_governor` submission path now:
   - rejects proposals for non-configured knobs
   - rejects stale `old_value` baselines
   - avoids approving proposals when knob state is missing
   - includes regression tests for both invalid-proposal paths

## Verification (via rch)
- `cargo fmt --check` -> exit `1` (pre-existing unrelated formatting drift)
- `cargo check --all-targets` -> exit `0`
- `cargo test -p frankenengine-node interface_hash::tests:: -- --nocapture` -> exit `0`
  - `test result: ok. 23 passed; 0 failed`
- Direct targeted run:
  - `cargo test -p frankenengine-node --bin frankenengine-node runtime::optimization_governor::tests::test_submit_rejects_stale_old_value -- --exact --nocapture`
  - `running 1 test` -> `ok`

## Notes
- The workspace currently emits many pre-existing warnings unrelated to this bead.
- No additional functional changes were made outside the two targeted files.
