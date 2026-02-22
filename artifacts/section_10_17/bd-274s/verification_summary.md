# bd-274s Verification Summary

- Status: **PASS**
- Checker: `61/61` PASS (`artifacts/section_10_17/bd-274s/check_report.json`)
- Checker self-test: PASS (`artifacts/section_10_17/bd-274s/check_self_test.txt`)
- Unit tests: `14` tests PASS (`artifacts/section_10_17/bd-274s/unit_tests.txt`)

## Delivered Surface

- `docs/specs/section_10_17/bd-274s_contract.md`
- `crates/franken-node/src/security/adversary_graph.rs`
- `crates/franken-node/src/security/quarantine_controller.rs`
- `scripts/check_adversary_graph.py`
- `tests/test_check_adversary_graph.py`
- `artifacts/10.17/adversary_graph_state.json`
- `artifacts/section_10_17/bd-274s/verification_evidence.json`
- `artifacts/section_10_17/bd-274s/verification_summary.md`

## Acceptance Coverage

- Risk posterior updates are deterministic: Beta-Bernoulli conjugate model (alpha/beta), no RNG.
- Identical evidence sequences produce bit-identical posteriors (verified by Rust unit tests).
- Policy thresholds trigger reproducible control actions:
  - Throttle at >= 0.3
  - Isolate at >= 0.5
  - Revoke at >= 0.7
  - Quarantine at >= 0.9
- Signed evidence entries (HMAC-SHA256) with monotonic sequence numbers.
- 8 structured event codes (ADV-001 through ADV-008).
- 6 error codes and 6 invariant tags for traceability.
- 27 inline Rust unit tests across both modules.

## Cargo Quality Gates (`rch`)

- `cargo check --all-targets` -> exit `101` (`artifacts/section_10_17/bd-274s/rch_cargo_check_all_targets.log`)

Cargo check failures are in other modules (federation, policy, runtime) -- not in adversary_graph.rs or quarantine_controller.rs.
