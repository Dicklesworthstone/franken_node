# bd-2ek7 Verification Summary

**Section:** 10.5  
**Verdict:** PASS
**Completion-debt bead:** bd-2ek7.1

## Scope Delivered

Replaced placeholder compatibility-signature acceptance logic with canonical,
fail-closed verification flows across the replacement-critical policy
compatibility surfaces:

- `crates/franken-node/src/policy/compat_gates.rs`
- `crates/franken-node/src/policy/compatibility_gate.rs`
- `tests/integration/compatibility_policy_pipeline.rs`
- `crates/franken-node/tests/compatibility_policy_pipeline.rs`
- `tests/e2e/compatibility_policy_operator_suite.sh`
- `artifacts/replacement_gap/bd-2ek7/operator_e2e_log.jsonl`
- `artifacts/replacement_gap/bd-2ek7/operator_e2e_summary.json`
- `artifacts/replacement_gap/bd-2ek7/operator_e2e_summary.md`

The current patch set adds canonical serialization, real asymmetric/HMAC
verification appropriate to the trust boundary, stale-receipt rejection,
scope-attenuation enforcement, cached authority validation, structured logs,
and adversarial regression tests that reject same-length and same-shape
forgeries.

## Completion-Debt Coverage

bd-2ek7.1 closes the four missing audit items recorded against bd-2ek7:

- `tests.unit.primary`: covered by `scripts/check_compat_gates.py`,
  `tests/test_check_compat_gates.py`, and existing Rust policy unit surfaces.
- `tests.integration.primary`: covered by the cargo-visible
  `compatibility_policy_pipeline` integration wrapper and the preserved rch
  evidence in `verification_evidence.json`.
- `tests.e2e.primary`: covered by
  `tests/e2e/compatibility_policy_operator_suite.sh`, which runs the checker
  end to end and emits operator evidence artifacts.
- `telemetry.primary`: covered by the policy result/rationale fields and the
  operator JSONL events containing `trace_id`, `predicate_id`,
  `parent_receipt_id`, `derived_scope`, `decision`, `reason_code`,
  `freshness_state`, and `explanation_digest`.

## Verification Status

- `python3 scripts/check_compat_gates.py --json` passed:
  `129 passed, 0 failed`, including completion-debt coverage checks.
- `python3 -m unittest tests/test_check_compat_gates.py` passed:
  `39 tests passed`, including mutation tests for missing completion-debt spec
  items and missing evidence paths.
- `tests/e2e/compatibility_policy_operator_suite.sh` passed:
  `129/129` checker assertions and 2 structured operator events with no missing
  required telemetry fields.
- `python3 -m compileall -q scripts/check_compat_gates.py tests/test_check_compat_gates.py`
  passed.
- Feature-gated remote compile passed with:
  `cargo check -p frankenengine-node --features extended-surfaces --tests`
  under constrained `rch` settings (`CARGO_BUILD_JOBS=1`, `RUSTFLAGS=-Cdebuginfo=0`).
- Focused `compat_gates` remote unit tests passed:
  `79 passed, 0 failed`.
- Package-level `cargo fmt --check -p frankenengine-node` currently fails on
  unrelated active-worktree diffs in `src/api/session_auth.rs` and
  `src/connector/control_channel.rs`, so it is not yet a bead-local signal.
- `compatibility_gate` remote unit tests passed:
  `33 passed, 0 failed`.
- Integration target passed after adding a cargo-visible wrapper:
  `2 passed, 0 failed`.
- `cargo clippy -p frankenengine-node --features extended-surfaces --lib -- -D warnings`
  passed for the library surface that contains the compatibility modules.
- `cargo clippy -p frankenengine-node --features extended-surfaces --all-targets -- -D warnings`
  still fails on an unrelated test-helper lint in
  `crates/franken-node/src/verifier_economy/mod.rs:1084`.

## Acceptance Coverage Already Proven

- Canonical signed receipts reject same-length forged mutations.
- Stale scope-mode receipts fail closed with stable reason codes.
- Scope-widening predicates are rejected both at registration time and during
  gate evaluation.
- Cached predicate evaluation stays within the enforced budget in the focused
  adversarial test lane.
- A source-level regression checker prevents placeholder-signature shortcut
  markers from reappearing in the compatibility modules.
- The completion-debt checker now fails closed when a required bd-2ek7.1 spec
  item or evidence path is missing.
- The operator E2E harness records the policy-compatibility telemetry contract
  in JSONL plus machine-readable and Markdown summaries.
