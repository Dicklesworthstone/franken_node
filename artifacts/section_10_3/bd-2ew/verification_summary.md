# bd-2ew: Rewrite Suggestion Engine — Verification Summary

## Bead
- **ID**: bd-2ew
- **Section**: 10.3

## Artifacts
1. `docs/specs/section_10_3/bd-2ew_contract.md`
2. `scripts/rewrite_suggestion_engine.py` — 12 API + 4 unsafe rewrite rules
3. `scripts/check_rewrite_engine.py`
4. `tests/test_check_rewrite_engine.py`
5. `crates/franken-node/src/migration/rewrite_suggestion_engine.rs` — Rust rewrite suggestion engine
6. `crates/franken-node/tests/rewrite_suggestion_engine.rs` — Rust integration tests

## Results
- 8 verification checks: all passed
- 12 unit tests: all passed
- 5 Rust integration tests: all passed

## Rust Implementation Evidence
- `rewrite_suggestion_engine.rs` defines the schema id, suggestion categories,
  risk ordering, rewrite suggestions, rollback command argv payloads, rollback
  plans, complete reports, and machine-readable verification checks.
- `produce_report_at` accepts fixed timestamps so deterministic tests can prove
  identical output for identical inputs.
- `generate_suggestions_from_scan` consumes the Rust project scanner report from
  `supply_chain::project_scanner`, closing the Python-only gap.
- Unknown API families become `manual-review` suggestions; unsafe APIs become
  `removal-needed` suggestions.
- Rollback plans deduplicate affected files and include structured argv forms.

## Rust Validation
- `rustfmt --edition 2024 crates/franken-node/src/migration/rewrite_suggestion_engine.rs crates/franken-node/tests/rewrite_suggestion_engine.rs --check`: PASS
- `git diff --check -- .beads/issues.jsonl crates/franken-node/src/migration/rewrite_suggestion_engine.rs crates/franken-node/tests/rewrite_suggestion_engine.rs crates/franken-node/src/migration/mod.rs crates/franken-node/Cargo.toml docs/specs/section_10_3/bd-2ew_contract.md artifacts/section_10_3/bd-2ew/verification_evidence.json artifacts/section_10_3/bd-2ew/verification_summary.md`: PASS
- `timeout 1800 rch exec -- env CARGO_BUILD_JOBS=1 cargo test -p frankenengine-node --no-default-features --features admin-tools --test rewrite_suggestion_engine`: PASS, 5 passed / 0 failed

## Verdict: PASS
