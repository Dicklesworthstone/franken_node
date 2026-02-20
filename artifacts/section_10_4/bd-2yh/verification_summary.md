# bd-2yh Verification Summary

## Outcome

Implemented extension trust-card API + CLI surfaces with deterministic, signed trust-card model and version-aware diff support.

## Delivered

- `crates/franken-node/src/supply_chain/trust_card.rs`
  - Full trust-card model (identity, cert, capability, behavior, provenance, revocation, risk)
  - Deterministic hash/signature computation and verification
  - Cache hit/miss/stale-refresh semantics
  - Telemetry event emission and version hash-linking
  - Extension-to-extension compare and same-extension version diff
- `crates/franken-node/src/supply_chain/mod.rs` export for `trust_card`
- `crates/franken-node/src/api/mod.rs`
- `crates/franken-node/src/api/trust_card_routes.rs`
  - create/update/get/list/by-publisher/search/compare/version-diff handlers
  - shared pagination response metadata
- `crates/franken-node/src/cli.rs`
  - new top-level `trust-card` command family (`show`, `export`, `list`, `compare`, `diff`)
- `crates/franken-node/src/main.rs`
  - command handler wiring and shared rendering/JSON output logic
- `docs/specs/section_10_4/bd-2yh_contract.md`
- `scripts/check_trust_card.py`
- `tests/test_check_trust_card.py`

## Validation

- PASS: `python3 scripts/check_trust_card.py --json` (77/77)
- PASS: `python3 scripts/check_trust_card.py --self-test --json`
- PASS: `python3 -m unittest tests/test_check_trust_card.py` (8 tests)
- PASS: `rch doctor`
- PASS: `rch exec -- rustfmt --edition 2024 --check --config skip_children=true ...<touched files>`

Cargo validation via `rch` (blocked by pre-existing environment/upstream issues):

- FAIL: `rch exec -- cargo test --manifest-path crates/franken-node/Cargo.toml trust_card -- --nocapture`
  - repo-root remote mirror missing sibling `franken_engine` path dependency
- FAIL: `rch exec -- cargo check --manifest-path crates/franken-node/Cargo.toml --all-targets`
  - same missing sibling path dependency
- FAIL: `rch exec -- cargo clippy --manifest-path crates/franken-node/Cargo.toml --all-targets -- -D warnings`
  - same missing sibling path dependency
- FAIL: `rch exec -- cargo fmt --manifest-path crates/franken-node/Cargo.toml --all --check`
  - broad pre-existing format drift/parsing issues outside bd-2yh scope
- FAIL: `rch exec -- cargo check --manifest-path franken_node/crates/franken-node/Cargo.toml --all-targets` from `/data/projects`
  - progresses further, then fails in sibling upstream crate (`franken_extension_host` unresolved import `serde`)

## Evidence Files

- `artifacts/section_10_4/bd-2yh/trust_card_report.json`
- `artifacts/section_10_4/bd-2yh/trust_card_self_test.json`
- `artifacts/section_10_4/bd-2yh/verification_evidence.json`
- `artifacts/section_10_4/bd-2yh/verification_summary.md`
