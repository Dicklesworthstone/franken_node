# bd-2a0: Project Scanner — Verification Summary

## Bead
- **ID**: bd-2a0
- **Section**: 10.3
- **Title**: Build project scanner for API/runtime/dependency risk inventory

## Artifacts Created
1. `docs/specs/section_10_3/bd-2a0_contract.md` — Design spec
2. `scripts/project_scanner.py` — Scanner implementation
3. `schemas/project_scan_report.schema.json` — Report schema
4. `scripts/check_project_scanner.py` — Verification script
5. `tests/test_check_project_scanner.py` — Unit tests
6. `crates/franken-node/src/supply_chain/project_scanner.rs` — Rust scanner implementation
7. `crates/franken-node/tests/project_scanner.rs` — Rust integration tests

## Scanner Capabilities
- 15 API detection patterns (fs, path, process, http, crypto, child_process)
- 4 unsafe patterns (eval, Function, vm.runInNewContext, process.binding)
- Native addon detection for 13 known packages
- Risk classification: low/medium/high/critical
- Migration readiness scoring: ready/partial/not-ready
- Registry integration for band/status lookups
- Deterministic Rust report generation for fixed timestamps and sorted source/dependency traversal
- Bounded Rust source, package, and registry reads to prevent oversized scan inputs
- Rust fail-closed malformed `package.json` handling
- Rust `node_modules` exclusion for dependency trees

## Verification Results
- **SCANNER-EXISTS**: PASS — Python scanner, Rust scanner, and schema exist
- **SCANNER-PATTERNS**: PASS — 15 API + 4 unsafe patterns represented in Rust scanner
- **SCANNER-REGISTRY**: PASS — 5 registry entries loaded from `docs/COMPATIBILITY_REGISTRY.json`
- **SCANNER-RUST-INTEGRATION**: PASS — `project_scanner` Rust test target passed
- **SCANNER-RISK**: PASS — All risk classifications correct
- **SCANNER-RUST-ARTIFACTS**: PASS — Source/test artifact hashes recorded in `verification_evidence.json`

## Test Results
- 20 unit tests: all passed
- 5 verification checks: all passed
- 5 Rust integration tests: all passed

## Rust Implementation Evidence
- `crates/franken-node/src/supply_chain/project_scanner.rs` defines the schema-compatible Rust report, risk distribution, API usage, dependency risk, and verification types.
- `scan_project_at` / `scan_project_with_registry_at` produce deterministic reports for fixed timestamps.
- `scan_text` detects API and unsafe usage; `scan_dependencies` flags native addon dependencies as critical.
- `verification_report_at` emits machine-readable scanner verification evidence.
- `crates/franken-node/src/supply_chain/mod.rs` exports `project_scanner`.
- `crates/franken-node/Cargo.toml` registers the `project_scanner` integration test target.

## Rust Validation
- `rustfmt --edition 2024 crates/franken-node/src/supply_chain/project_scanner.rs crates/franken-node/tests/project_scanner.rs --check`: PASS
- `git diff --check -- crates/franken-node/src/supply_chain/project_scanner.rs crates/franken-node/tests/project_scanner.rs crates/franken-node/src/supply_chain/mod.rs crates/franken-node/Cargo.toml`: PASS
- `UBS_SKIP_RUST_BUILD=1 ubs crates/franken-node/src/supply_chain/project_scanner.rs crates/franken-node/tests/project_scanner.rs crates/franken-node/Cargo.toml`: PASS with 0 criticals
- `timeout 600 rch exec -- bash -lc 'CARGO_TARGET_DIR=/data/tmp/franken_node_bd2a01_target CARGO_BUILD_JOBS=1 cargo test -p frankenengine-node --no-default-features --test project_scanner'`: PASS, 5 passed / 0 failed

## Verdict: PASS
