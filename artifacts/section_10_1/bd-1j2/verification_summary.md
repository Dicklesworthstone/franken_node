# bd-1j2 Verification Summary: Split Contract CI Enforcement

## Bead
- **ID:** bd-1j2
- **Title:** [10.1] Enforce repository split contract checks in CI
- **Section:** 10.1 (Charter + Split Governance)

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Spec/contract document | `docs/specs/section_10_1/bd-1j2_contract.md` | Created |
| Enforcement script | `scripts/check_split_contract.py` | Created |
| Unit + E2E tests (11 tests) | `tests/test_check_split_contract.py` | All pass |
| Verification evidence | `artifacts/section_10_1/bd-1j2/verification_evidence.json` | Generated |

## CI Check Coverage

| Check ID | What It Enforces | Result |
|----------|-----------------|--------|
| SPLIT-NO-LOCAL | No local `crates/franken-engine/` or `crates/franken-extension-host/` dirs | PASS |
| SPLIT-PATH-DEPS | Engine Cargo.toml deps point to `/dp/franken_engine/crates/` | PASS |
| SPLIT-NO-INTERNALS | No Rust source imports engine-internal modules | PASS |
| SPLIT-GOVERNANCE | `ENGINE_SPLIT_CONTRACT.md` and `PRODUCT_CHARTER.md` exist with required content | PASS |

## Telemetry and Migration Evidence

- Report schema: `franken-node/split-contract-report/v1`
- Telemetry namespace: `franken_node.section_10_1.split_contract`
- Gate event: `SPLIT_CONTRACT_GATE_PASSED`
- Migration policy: `SPLIT-CONTRACT-MIGRATION-POLICY`
- Violation action: `block_merge`

## Test Results

11/11 tests passing:
- `test_script_runs_successfully` - Script executes and produces JSON
- `test_verdict_is_pass` - Current repo passes
- `test_all_checks_present` - All 4 check IDs present
- `test_no_local_engine_crates_check` - No forbidden directories
- `test_path_deps_check` - Engine path deps valid
- `test_governance_docs_check` - Required docs exist
- `test_summary_counts` - 4/4 pass, 0 fail
- `test_telemetry_events_cover_each_check_and_gate` - Per-check and aggregate telemetry is stable
- `test_migration_policy_blocks_local_engine_reintroduction` - Migration metadata blocks local engine copies
- `test_e2e_temp_repo_local_engine_copy_fails_closed` - Temp-repo E2E proves local engine reintroduction fails closed
- `test_human_readable_output` - Non-JSON output works

**Overall Verdict: PASS (4/4 checks, 11/11 tests)**
