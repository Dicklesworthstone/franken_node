# bd-274s Support Verification Notes (PurpleHarbor)

- Checker: `scripts/check_bd_274s_bayesian_quarantine.py`
- Verdict: **FAIL** (7/15)
- Missing required files: `6/6`

## Passing Signals
- Bead record is accessible and correctly typed/labeled in `br`.
- Required upstream dependency `bd-1nl1` is closed.
- Required dependents (`bd-1xbc`, `bd-3t08`) are correctly linked.
- Fallback signal surface exists in `crates/franken-node/src/security/bpet/economic_integration.rs` with threshold/quarantine/propensity markers.

## Closure Gaps
- `required_files_present`: missing=['crates/franken-node/src/security/adversary_graph.rs', 'crates/franken-node/src/security/quarantine_controller.rs', 'tests/integration/bayesian_risk_quarantine.rs', 'artifacts/10.17/adversary_graph_state.json', 'artifacts/section_10_17/bd-274s/verification_evidence.json', 'artifacts/section_10_17/bd-274s/verification_summary.md']
- `adversary_graph_tokens`: expects posterior/deterministic/evidence markers
- `quarantine_action_tokens`: found=[]
- `quarantine_signed_evidence_tokens`: expects signed evidence markers in quarantine controller
- `integration_test_determinism_markers`: expects deterministic quarantine integration assertions
- `adversary_graph_state_parseable`: missing or invalid json
- `verification_evidence_parseable`: missing or invalid json
- `verification_summary_present`: artifacts/section_10_17/bd-274s/verification_summary.md

## Suggested Next Moves
1. Implement canonical files: `crates/franken-node/src/security/adversary_graph.rs`, `crates/franken-node/src/security/quarantine_controller.rs`.
2. Add integration coverage: `tests/integration/bayesian_risk_quarantine.rs` with deterministic replay assertions.
3. Emit state artifact: `artifacts/10.17/adversary_graph_state.json` with stable schema fields (`schema_version`, `generated_at`, `posteriors`, `actions`).
4. Generate bead artifacts: `artifacts/section_10_17/bd-274s/verification_evidence.json` + `verification_summary.md`.

## Support Artifacts
- `artifacts/section_10_17/bd-274s/support_check_report_purpleharbor.json`
- `artifacts/section_10_17/bd-274s/support_check_self_test_purpleharbor.txt`
- `artifacts/section_10_17/bd-274s/support_unit_tests_purpleharbor.txt`
