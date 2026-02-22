# bd-3ptu Verification Summary

- bead: `bd-3ptu`
- support bead: `bd-3287`
- section: `10.18`
- verdict: **FAIL**
- checks: 33/44 passed (11 failed)
- generated_at: 2026-02-22T06:35:36.996873+00:00

## Scope
- `tests/security/vef_adversarial_suite.rs` (or fallback `tests/vef_adversarial_suite.rs`)
- `docs/security/vef_adversarial_testing.md`
- `artifacts/10.18/vef_adversarial_results.json`

## Failed Checks
- `evidence_exists` — artifacts/section_10_18/bd-3ptu/verification_evidence.json
- `summary_exists` — artifacts/section_10_18/bd-3ptu/verification_summary.md
- `suite_symbol_expect_err` — expect_err
- `suite_minimum_test_count` — 7 tests
- `doc_attack_class_receipt tampering` — receipt tampering
- `doc_attack_class_proof replay` — proof replay
- `doc_attack_class_commitment mismatch` — commitment mismatch
- `report_parseable_json` — invalid or missing JSON
- `evidence_parseable_json` — invalid or missing JSON
- `summary_mentions_bd` — bd-3ptu
- `summary_mentions_verdict` — verdict marker
