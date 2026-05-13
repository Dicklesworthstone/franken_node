# bd-1e0 Verification Summary

## Migration Singularity Demo Pipeline for Flagship Repositories

**Bead:** bd-1e0
**Section:** 10.9
**Verdict:** PASS
**Date:** 2026-05-13

## Results

| Metric | Value |
|--------|-------|
| Total checks | 96 |
| Passing | 96 |
| Failing | 0 |
| Verdict | PASS |

## Verification Categories

| Category | Checks | Status |
|----------|--------|--------|
| File existence (spec, policy, fixtures, E2E test) | 4 | PASS |
| Live CLI E2E pipeline coverage | 8 | PASS |
| Flagship config validation | 5 | PASS |
| Pipeline stages (6 stages) | 6 | PASS |
| Stage outputs (6 artifacts) | 6 | PASS |
| Event codes (MSD-001..004) | 4 | PASS |
| Invariants (INV-MSD-*) | 4 | PASS |
| Error codes (ERR-MSD-*) | 5 | PASS |
| Confidence grades (spec + policy) | 6 | PASS |
| Rollback policy | 4 | PASS |
| Reproducibility (spec + policy) | 6 | PASS |
| Evidence integrity (spec + policy) | 6 | PASS |
| Before/after dimensions | 5 | PASS |
| Timeline targets | 4 | PASS |
| Acceptance criteria | 7 | PASS |
| Policy event logging | 4 | PASS |
| Policy invariants | 4 | PASS |
| Flagship criteria | 4 | PASS |
| Compatibility report | 4 | PASS |

## Unit Tests

46 unit tests pass covering all verification functions, CLI modes (--json,
--self-test, human-readable), and edge cases (_safe_rel for paths inside
and outside ROOT). The live CLI E2E test
`migration_demo_pipeline_runs_live_migrate_commands_end_to_end` drives
`franken-node migrate audit --format json`, `franken-node migrate rewrite
--apply --json --emit-rollback`, and `franken-node migrate validate --format
json` against an isolated project and asserts rollback artifact generation,
manifest mutation, and transformed-runtime smoke validation.

## Artifacts Produced

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_9/bd-1e0_contract.md` |
| Policy doc | `docs/policy/migration_singularity_demo.md` |
| Verification script | `scripts/check_migration_demo.py` |
| Unit tests | `tests/test_check_migration_demo.py` |
| Live CLI E2E test | `crates/franken-node/tests/migrate_cli_e2e.rs::migration_demo_pipeline_runs_live_migrate_commands_end_to_end` |
| Flagship configs | `fixtures/migration-demos/{express,nextjs-starter,date-fns}.json` |
| Verification evidence | `artifacts/section_10_9/bd-1e0/verification_evidence.json` |
| Verification summary | `artifacts/section_10_9/bd-1e0/verification_summary.md` |
