# bd-1e0: Migration Singularity Demo Pipeline for Flagship Repositories

## Scope

End-to-end automated migration demo pipeline that proves one-command migration
from Node.js to franken_node on well-known flagship repositories. The pipeline
covers discovery through validation with structured before/after evidence,
reproducibility guarantees, and publication-ready migration reports.

## Target Flagship Repositories

The demo pipeline operates on at least three pinned flagship Node.js projects
spanning distinct categories:

| Category | Example Repository | Pinned Version | Rationale |
|----------|--------------------|----------------|-----------|
| Web framework | Express | v4.21.0 | Most-used Node.js HTTP framework |
| Full-stack framework | Next.js starter | v14.2.0 | Dominant full-stack framework |
| Utility library | date-fns | v3.6.0 | Pure-JS utility with broad API surface |

### Flagship Repository Criteria

A repository qualifies as "flagship" when it meets all of the following:

| Criterion | Minimum Threshold |
|-----------|-------------------|
| GitHub stars | >= 10,000 |
| Weekly npm downloads | >= 500,000 |
| Dependency count (direct) | >= 5 |
| Test coverage | >= 60% line coverage |
| Active maintenance | Commit within last 90 days |

## Pipeline Stages

The pipeline executes six sequential stages, each producing structured output:

### Stage 1: Discovery

Locate and clone the target repository at the pinned version. Enumerate source
files, test files, configuration, and dependency manifests.

**Output**: `discovery_manifest.json` containing file inventory, dependency
graph, and repository metadata.

### Stage 2: Analysis (Audit + Risk Map)

Static analysis of source code identifying:
- API usage by compatibility band: safe, conditional, unsafe
- Dependency graph with risk annotations per dependency
- Platform-specific code patterns (fs, child_process, native addons)
- Estimated migration complexity score (0-100 scale)

Risk is quantified per file and per API call site. Visual and structured
output shows which code paths are safe for automatic migration, which require
conditional handling, and which need manual intervention.

**Output**: `analysis_report.json` with per-file risk map, complexity score,
and API band classification.

### Stage 3: Migration Plan Generation (Rewrite Suggestions)

Automated code transformation suggestions for conditional and unsafe API usage:
- Original code snippet
- Proposed replacement code
- Confidence grade: high (>= 90%), medium (70-89%), low (< 70%)
- Rationale for the transformation
- High-confidence suggestions can be auto-applied
- Low-confidence suggestions are flagged for human review

**Output**: `migration_plan.json` with ordered list of transformations.

### Stage 4: Execution

Apply high-confidence transformations automatically. Stage medium/low-confidence
suggestions for review. Record every transformation applied with before/after
file content.

**Output**: `execution_log.json` with applied transformations and diffs.

### Stage 5: Validation

After applying transformations, run the project's existing test suite under
franken_node. Capture:
- Tests passed (count and names)
- Tests failed (with root cause classification)
- Tests skipped (with reason)
- Performance benchmarks: startup time, request throughput, memory usage
- Security posture: trust verification status, containment capabilities gained

**Output**: `validation_report.json` with test results, performance metrics,
and security posture comparison.

### Stage 6: Rollback

If validation fails beyond acceptable thresholds, automatically rollback all
transformations. Produce a clear report of what succeeded, what failed, and
recommended manual steps.

**Output**: `rollback_report.json` (only if rollback triggered).

## Before/After Evidence

The pipeline produces side-by-side comparison artifacts:

| Dimension | Before | After |
|-----------|--------|-------|
| Test pass rate | Measured under Node.js | Measured under franken_node |
| Startup time | Baseline (ms) | Migrated (ms) |
| Request throughput | Baseline (req/s) | Migrated (req/s) |
| Memory usage | Baseline (MB) | Migrated (MB) |
| Security posture | No containment | Trust-verified, sandboxed |

Evidence is structured JSON with SHA-256 integrity hashes for every artifact.

## Demo Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_9/bd-1e0_contract.md` |
| Policy doc | `docs/policy/migration_singularity_demo.md` |
| Verification script | `scripts/check_migration_demo.py` |
| Unit tests | `tests/test_check_migration_demo.py` |
| Live CLI E2E test | `crates/franken-node/tests/migrate_cli_e2e.rs::migration_demo_pipeline_runs_live_migrate_commands_end_to_end` |
| Flagship configs | `fixtures/migration-demos/` |
| Verification evidence | `artifacts/section_10_9/bd-1e0/verification_evidence.json` |
| Verification summary | `artifacts/section_10_9/bd-1e0/verification_summary.md` |

## Migration Timeline

| Phase | Duration Target | Description |
|-------|-----------------|-------------|
| Discovery | < 30s | Clone and enumerate |
| Analysis | < 120s | Static analysis and risk mapping |
| Plan generation | < 60s | Transformation suggestion generation |
| Execution | < 120s | Apply transformations |
| Validation | < 300s | Run test suite and benchmarks |
| Rollback | < 30s | Revert if needed |
| **Total** | **< 10 min** | Full pipeline on medium-sized project |

## Compatibility Report

The pipeline generates a publication-ready Markdown migration report containing:
- Executive summary with migration verdict
- Detailed findings per pipeline stage
- Before/after comparison tables
- Confidence assessment per transformation category
- Recommended next steps for manual intervention items

## Reproducibility

The entire pipeline runs in a hermetic container with pinned dependencies.
An external party can execute:

```
./migrate-demo.sh <repo-url> <version>
```

and reproduce the exact same results. Container image hash is recorded in
evidence for auditability.

## Event Codes

| Code | Trigger |
|------|---------|
| MSD-001 | Pipeline started: target repository identified and version pinned |
| MSD-002 | Stage completed: emitted once per stage with stage name and duration |
| MSD-003 | Migration validated: all validation checks passed |
| MSD-004 | Rollback triggered: validation failed, transformations reverted |

## Invariants

| ID | Statement |
|----|-----------|
| INV-MSD-PIPELINE | All six pipeline stages execute in order; no stage is skipped |
| INV-MSD-VALIDATION | Validation runs the project's own test suite; synthetic tests are never substituted |
| INV-MSD-ROLLBACK | If validation fails beyond threshold, rollback is automatic and complete |
| INV-MSD-ARTIFACTS | Every pipeline run produces structured JSON evidence with integrity hashes |

## Error Codes

| Code | Condition |
|------|-----------|
| ERR-MSD-CLONE-FAIL | Target repository cannot be cloned at pinned version |
| ERR-MSD-ANALYSIS-TIMEOUT | Static analysis exceeds 120s timeout |
| ERR-MSD-TRANSFORM-CONFLICT | Transformation produces conflicting file edits |
| ERR-MSD-VALIDATION-TIMEOUT | Test suite execution exceeds 300s timeout |
| ERR-MSD-ROLLBACK-INCOMPLETE | Rollback could not fully revert all transformations |

## Acceptance Criteria

1. Pipeline executes end-to-end on at least three flagship Node.js repositories with a single command.
2. All six pipeline stages (discovery, analysis, plan generation, execution, validation, rollback) produce structured output.
3. Rewrite suggestions include confidence grades; high-confidence suggestions are verifiably correct (validated by test suite).
4. Before/after evidence includes test pass rates, performance comparison, and security posture improvement.
5. Pipeline runs in a hermetic container and produces reproducible results across runs.
6. Migration report (Markdown) is generated automatically and is suitable for publication without manual editing.
7. The pipeline handles migration failures gracefully: partial migration produces a clear report of what succeeded, what failed, and recommended manual steps.
8. Execution time for the full pipeline on a medium-sized project (Express) is under 10 minutes on standard CI hardware.
9. Evidence artifacts include SHA-256 integrity hashes for tamper detection.
10. Rollback mechanism reverts all transformations when validation fails beyond configurable thresholds.
