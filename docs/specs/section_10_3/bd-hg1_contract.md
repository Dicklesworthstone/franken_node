# bd-hg1: One-Command Migration Report Export

## Decision Rationale

Enterprise adoption requires a single command that produces a comprehensive, shareable migration assessment. This command orchestrates scan → score → validate → plan → confidence into one exportable report.

## Scope

Build `franken-node migrate-report <project>` that:
1. Runs project scanner
2. Computes risk score
3. Generates rewrite suggestions
4. Produces rollout plan
5. Computes confidence report
6. Exports everything as a single JSON/HTML report

## Command Interface

```
franken-node migrate-report <project_dir> [--format json|html] [--output report.json]
```

## Report Sections

1. Executive Summary (go/no-go, confidence, risk score)
2. API Inventory (detected APIs by family and band)
3. Risk Assessment (score, features, difficulty)
4. Rewrite Suggestions (prioritized list)
5. Rollout Plan (phase-by-phase with gates)
6. Confidence Assessment (score with uncertainty bands)

## Invariants

1. Single command produces complete report.
2. Report is self-contained (no external references needed).
3. Stable report content is deterministic for identical project state: section ordering, risk scoring, API inventory, rewrite suggestions, rollout gates, and confidence bands must not vary for the same inputs.
4. `generated_at_utc` is intentionally dynamic provenance and is excluded from content-determinism comparisons.
5. JSON output validates against schema.

## Determinism Boundary

Regression tests and gates must compare stable report content separately from wall-clock provenance. Do not remove `generated_at_utc` to satisfy deterministic-output checks; scrub or ignore that field when asserting repeatability.

## Measured Standalone Report Workflow

`scripts/migrate_report.py` now connects assessment to the executable migration validator and failure-capsule exporter. This is the standalone report surface, **not a change to the native Rust `franken-node migrate-report` or `migrate validate` dispatch**. The native interfaces above remain separate. This workflow does not apply suggested rewrites or deploy a fleet.

```bash
python3 scripts/migrate_report.py ./original-project \
  --migrated-project ./rewritten-project \
  --execute \
  --compare-filesystem \
  --failure-dir ./migration-failures \
  --out ./migration-report.html \
  --format html \
  --json
```

The default runtime commands are `node {test}` and `franken-node run --console-only {test}`. Explicit JSON argv arrays can be supplied with `--baseline-command` and `--migration-command`; commands are never passed to a shell. No package installation, policy authority, permissive profile, or degraded-runtime fallback is introduced by the report workflow. Framework-specific commands and TypeScript support remain operator responsibilities.

Without `--execute`, the command only assesses captured inputs and returns `ASSESSED` / `NO-GO` with exit 2. Static findings alone cannot establish runtime equivalence. `--failure-dir` requires explicit execution. Output paths must be new, distinct, outside both input trees, and have existing parent directories. They are checked before guest code starts.

### Same inputs throughout the workflow

Each distinct original/candidate tree is captured once before analysis or execution. Assessment, runtime validation, and automatic failure export consume those captured bytes. Staged and measured input hashes must match the captured input hashes before the result can support progression. Changes to the original source tree after capture cannot silently replace the measured capsule's contents.

Assessment retains original findings and separately evaluates the candidate tree. Candidate risks govern progression: an unsafe construct removed by a successful rewrite is not treated as still present, while unresolved high/critical candidate findings or adapter/manual-review suggestions remain blockers even if tests pass. Project package manifests are checked across monorepos, including optional and peer dependencies. Invalid JSON, malformed dependency declarations, unreadable sources, and invalid source encoding are errors rather than silently disappearing from the inventory.

The scanner remains a regex-based API inventory and declared-dependency check, not a complete static security analysis. Rewrite suggestions remain advisory and explicitly unapplied. Embedded legacy example/rollback command strings are not executed.

### Measured decisions and uncertainty

The report includes the complete validation result, resolved runtime bindings, input digests, and capture/assessment/validation stage events. Runtime executable/argument and replay-validator identities are checked before and after execution through the existing replay binding mechanism. These hashes do not capture dynamic libraries, ambient environment, or external services.

`scripts/migration_confidence_report.py` reconciles the declared verdict and counts with the actual per-case observations: nonempty matching inventories, complete accounting, normal successful exits, exact stdout/stderr digests and counts, and optional persistent filesystem-delta identities. A summary-only PASS, incomplete output, duplicate case, matching crash, timeout, or differing filesystem outcome cannot authorize progression.

Unavailable fixture coverage and API tracking are reported as unknown, not assumed 50%/80%. Low-risk API counts are not used as a surrogate for measured coverage. The score and uncertainty band are explicitly heuristic, not a calibrated success probability or statistical confidence interval.

The executive decision, nested confidence decision, and rollout validation gate agree. `GO` is limited to evaluating the captured test scope. It does not authorize production rollout: the shadow phase can be `eligible_for_evaluation`, while canary/ramp/default remain `not_evaluated` and every phase retains `execution_authorized=false`. Missing registry data and unresolved candidate reviews block readiness.

### Automatic failure evidence and exports

With `--failure-dir`, a complete measured FAIL produces an ordinary `migration-failure-replay-v1` capsule containing the original captured inputs and the measurements from this run. The report records its path, identity, and content hash. It works with the existing replay, fix-verification, and minimization tools without creating a second replay format. A passing run creates no failure directory; absent tests or incomplete/infrastructure-failed execution cannot be represented as a replayable complete failure.

Capsules are mode 0600 beneath a new mode-0700 directory. They may contain source code, `.env` files and keys: treat them as sensitive. Integrity hashes are not signatures or encryption. Reports omit raw guest stdout/stderr and file contents, although their paths, findings, command arguments, and metadata can also be sensitive.

JSON and escaped self-contained HTML exports are mode 0600 and use private temporary files, file fsync, and an atomic create-only hard link. An existing destination—including one created after preflight—is never overwritten. Failure to publish a report returns an error and preserves the measured report and any already-created capsule reference in stdout JSON.

Workflow schema: `measured-migration-report-v1`, alongside the retained `report_version: 1.0` field. `release_certification` is always false.

| Workflow status | Exit | Meaning |
|---|---:|---|
| `VALIDATED` / `GO` | 0 | Complete passing measured tests and satisfied candidate assessment/review gates; captured scope only |
| `BLOCKED` / `NO-GO` | 1 | Measured failure, no tests, or an unmet assessment/review gate; available evidence is retained |
| `ASSESSED` / `NO-GO` | 2 | Static assessment only; no runtime equivalence established |
| `ERROR` / `NO-GO` | 2 | Invalid inputs, unavailable runtime, provenance mismatch, incomplete execution, or publication failure |

The existing validator supplies process/output bounds, fresh case workspaces and POSIX process-group supervision; assessment and execution share a total budget. These are not an OS sandbox. Execute trusted projects only. Absolute-path writes, ambient credentials, network effects, escaped process groups, and concurrent host filesystem mutation require separate containment. Sequential file capture and pre/post hashing are not atomic whole-machine snapshots.

### Verification

```bash
python3 -m unittest discover -s tests -p test_check_confidence_report.py -v
python3 -m unittest discover -s tests -p test_check_migrate_report.py -v
```

The report suite contains real Node/Node orchestration tests for positive decisions, console/filesystem divergence, automatic capture and replay, source changes after capture, review precedence, nested native dependencies, invalid manifests, bounded execution, private HTML/JSON publication and failure exits. Node/Node tests with deliberately different programs validate the workflow; native Franken compatibility must be measured separately. The report self-test also checks the separate native Rust command's source contract and therefore requires a complete checkout.

## References

- All bd-* contracts in section_10_3/
- [bd-2st_contract.md](bd-2st_contract.md) — Executable validation and its scope
- [bd-3f9_contract.md](bd-3f9_contract.md) — Replay, runtime bindings and fix verification
