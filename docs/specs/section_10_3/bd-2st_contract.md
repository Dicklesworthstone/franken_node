# bd-2st: Migration Validation Runner

## Decision Rationale

After rewrite suggestions are applied, operators need a validation runner that executes checks between the original Node.js/Bun execution and franken_node execution. Discovery alone cannot establish behavioral equivalence before migration.

## Scope

`scripts/migration_validation_runner.py` now executes the discovered tests rather than emitting design-phase PENDING reports. Its default baseline command is `node {test}`; its default migration command is `franken-node run --console-only {test}`. The native product's ordinary policy/configuration remains in force: the runner does not install dependencies, mint authority, or enable a degraded fallback.

This is the standalone runner designated by this contract. It does not change the Rust `franken-node migrate validate` dispatch, replace the L1/L2 release oracle, or certify engine compatibility by itself.

## Operator Usage

Compare a captured original project against its rewritten counterpart:

```bash
python3 scripts/migration_validation_runner.py ./original-project \
  --migrated-project ./rewritten-project \
  --compare-filesystem \
  --timeout-seconds 30 \
  --total-timeout-seconds 300 \
  --out ./migration-validation.json \
  --json
```

Without `--migrated-project`, both runtimes receive the same captured input. Both test inventories must match; added or removed test counterparts are an ERROR before either runtime starts.

Runtime/test-framework commands can be supplied as JSON argument arrays. They must contain exactly one standalone `{test}` argument. Commands are not passed to a shell. For example, an installed Bun reference can be selected with `--baseline-command '["bun", "{test}"]'`. Framework-specific launchers and TypeScript support are the caller's responsibility; merely discovering a `.ts` file does not imply Node can execute it. Each test file is launched separately, not as an automatically inferred package.json test script.

Exit status is 0 only for PASS, 1 for measured FAIL, and 2 for ERROR or NO_TESTS. Report-write failures also return 2. `--out` publishes JSON with a private temporary file, file fsync, and atomic rename; it never turns a failed validation into a successful CLI exit.

## Execution and Comparison

1. **Capture:** Read bounded original and rewritten workspace snapshots before execution. Include dependencies and configuration; exclude `.git`. Preserve contained symlink chains, rebasing absolute internal links. Refuse external/excluded links, unreadable subtrees, special files, and exhausted input budgets. Capture is sequential, not an atomic multi-file filesystem snapshot.
2. **Discovery:** Find JS/TS/MJS/CJS test/spec files and files under `test`/`__tests__`. Exclude dependency and VCS directories from discovery. Compare both inventories before executing any tests.
3. **Dual execution:** Materialize fresh per-test, per-runtime copies from captured bytes. Use a fixed inherited environment for both legs, stdin closed, separately drained stdout/stderr, and a new POSIX process group. Enforce per-leg and total deadlines and per-stream output caps. Dispose of each case pair before proceeding, rather than retaining a project copy for every case.
4. **Output comparison:** Require both processes to exit successfully and compare exact stdout and stderr bytes. Preserve trailing-newline and non-UTF-8 differences. Matching crashes, signals, timeouts, or truncated output are never PASS. The legacy timestamp/PID/path canonicalizer remains a diagnostic helper only; it cannot normalize a live difference into success.
5. **Optional filesystem comparison:** With `--compare-filesystem`, compare persistent file/link/ordinary-permission deltas relative to each leg's own starting snapshot. This detects identical console output with divergent writes or deletions without confusing rewritten source with a runtime effect. Compare the complete delta, hash it, and retain at most 20 changed-path details in the report. This does not observe transient create-then-delete activity, changes outside the workspace, ownership, timestamps, or network effects.
6. **Report:** Emit measured per-leg evidence, band-aware divergence severity, and complete counts. Preserve already-completed leg evidence if staging or the other leg encounters an infrastructure failure. An informational edge-band difference remains a failed equivalence check; severity is not a waiver.

## Report Contract

Schema: `migration-validation-v1`.

- `phase` is `execution`; `comparison_mode` is `exact-bytes`.
- `validation_scope` distinguishes `test-process-stdout-stderr-exit` from `test-process-and-workspace-delta`; `release_certification` is always false.
- `inputs` binds the captured trees with SHA-256 digests; `commands` records the explicitly resolved runtime argv templates.
- `test_discovery` includes both missing-counterpart lists.
- `validation_results` contains test identity, status, compatibility band, divergence channels, and completed runtime observations. Observations include exit code, termination class, elapsed time, observed byte counts, stream digests, and completeness flags. Digests of interrupted streams describe only observed bytes, not unobserved output.
- Optional `workspace_delta` summaries contain a full-delta digest, changed-path count, and a bounded detail preview. Raw stdout, stderr, and file contents are not serialized.
- `summary` accounts for passed, failed, errored, and skipped cases. `errors` describes infrastructure/input failures. Only a nonempty completely successful run receives PASS.

Default limits are 30 seconds per runtime leg, 300 seconds total, and 1 MiB per output stream. Hard input ceilings are 1,024 tests, 50,000 entries, and 256 MiB per captured project. Command argv is bounded to 256 arguments/64 KiB. These are runner/capture limits, not OS resource quotas for arbitrary guest code.

## Safety and Evidence Boundaries

Run only trusted projects. Disposable workspaces isolate ordinary relative-file mutations; they are not an OS sandbox. Absolute paths, ambient credentials, network effects, and descendants that escape the process group require separate isolation. Native franken-node capability policy is not weakened by this runner. Non-POSIX execution is refused until equivalent process-tree supervision exists.

The real-process regression suite explicitly uses Node on both legs to test the orchestrator with equal or deliberately different programs. Those tests establish runner behavior, not native Franken parity. The self-test includes a genuine Python-command differential probe so a green result requires process execution, not only source-string checks. Native Node/Franken project measurements still require an installed working product binary.

## Primary Implementation Surface

- `scripts/migration_validation_runner.py`: discovery, snapshots, dual execution, exact comparison, optional filesystem deltas, report export, and self-test.
- `crates/franken-node/src/runtime/lockstep_harness.rs`: the separate product lockstep harness for Node/Bun/franken_node comparisons and divergence fixtures.
- `tests/test_check_migration_validation.py`: unit and real-process regression coverage.

## Invariants

1. Every test/runtime pair starts from the captured input rather than a previous pair's mutated workspace.
2. All measured divergences are classified by compatibility band.
3. No divergence, missing runtime, missing counterpart, no-test run, matching failure, timeout, or output overflow becomes PASS.
4. Reports preserve available execution evidence without embedding raw program output or file contents.
5. Input/output/delta hashes are deterministic for identical captured data; live timestamps and elapsed times remain measurements, not deterministic claims.

## References

- [bd-2ew_contract.md](bd-2ew_contract.md) — Rewrite Engine
- [L1_LOCKSTEP_RUNNER.md](../../L1_LOCKSTEP_RUNNER.md)
