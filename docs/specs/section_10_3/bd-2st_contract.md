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

## Native Rust Project-Suite Operator (Linux)

`tools/migration-validator/` provides an independently buildable native executable over the actual `crates/franken-node/src/migration/validation_suite.rs` and `smoke_supervisor.rs` modules. It does not invoke Python, copy the executor into a test implementation, or link the optional engine library graph. Instead it executes an explicitly selected installed product binary as its candidate runtime.

From the repository root:

```bash
cargo run --manifest-path tools/migration-validator/Cargo.toml -- \
  /path/to/project \
  --native-bin /path/to/franken-node \
  --execute \
  --out /path/outside-project/new-validation-report.json
```

Use an actual Node installation on an absolute PATH entry and a trusted native `franken-node` binary outside the measured project. Executable hashes identify the bytes used; they do not authenticate the vendor or prove that an arbitrary executable implements the native runtime. The candidate command is fixed to `run ./test --runtime franken-engine --engine-bin <selected-binary> --console-only`. The degraded-runtime opt-in is removed. The operator does not install packages, grant capabilities, infer package scripts, or add policy exceptions. Prepare the project's ordinary configuration and dependencies before measurement.

### Native execution contract

The operator captures one project before execution, including dependencies and configuration but excluding `.git`. It preserves contained symlink chains and ordinary permissions, rebases absolute internal links, and refuses external/excluded links, hard-linked regular files, nonregular inputs, unreadable files, oversized captures, and detected file changes during capture. This is a sequential capture, not an atomic filesystem snapshot.

It discovers exact `.test`/`.spec` filenames with JS/MJS/CJS/TS/MTS/CTS extensions and supported files under `test`/`__tests__`. Dependency, VCS, product-state and migration-backup directories are excluded from test discovery. Every case/runtime pair receives a new private workspace restored from the captured bytes. No prior case's ordinary relative-file changes are carried into the next case. TypeScript and framework support still depend on the selected runtimes; each discovered file is launched directly.

Both normal zero exits and exact stdout/stderr equality are required. Signals, matching nonzero exits, timeouts, overflow and infrastructure errors never pass. A later passing case cannot erase an earlier failure. Completed reference observations survive a candidate-side error; remaining cases are attempted while the total budget permits. The full inventory is accounted for with passed, failed, errored and skipped counts.

Direct executable identities are hashed before and after the suite. Changed identities, failed identity rechecks, skipped cases and infrastructure errors yield ERROR. Dynamic libraries, environment values, external services and binary substitutions restored between the two checks are outside this provenance check.

Limits: 1,024 cases, 50,000 captured entries, 256 MiB of file contents, 4,096 bytes per path, 512 MiB per direct runtime executable, 30 seconds per runtime leg, 300 seconds total and 16 MiB per output stream. The owned Linux supervisor provides nonblocking pipe capture and bounded process-group cleanup, including ordinary background group members after successful leader exit. Escaped descendants and arbitrary guest resource consumption require separate OS containment.

### Native reports and exits

Normal report schema: `franken-node/native-validation-suite/v1`. The report includes captured input hash, direct runtime paths/hashes/arguments, case identities, exact-stream hashes and byte counts, exits/signals, divergence channels, errors and complete counts. Raw guest output and source contents are omitted. `scope` is `captured-test-process-stdout-stderr-exit`; `release_certification` is always false.

Exit 0 means a complete nonempty PASS, exit 1 means measured FAIL, and exit 2 means ERROR, missing tests, missing consent or report-publication failure. JSON is printed on stdout. `--out` requires a new file outside the project, preflights that destination before guest execution, and opens it create-only with mode 0600. Existing destinations are never overwritten. A write failure may leave a partial new file; stdout retains the completed measurements with ERROR and publication details.

Run only trusted projects. Workspaces are not an OS sandbox and the report is not a signed certificate. Exact-output comparison is conservative: timestamps, temporary paths, framework durations and other nondeterminism can legitimately cause differences.

### Remaining integration boundary

This native operator does **not** yet replace the existing `franken-node migrate validate` or `migrate-report` dispatch. The optional-suite API is provided for that integration, but those call-site changes are separate. Native filesystem-delta comparison, distinct rewritten-tree input, failure-capsule export and reduction are not implemented in this native operator; the Python workflows above continue to provide those capabilities.

The operator's real-process regressions use explicitly identified Node/Node commands for differential orchestration and `/bin/false` for a deliberate CLI failure. Those tests are not native Franken compatibility measurements. Its standard tests also include the exact production Linux supervisor tests.

```bash
cargo test --manifest-path tools/migration-validator/Cargo.toml
cargo clippy --manifest-path tools/migration-validator/Cargo.toml --all-targets -- -D warnings
```

## References

- [bd-2ew_contract.md](bd-2ew_contract.md) — Rewrite Engine
- [L1_LOCKSTEP_RUNNER.md](../../L1_LOCKSTEP_RUNNER.md)
