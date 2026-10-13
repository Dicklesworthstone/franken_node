# Minimized Divergence Fixture Generation

> Design target: when divergences are detected, automatically generate the
> smallest fixture that reproduces the behavior difference.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md), [fixture_runner.py](../scripts/fixture_runner.py)

Sections 1–5 describe the full target design. Sections 7–8 document the executable
migration-capsule reducer, including opt-in sub-line source and binary stdin
reduction; neither claims a global minimum or native L1 automatic integration.

---

## 1. Purpose

When the L1 lockstep oracle detects a divergence between Node.js/Bun and franken_node, the minimized fixture generator produces the smallest possible test case that reproduces the difference. This aids debugging, reduces noise in the divergence ledger, and produces high-quality regression fixtures.

## 2. Minimization Strategies

### 2.1 Input Reduction

Progressively simplify fixture inputs:
1. Remove optional arguments one at a time
2. Reduce string arguments to shorter values
3. Remove array elements
4. Simplify object properties
5. After each simplification, re-run through oracle
6. If divergence persists → keep simplification
7. If divergence disappears → restore previous value
8. Repeat until no further reduction preserves the divergence

### 2.2 Scope Isolation

Narrow the API call surface:
1. If fixture involves multiple API calls, binary-search for the call that triggers divergence
2. Remove setup/teardown steps that don't affect the divergence
3. Inline constants rather than using file/env dependencies

### 2.3 Output Extraction

Capture canonical outputs from all runtimes:
1. Run minimized fixture through each oracle runtime
2. Canonicalize all outputs
3. Store both expected (oracle source) and actual (franken_node) as structured data
4. Annotate with divergence type (value mismatch, error difference, timing)

## 3. Generated Fixture Format

Minimized fixtures extend the standard fixture schema with:

```json
{
  "id": "fixture:fs:readFile:utf8-basic_min",
  "api_family": "fs",
  "api_name": "readFile",
  "band": "core",
  "description": "Minimized reproduction of DIV-003",
  "input": {"args": ["test.txt"]},
  "expected_output": {"return_value": "data"},
  "oracle_source": "node-20.11.0",
  "tags": ["minimized", "core", "divergence"],
  "minimized_from": "fixture:fs:readFile:utf8-basic",
  "minimization_method": "input-reduction",
  "divergence_id": "DIV-003"
}
```

## 4. Storage

- **Location**: `docs/fixtures/minimized/`
- **Naming**: `<original_id>_min.json`
- **Lifecycle**: Minimized fixtures persist as regression tests even after the divergence is resolved

## 5. Integration

- L1 lockstep runner triggers minimization on new divergences
- Minimized fixtures are added to the fixture corpus for continuous testing
- Divergence ledger entries reference their minimized fixture
- CI includes minimized fixtures in the standard fixture run

## 6. References

- [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md) — Oracle runner
- [DIVERGENCE_LEDGER.json](DIVERGENCE_LEDGER.json) — Divergence records
- [compatibility_fixture.schema.json](../schemas/compatibility_fixture.schema.json) — Fixture format

## 7. Delivered Execution-Backed Migration Reducer

Implementation: `scripts/minimize_migration_failure.py`.
Regression suite: `tests/test_minimize_migration_failure.py`.

This reducer consumes the executable `migration-failure-replay-v1` capsules
produced by `scripts/failure_replay.py`. It restores captured input bytes,
executes the real baseline and migration commands via the existing migration
runner, and searches for deletable source lines. It is not a static string
checker, a random fixture generator, or a test-count gate.

### One-command capture → reduction → inspectable repro

```bash
python3 scripts/minimize_migration_failure.py \
  --capture ./original-project \
  --migrated-project ./rewritten-project \
  --capture-out ./original-failure.json \
  --compare-filesystem \
  --execute \
  --out ./reduced-failure.json \
  --export-dir ./repro-workspaces \
  --seconds 120 \
  --max-executions 128 \
  --json
```

Defaults use the Node and native `franken-node run` command templates documented
in [MIGRATION_CAPTURED_EXECUTION.md](MIGRATION_CAPTURED_EXECUTION.md), including
the application-argument slot and the native option terminator.
Explicit `--baseline-command` and `--migration-command` JSON argv arrays can
select other trusted executables. The tool never executes commands embedded in
an untrusted capsule, installs dependencies, or changes product policy.

The original measured capsule is saved before reduction. If the reference
failed, the failure is unstable, or reduction cannot finish safely, that
original remains available. A passing capture is reported as `NO_FAILURE`, not
turned into a fabricated failing fixture. All requested destinations must be
new, distinct paths with existing parent directories; they are checked before
any guest code starts.

For an existing capsule, use its path instead of `--capture`, omit capture-only
options, and optionally pin its hash from an independent trusted channel:

```bash
python3 scripts/minimize_migration_failure.py ./original-failure.json \
  --execute --expected-sha256 "$CAPSULE_SHA256" \
  --out ./reduced-failure.json --json
```

Use repeated `--source-file lib/helper.js` arguments to reduce shared supporting
source files instead of the failing test files. Only explicit regular UTF-8
JS/TS sources present in both captured trees are eligible. Configuration files,
permissions, symlinks, dependencies outside the selected source set, and the
entire test inventory remain unchanged. Original project directories are never
edited by the reducer.

### Preservation predicate

Before reduction, the original capsule must reproduce at least twice using its
recorded executable/argument/validator bindings. Reference runs must have
succeeded. Timeout, signal-terminated, or truncated-output seeds are refused.
A migration-side ordinary nonzero exit can be preserved, but cannot be swapped
for a different error merely because the exit is still nonzero.

Every accepted candidate must preserve **all recorded case observations**, not
just the selected failure: test IDs, statuses, divergence channels, stdout and
stderr digests/counts, exits, and recorded persistent filesystem-delta digests.
Only input hashes are allowed to change. Each acceptance requires at least two
fresh full-suite runs. A new syntax error, reference failure, different output,
or formerly passing test regression rejects the candidate.

After search, the reducer runs fresh final confirmations, recomputes the reduced
input hashes, and emits a new ordinary replay capsule. A cached acceptance is
never final proof. If final observations drift, no reduced capsule is emitted.
The output works with existing `failure_replay.py --replay` and `--verify-fix`;
the existing replay/runner scripts and their validator bindings are unchanged.
`REPRODUCED` still means the migration failure reproduces, not that it is fixed.

### Search, budgets and evidence

The algorithm uses deterministic complement-based delta debugging on source
lines and repeats file/leg sweeps until no further accepted reduction occurs.
Rejected configurations are cached using the complete selected-source state.
Syntax-invalid candidates are rejected by actual execution rather than being
accepted as replacement failures.

Defaults: 128 full-suite oracle executions, 120 seconds, two confirmations.
Limits: 4,096 executions, 3,600 seconds, 2–8 confirmations, 16 selected paths,
and 1 MiB/4,096 lines per selected source. Final confirmation executions and
20% of the reduction wall-time allowance are reserved. Capture shares the CLI
wall-time allowance; its initial measured run is additional to the reduction
execution count. Offline export has a separate bounded staging allowance.

A search budget can produce a smaller verified capsule with
`search_complete=false`; it is never labeled a completed minimum. Failure to
complete final verification produces ERROR instead. Even a completed line
search does not claim a global minimum, grammar-level minimality, or equivalent
behavior on inputs outside the recorded cases. Repeated confirmation detects
some instability; it does not establish general determinism.

The content-bound `minimization` metadata records the parent capsule digest,
reducer implementation hash, selected paths, before/after source byte totals,
confirmation counts, execution/acceptance/rejection statistics, candidate
hashes, and whether a budget was exhausted. Diagnostic records do not contain
raw source or program output. Capsule source content is still sensitive.

### Export and exit behavior

`--export-dir` restores `baseline/` and `migration/` beneath a new mode-0700
directory and writes a mode-0600 `reproduction.json` manifest only after checking
both restored input hashes. Export does not execute guest code. The Python
`export_capsule` API can also perform this restoration offline. On an I/O error
a partial directory may remain, but it is not reported as a successful export.

Exit 0 means `REDUCED`, or `NO_FAILURE` in capture mode. Exit 1 means a verified
but `UNCHANGED` capsule. Exit 2 means invalid input, provenance/reproduction
failure, exhausted final-verification budget, or another error. A successful
reduction still records `validation_verdict=FAIL`: it is a better reproducer,
not a passing migration. Errors report paths to any already-saved capsules.

Run only trusted projects. Workspace copies are not an OS sandbox. Capsules
and exported workspaces can contain source, credentials and private keys; file
permissions are not encryption. Checksums are not signatures. Ambient state,
network services, dynamic libraries and process-group escapes remain outside
the replay contract.

### Remaining program work

Native L1-triggered capture/reduction and divergence-ledger/fixture-corpus
registration remain separate work. Expression/AST-aware reduction, structured
argument simplification, timeout/crash-specific predicates, and full deterministic
runtime/environment capture are not implemented. Section 8 adds bounded deletion
inside source lines and binary stdin fixtures, not a language-aware rewrite or
general-purpose input generator. Regression suites use explicit Node/Node
processes to validate orchestration; native Franken compatibility remains separate.

## 8. Sub-Line Source and Paired Stdin Reduction

### Minified sources

Line-only reduction cannot meaningfully shrink a one-line minified dependency.
Select `--source-granularity utf8` to add contiguous Unicode-scalar deletion
after line reduction, using the same all-case execution predicate:

```sh
python3 scripts/minimize_migration_failure.py original-failure.json \
  --execute --expected-sha256 "$CAPSULE_SHA256" \
  --source-file lib/minified.cjs --source-granularity utf8 \
  --max-executions 128 --seconds 120 --out reduced-source.json --json
```

This mode does not parse, reformat, normalize Unicode, or inject replacement
code. Every source candidate remains valid UTF-8; syntax-invalid JavaScript,
new reference failures, and changed output are rejected by the runtime oracle.
Deletion can occur inside a literal, but acceptance proves only the recorded
case observations, not equivalent behavior on arbitrary inputs. `.mts` and
`.cts` join the existing explicit JS/TS source extensions. Default `lines`
behavior and all source size, line-count and confirmation limits remain intact.

### Binary request fixtures

Select a fixture already declared as `stdin` in the captured test manifest:

```sh
python3 scripts/minimize_migration_failure.py original-failure.json \
  --execute --expected-sha256 "$CAPSULE_SHA256" \
  --stdin-file fixtures/request.bin \
  --max-executions 128 --seconds 120 --out reduced-input.json --json
```

Without `--source-file`, stdin selection leaves every source file unchanged.
Repeat `--stdin-file` for multiple declared fixtures, or combine explicit source
and stdin selections for a fixed-point search across both kinds of input.
An input candidate replaces the selected fixture with **identical bytes in
both captured runtime workspaces**. NUL and invalid UTF-8 bytes are supported;
there is no decoding, newline normalization or transport substitution. The
captured `file`/`pipe` mode, arguments, environment, test inventory and concurrency
remain unchanged. Every case using a shared fixture must preserve its recorded
behavior, including previously passing cases, not just the selected failure.

Selections must be distinct, ordinary captured files, at most 1 MiB each, and
declared by both inventories. Undeclared files, symlinks, duplicate selections,
source/stdin overlap and more than 16 distinct selected paths are rejected before
runtime lookup. A stdin selection may not be any selected test entrypoint or
any output-expectation fixture, even one belonging to a different passing test.
The existing runner checks identical request settings and golden fixture bytes
before execution; this feature does not waive that admission barrier.

### Budgets, receipts and verification

Both modes use strict deletion and the existing repeated full-suite acceptance
checks, runtime/validator identity rechecks and fresh final confirmations. The
reduction kernel's source digest is recorded and rechecked alongside the main
reducer. A per-search partition bound of 4,096 oracle calls also applies;
exhaustion retains only the last accepted state and reports incomplete search.
The full-suite execution limit remains shared across source and stdin searches,
with final confirmations and 20% of wall time reserved. There is no unbounded
character-by-character scan followed by an unverified best-effort result.

Metadata distinguishes `source_granularity`, `source_files`, `stdin_files`, and
the reduction kernel hash. Attempt records identify `kind: source` or `stdin`;
stdin attempts identify `leg: both`. Byte totals count selected bytes in both
captured workspaces, so a shared 100-byte stdin fixture contributes 200 bytes.
No raw source, request bytes or output is placed in minimization metadata.
The new capsule still contains sensitive input material and requires private
storage. Replay remains reproduction of a failure, not a verified fix.

Focused checks:

```sh
python3 -m unittest discover -s tests -p test_migration_reduction.py -v
python3 -m unittest discover -s tests -p test_migration_reduction_capsules.py -v
python3 -m unittest discover -s tests -p test_minimize_migration_failure.py -v
```

The capsule regressions use the production capture, validation, minimization
and replay functions with actual Node processes. They cover minified-source
reduction, shared binary input preserving passing cases, file-mode replay after
relocation, protected fixture admission and reserved confirmation budgets. They
do not establish native engine compatibility, a migration-throughput KPI,
general determinism, an OS sandbox, or a global/grammar-level minimum.
