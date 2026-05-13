# Conformance Harness Operator Playbook

This playbook covers how to run, debug, and interpret the extension
conformance test suite. It is the primary reference for anyone operating the
conformance harness locally or in CI.

## Quick Start

```bash
# Run the fast conformance check (5 official extensions)
PI_OFFICIAL_MAX=5 cargo test --test ext_conformance_diff \
  --features ext-conformance -- --nocapture

# Run the full 223-extension campaign
cargo test --test ext_conformance_generated conformance_full_report \
  --features ext-conformance -- --nocapture

# Run scenario conformance
cargo test --test ext_conformance_scenarios \
  --features ext-conformance scenario_conformance_suite -- --nocapture

# Generate the runtime API matrix report
cargo test --test ext_conformance_matrix \
  generate_runtime_api_matrix_report -- --nocapture
```

## Prerequisites

### Bun Installation

The TS oracle requires Bun 1.3.8+. The harness expects it at
`/home/ubuntu/.bun/bin/bun`.

```bash
# Install Bun
curl -fsSL https://bun.sh/install | bash

# Or symlink an existing installation
ln -sf $(which bun) /home/ubuntu/.bun/bin/bun
```

### pi-mono Dependencies

The TS oracle loads extensions through the legacy pi-mono TypeScript runtime.
Its npm dependencies must be installed:

```bash
cd legacy_pi_mono_code/pi-mono
npm ci
```

### Feature Flag

Most conformance tests require the `ext-conformance` cargo feature:

```bash
cargo test --features ext-conformance --test ext_conformance_diff
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PI_TEST_MODE` | unset | Set to `1` for deterministic timestamps and CWD normalization |
| `PI_CONFORMANCE_SEED` | unset | Seed for deterministic conformance diff runs (e.g., `42`) |
| `PI_EXT_RANDOM_SEED` | `42` | Seed for `ext_random_trials` deterministic selection |
| `PI_EXT_RANDOM_N` | `1` | Bounded `ext_random_trials` sample size; raise only for explicit batch runs |
| `PI_EXT_RANDOM_FILTER` | unset | Optional `ext_random_trials` filter such as `tier:1-3` or `source:community` |
| `PI_EXT_RANDOM_IDS` | unset | Explicit comma-separated `ext_random_trials` extension IDs |
| `PI_EXT_RANDOM_OUTPUT_DIR` | `$TMPDIR/pi_agent_rust/ext_conformance/random_trials` | Override random-trial JSONL and manifest output directory |
| `PI_TS_ORACLE_TIMEOUT_SECS` | `30` | Per-extension timeout for the TS oracle |
| `PI_OFFICIAL_MAX` | unset | Limit number of official extensions tested (e.g., `5` for fast checks) |
| `PI_DETERMINISTIC_CWD` | auto | Override deterministic working directory |
| `PI_DETERMINISTIC_HOME` | auto | Override deterministic home directory |
| `PI_DETERMINISTIC_TIME_MS` | auto | Fixed timestamp for deterministic output |
| `PI_DETERMINISTIC_TIME_STEP_MS` | auto | Time increment per `Date.now()` call |
| `PI_DETERMINISTIC_RANDOM` | auto | Fixed random value (overrides seed) |
| `PI_DETERMINISTIC_RANDOM_SEED` | auto | Seed for deterministic PRNG |
| `RUST_TEST_THREADS` | `1` | Set to `1` for deterministic serial execution |
| `CARGO_TARGET_DIR` | `target` | Isolate build artifacts per agent (multi-agent environments) |

## Test Suites

### Differential Conformance (`ext_conformance_diff`)

The core conformance test. Runs each extension in both the TypeScript oracle
(Bun + pi-mono) and the Rust QuickJS runtime, then compares outputs.

```bash
# All official extensions
cargo test --test ext_conformance_diff --features ext-conformance -- --nocapture

# Single extension (by test name)
cargo test --test ext_conformance_diff diff_official_hello -- --nocapture

# Community extensions (ignored by default)
cargo test --test ext_conformance_diff --features ext-conformance -- --ignored --nocapture
```

**How it works:**

1. Extension file is loaded into the TS oracle via Bun
2. Same file is loaded into the Rust QuickJS runtime
3. Both outputs are normalized (timestamps, paths, random values)
4. Outputs are compared field-by-field
5. Differences produce a FAIL with detailed diff output

### Generated Conformance (`ext_conformance_generated`)

Runs the full 223-extension corpus through a load-and-register test:

```bash
# Full report
cargo test --test ext_conformance_generated conformance_full_report \
  --features ext-conformance -- --nocapture

# Owner-tracked opt-in lane for generated tier 3-5 extension tests.
cargo test --test ext_conformance_generated --features ext-conformance \
  -- --include-ignored --nocapture
```

The generated `#[ignore]` cases are owned by `bd-8t27h.17`; they are not
generic unvendored placeholders. Treat failures in this lane as corpus onboarding
work and either vendor the missing artifact, keep the extension in the tracked
stretch tier with a concrete reason, or file a narrower owner bead.

### Random Trial Smoke Lane (`ext_random_trials`)

Runs a deterministic random subset from the Rust-N/A pool. The default is a
single-extension smoke run so ordinary `cargo test` stays bounded, and output
defaults under `TMPDIR`.

```bash
export CARGO_TARGET_DIR="/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target"
export TMPDIR="/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp"
mkdir -p "$CARGO_TARGET_DIR" "$TMPDIR"

PI_EXT_RANDOM_SEED=42 PI_EXT_RANDOM_N=1 \
  rch exec -- cargo test --test ext_random_trials \
    --features ext-conformance random_trials_batch -- --nocapture
```

For a wider opt-in batch, raise `PI_EXT_RANDOM_N` or pass
`PI_EXT_RANDOM_IDS=id-a,id-b`; results are written to
`$TMPDIR/pi_agent_rust/ext_conformance/random_trials` unless
`PI_EXT_RANDOM_OUTPUT_DIR` is set.

### Scenario Conformance (`ext_conformance_scenarios`)

Tests specific behavioral scenarios defined in JSON fixtures:

```bash
cargo test --test ext_conformance_scenarios \
  --features ext-conformance scenario_conformance_suite -- --nocapture
```

Each scenario specifies:
- An extension to load
- Expected registration shape (tools, flags, commands, event hooks)
- Expected hostcall behavior (exec calls, session operations, UI events)
- Expected content output

### Runtime API Matrix (`ext_conformance_matrix`)

Validates Node.js and Bun API surface coverage:

```bash
# Check critical entries pass
cargo test --test ext_conformance_matrix \
  runtime_api_matrix_node_critical_entries_pass -- --nocapture

# Generate full matrix report
cargo test --test ext_conformance_matrix \
  generate_runtime_api_matrix_report -- --nocapture
```

### Negative Policy Tests (`extensions_policy_negative`)

Validates that the capability policy correctly denies unauthorized operations:

```bash
cargo test --test extensions_policy_negative -- --nocapture
```

### Capability Denial Matrix (`capability_denial_matrix`)

Tests all combinations of policy profiles and capability requests:

```bash
cargo test --test capability_denial_matrix -- --nocapture
```

## Interpreting Results

### Status Codes

| Status | Meaning |
|--------|---------|
| `PASS` | Extension behavior matches between TS oracle and Rust runtime |
| `FAIL` | Behavioral difference detected (see diff output) |
| `N/A` | Extension not yet tested (usually community/npm/third-party tiers) |
| `SKIP` | Test skipped due to missing harness capability |
| `ERROR` | Test infrastructure failure (not an extension problem) |

### Conformance Summary (`conformance_summary.json`)

```json
{
  "schema": "pi.ext.conformance_summary.v2",
  "counts": { "pass": 56, "fail": 4, "na": 163, "total": 223 },
  "pass_rate_pct": 93.33,
  "per_tier": { ... },
  "evidence": { "golden_fixtures": 16, "parity_logs": 16, ... }
}
```

Key metrics:
- `pass_rate_pct`: Calculated as `pass / (pass + fail) * 100` (N/A excluded)
- `per_tier`: Breakdown by extension source tier
- `evidence`: Count of evidence artifacts generated

### Failure Buckets

Common failure categories and their root causes:

| Bucket | Root Cause | Fix |
|--------|-----------|-----|
| `multi_file_dependency` | Extension imports sibling files via relative paths | Implement relative specifier resolution |
| `runtime_error` | Extension throws during load/activate | Check missing shim or API surface |
| `host_read_policy_denial` | `readFileSync` blocked by host-read fallback | Extension reads outside allowed root |
| `package_module_specifier` | `require("some-npm-pkg")` not stubbed | Add virtual module stub |
| `test_fixture` | Not a real extension (test infra artifact) | Ignore |

### Reading Diff Output

When a test fails, the output shows field-by-field differences:

```
DIFF: extension "hello" field "tools[0].description"
  TS oracle:  "Say hello to someone"
  Rust:       "Say hello"
```

Check whether the difference is:
1. A real behavioral gap (needs code fix)
2. A normalization issue (needs deterministic settings)
3. A TS oracle bug (rare, but possible)

## CI Profiles

### PR (Fast)

Triggered on pull requests. Runs a subset for quick feedback:

- `ext_conformance_diff` with `PI_OFFICIAL_MAX=5`
- `ext_conformance_generated` (generated tier 1-2)
- `extensions_policy_negative`
- `capability_denial_matrix`

### Nightly (Full)

Runs at 02:00 UTC daily:

- Full `ext_conformance_diff` (all 66 official)
- Full `ext_conformance_generated` (including ignored)
- `ext_conformance_scenarios`
- `ext_conformance_fixture_schema`
- `ext_conformance_artifacts`
- `conformance_report` generation

### Weekly (Extended)

Runs Saturday 02:00 UTC:

- Community, npm, and third-party extensions
- Full corpus including all ignored tests

## CI Gate Thresholds

The CI gate (`ci.yml`) enforces minimum quality standards:

| Metric | Threshold | Current |
|--------|-----------|---------|
| Pass rate | >= 80% | 93.3% |
| Max fail count | <= 36 | 4 |
| Max N/A count | <= 170 | 163 |
| Evidence contract | `pass` | `pass` |

Gate mode:
- `strict` (default): Fails the build if thresholds are violated
- `rollback`: Warns but allows the build to proceed

## Debugging Workflows

### Debug a Single Extension Failure

```bash
# 1. Run the specific extension's diff test
cargo test --test ext_conformance_diff diff_official_hello \
  --features ext-conformance -- --nocapture 2>&1 | tee /tmp/debug.log

# 2. Check the TS oracle output separately
cd legacy_pi_mono_code/pi-mono
bun run packages/coding-agent/src/core/extensions/runner.ts \
  --extension /path/to/extension.ts

# 3. Check the Rust runtime output
cargo test --test ext_conformance_scenarios \
  --features ext-conformance -- hello --nocapture
```

### Debug TS Oracle Timeout

If the TS oracle times out:

```bash
# Increase timeout
export PI_TS_ORACLE_TIMEOUT_SECS=60

# Or check if Bun is installed correctly
/home/ubuntu/.bun/bin/bun --version

# Check pi-mono dependencies
cd legacy_pi_mono_code/pi-mono && npm ci
```

The harness includes retry logic (up to 3 retries) for flaky oracle
timeouts.

### Debug a "Module Not Found" Error

```bash
# 1. Check which module is missing
cargo test --test ext_conformance_diff diff_official_<name> \
  --features ext-conformance -- --nocapture 2>&1 | grep "Module not found"

# 2. Check if the module is shimmed
grep "node:<module>" src/extensions_js.rs

# 3. Check virtual module stubs
grep "<package-name>" src/extensions_js.rs
```

### Update Baseline After Improvements

After fixing bugs or adding shims:

```bash
# 1. Run the full campaign
cargo test --test ext_conformance_generated conformance_full_report \
  --features ext-conformance -- --nocapture

# 2. The test auto-generates updated reports in:
#    tests/ext_conformance/reports/conformance_summary.json
#    tests/ext_conformance/reports/CONFORMANCE_REPORT.md

# 3. Update the baseline
cp tests/ext_conformance/reports/conformance_summary.json \
   tests/ext_conformance/reports/conformance_baseline.json

# 4. Run the compatibility validation pack
python3 tests/ext_conformance/build_inventory.py
```

### Handle Flaky Tests

1. Check if the failure is deterministic by running with fixed seed:
   ```bash
   PI_CONFORMANCE_SEED=42 PI_TEST_MODE=1 RUST_TEST_THREADS=1 \
     cargo test --test ext_conformance_diff -- --nocapture
   ```

2. If the TS oracle is flaky, increase the timeout and retry count.

3. For path-dependent failures, ensure deterministic CWD/HOME are set.

## Artifact Locations

| Artifact | Path | Format |
|----------|------|--------|
| Conformance summary | `tests/ext_conformance/reports/conformance_summary.json` | JSON |
| Conformance report | `tests/ext_conformance/reports/CONFORMANCE_REPORT.md` | Markdown |
| Conformance events | `tests/ext_conformance/reports/conformance_events.jsonl` | JSONL |
| Conformance baseline | `tests/ext_conformance/reports/conformance_baseline.json` | JSON |
| Compatibility summary | `tests/ext_conformance/reports/COMPATIBILITY_SUMMARY.md` | Markdown |
| Validation pack | `tests/ext_conformance/reports/compatibility_validation_pack.json` | JSON |
| Scenario results | `tests/ext_conformance/reports/scenario_conformance.json` | JSON |
| Scenario events | `tests/ext_conformance/reports/scenario_conformance.jsonl` | JSONL |
| Smoke triage | `tests/ext_conformance/reports/smoke_triage.json` | JSON |
| Inventory | `tests/ext_conformance/reports/inventory.json` | JSON |
| Per-extension logs | `tests/ext_conformance/reports/extensions/<name>.jsonl` | JSONL |
| Parity logs | `tests/ext_conformance/reports/parity/extensions/<name>.jsonl` | JSONL |
| Smoke logs | `tests/ext_conformance/reports/smoke/extensions/<name>.jsonl` | JSONL |
| Runtime API matrix | `tests/ext_conformance/reports/parity/runtime_api_matrix.json` | JSON |
| Validated manifest | `tests/ext_conformance/VALIDATED_MANIFEST.json` | JSON |
| E2E results | `tests/e2e_results/<timestamp>/` | Mixed |
| CI gate verdict | `tests/e2e_results/<timestamp>/ci_gate_promotion_v1.json` | JSON |

## Unified Verification Runner

The `scripts/e2e/run_all.sh` script provides a single entry point for all
verification:

```bash
# Full verification (lint + lib tests + all suites)
./scripts/e2e/run_all.sh

# Quick local iteration
./scripts/e2e/run_all.sh --profile quick

# CI profile (deterministic)
./scripts/e2e/run_all.sh --profile ci

# Run specific suite
./scripts/e2e/run_all.sh --suite e2e_extension_registration

# Skip lint gates
./scripts/e2e/run_all.sh --skip-lint

# List available suites
./scripts/e2e/run_all.sh --list

# Rerun only failures from a previous run
./scripts/e2e/run_all.sh --rerun-from tests/e2e_results/<timestamp>/summary.json

# Compare against baseline
./scripts/e2e/run_all.sh --diff-from tests/e2e_results/<timestamp>/summary.json
```

### Profiles

| Profile | Scope | Use Case |
|---------|-------|----------|
| `full` | Lint + lib + all targets (unit, vcr, e2e) | Release verification |
| `quick` | Lint + lib + unit only | Fast local iteration |
| `focused` | Lint + lib + selected integration | Targeted debugging |
| `ci` | Lint + lib + all non-e2e + 1 e2e | CI pipeline |

## Multi-Agent Considerations

In environments where multiple agents work concurrently on the same
codebase:

1. **Isolate build artifacts**: Use `CARGO_TARGET_DIR=target-<agent-name>` to
   prevent build cache conflicts.

2. **Serial test execution**: Set `RUST_TEST_THREADS=1` to avoid filesystem
   contention in the VFS.

3. **Deterministic settings**: Always set `PI_TEST_MODE=1` and
   `PI_CONFORMANCE_SEED=42` for reproducible results.

4. **Check for compilation errors**: Other agents may modify shared files
   like `src/extensions.rs`. If compilation fails, pull latest changes and
   retry.
