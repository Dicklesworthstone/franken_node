# `tests/perf_beads/` — perf-bead test scripts

Per-bead test scripts under the **T15 cross-cutting test infrastructure**
of the bd-98xo5 performance optimization EPIC.

- Producer harness: [`scripts/run_perf_bead_test.sh`](../../scripts/run_perf_bead_test.sh) (bd-98xo5.15.1).
- Log schema: [`docs/dev/perf_bead_testing.md`](../../docs/dev/perf_bead_testing.md).
- Consumer / CI: [`scripts/render_perf_test_summary.py`](../../scripts/render_perf_test_summary.py)
  + [`.github/workflows/perf-bead-tests.yml`](../../.github/workflows/perf-bead-tests.yml) (bd-98xo5.15.2).
- Reference template: [`_template.sh`](_template.sh) (this directory).

## Naming convention

```
tests/perf_beads/bd-98xo5.X.tests.sh
```

The `.tests.sh` suffix is what `scripts/detect_affected_perf_beads.py`
expects when wiring a Tx.tests script into the CI matrix. If you ship
a new Tx.tests bead, also append a row to the `AFFECTED_MAP` in that
helper so a touching PR triggers your script.

## Authoring a new perf-bead test script

```bash
cp tests/perf_beads/_template.sh tests/perf_beads/bd-98xo5.X.tests.sh
chmod +x tests/perf_beads/bd-98xo5.X.tests.sh
```

Edit the copy:

1. Change `BEAD_ID="bd-98xo5.0.template"` to your bead id with the
   `.tests` suffix (e.g. `bd-98xo5.5.tests`).
2. Replace each phase block's cases with the ones that exercise your
   bead's optimised surface. The template ships with `build` / `unit`
   / `baseline`; add or drop phases as needed — the canonical order is
   `build → unit → property → fuzz → e2e → baseline → cleanup`.
3. Replace the Criterion `BENCH_BIN` path, `--bench` filter, metric
   name, and `BUDGET_NS` with the values that gate your bead's perf
   regression check.

## Required phases

Use whichever apply, **in this order**:

| phase      | purpose |
|------------|---------|
| `build`    | Build the optimised binary under `--profile release-perf` (see [`docs/dev/profiling.md`](../../docs/dev/profiling.md)). Required. |
| `unit`     | Narrow `cargo test` selectors that hit the optimised call sites. |
| `property` | `proptest` / `quickcheck` invariants over the optimised code. |
| `fuzz`     | `cargo +nightly fuzz run` smoke (small input budget, e.g. `-runs=5000`). |
| `e2e`      | Integration tests under `crates/franken-node/tests/` or `tests/e2e/`. |
| `baseline` | Re-run Criterion + compare measurements against the bead's perf budget. |
| `cleanup`  | Tear down any scratch state the script created. |

## Sourcing the harness

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/run_perf_bead_test.sh
source "${SCRIPT_DIR}/scripts/run_perf_bead_test.sh"
perf_test_init "bd-98xo5.X.tests"
```

After sourcing, nine functions are in scope (full reference:
[`docs/dev/perf_bead_testing.md`](../../docs/dev/perf_bead_testing.md#api-reference)).

- `perf_test_start <phase>` — emits `TEST-START`, resets counters.
- `perf_test_case <name>` — emits `TEST-CASE`, starts case timer.
- `perf_test_pass` — emits `TEST-PASS`, bumps phase passed count.
- `perf_test_fail <reason>` — emits `TEST-FAIL`, attaches `stderr_tail`.
- `perf_test_skip <reason>` — emits `TEST-SKIP`.
- `perf_test_measurement <metric> <value> <unit>` — emits `PERF-MEASUREMENT`.
- `perf_test_summary` — emits `TEST-SUMMARY`. Returns non-zero iff
  any TEST-FAIL was emitted in the phase — exit on non-zero in your
  script so a failure in `build` short-circuits the rest.
- `perf_test_run_cargo <args...>` — wraps `rch exec -- cargo <args>`
  with `BUILD-START` / `BUILD-DONE` brackets and stderr capture.
- `perf_test_hook_fired <hook> <detail>` — record an integrity hook
  fire (e.g. `ubs` flag, `cargo-deny` warning). Doesn't affect counts.

## Consuming the resulting log

Each `perf_test_init` call writes JSONL to:

```
tests/artifacts/perf/test_runs/<bead-id>_<timestamp>Z/test_log.jsonl
```

Render the log:

```bash
# Human table:
python3 scripts/render_perf_test_summary.py \
    tests/artifacts/perf/test_runs/bd-98xo5.X.tests_*/test_log.jsonl

# CI gate (exit 0 iff PASS):
python3 scripts/render_perf_test_summary.py --ci \
    tests/artifacts/perf/test_runs/bd-98xo5.X.tests_*/test_log.jsonl

# Machine-readable JSON:
python3 scripts/render_perf_test_summary.py --json \
    tests/artifacts/perf/test_runs/bd-98xo5.X.tests_*/test_log.jsonl

# Diff two runs:
python3 scripts/render_perf_test_summary.py --diff \
    tests/artifacts/perf/test_runs/<old>/test_log.jsonl \
    tests/artifacts/perf/test_runs/<new>/test_log.jsonl
```

Exit codes:

| code | meaning |
|------|---------|
| 0    | every phase TEST-SUMMARY had `failed=0` (verdict PASS) |
| 1    | at least one `TEST-FAIL` was emitted (verdict FAIL) |
| 2    | malformed JSONL / schema mismatch (missing field, unknown event_code, mismatched trace_id) |

## Out of scope (handled elsewhere)

- **Perf budget contract** is in [`bd-98xo5.13`](../../.beads/issues.jsonl)
  (`hot_path_perf_budget_contract` JSON), not in individual scripts.
- **Cross-track summary dashboards** are a separate ops concern; the
  JSONL files in `tests/artifacts/perf/test_runs/` are the canonical
  source.
