# Perf-bead testing harness

> Shared shell harness + log schema for the `bd-98xo5.*` performance
> optimisation bead test suites. Every `tests/perf_beads/*.sh` script
> must source `scripts/run_perf_bead_test.sh` and emit the canonical
> JSONL events documented below. The harness lives here so that
> per-bead test scripts stay one-shot and consumer tooling
> (`scripts/render_perf_test_summary.py` from
> [`bd-98xo5.15.2`](../../.beads/issues.jsonl), CI dashboards) can
> read every run with the same parser.

Tracking bead: [`bd-98xo5.15`](../../.beads/issues.jsonl) (parent EPIC
for cross-cutting test infrastructure).

## Why the harness exists

The `bd-98xo5` EPIC ships ~6 optimisation tracks (T1 threshold_sig
preparsed keys, T2 Ed25519Scheme preparsed handles, T4 trust_card
deep-clone removal, T5 DGIS NodeId interning, T6 replay_bundle byte
streaming, T7 fleet_transport canonicalize path-alloc cleanup). Each
ships an opt-test sub-bead (Tx.tests) that runs build, unit,
property, fuzz, and e2e phases against the optimised code.

If every Tx.tests script implements logging from scratch:

- formats drift (one script emits `event: PASS`, another emits
  `kind: pass`)
- the cross-track summary tool can't merge runs
- re-baseline comparisons against round-1 / round-2 numbers become
  impossible without bespoke parsers per bead

The shared harness pins **one** schema, **one** set of event codes,
and **one** consumer-side parser. Every Tx.tests script becomes a
shell file that sources `run_perf_bead_test.sh`, calls the API
documented below, and trusts the harness to produce compliant JSONL.

## Quick start

Authoring a new `tests/perf_beads/<bead-id>.sh`:

```bash
#!/usr/bin/env bash
# Tx.tests script for bd-98xo5.X.

set -uo pipefail
source "$(git rev-parse --show-toplevel)/scripts/run_perf_bead_test.sh"

perf_test_init "bd-98xo5.X.tests"

# Phase 1 — build the optimised binary.
perf_test_start "build"
perf_test_run_cargo build --profile release-perf \
    -p frankenengine-node --bench crypto_scheme_bench || {
    perf_test_summary
    exit 1
}
perf_test_summary || exit 1

# Phase 2 — unit tests.
perf_test_start "unit"
perf_test_case "preparsed_signer_byte_identical"
if rch exec -- cargo test -p frankenengine-node \
       crypto::schemes::tests::preparsed_signer_byte_identical >/dev/null 2>&1; then
    perf_test_pass
else
    perf_test_fail "preparsed signer signature drift vs stateless sign_raw"
fi
perf_test_summary || exit 1

# Phase 3 — Criterion re-baseline. Read the report.json and emit
# PERF-MEASUREMENT for every interesting metric.
perf_test_start "baseline"
perf_test_measurement "preparsed_sign_p95_us" "26.0" "microseconds"
perf_test_measurement "wrapper_overhead_pct" "8.7" "percent"
perf_test_summary || exit 1
```

That script writes JSONL to
`tests/artifacts/perf/test_runs/bd-98xo5.X.tests_<timestamp>/test_log.jsonl`
and exits non-zero if any phase had failures.

## Log schema

Every line in `test_log.jsonl` is one JSON object:

```json
{
  "timestamp": "2026-05-21T05:42:31.118Z",
  "level": "info",
  "event_code": "TEST-PASS",
  "bead_id": "bd-98xo5.X.tests",
  "trace_id": "<uuid>",
  "phase": "unit",
  "test_name": "preparsed_signer_byte_identical",
  "duration_ms": 142,
  "extra": {}
}
```

Field semantics:

| field | type | semantics |
|---|---|---|
| `timestamp` | string (RFC 3339 + millis) | UTC, millisecond precision. Format: `YYYY-MM-DDTHH:MM:SS.sssZ`. |
| `level` | `"info" \| "warn" \| "error"` | Severity for human / log-aggregator filtering. `error` only on TEST-FAIL. |
| `event_code` | string (enum below) | Stable code identifying the event class. New codes require an RFC + a CHANGELOG entry. |
| `bead_id` | string | Caller bead. Always `bd-98xo5.X.tests` for opt-test sub-beads. |
| `trace_id` | string | Per-run UUID (uuidgen) or sha256(pid+ns) fallback. Same value for every line of a single run. |
| `phase` | string | One of `build / unit / property / fuzz / e2e / baseline / cleanup`. Set by `perf_test_start`. |
| `test_name` | string \| null | Set by `perf_test_case` / `perf_test_measurement`; null on TEST-START / TEST-SUMMARY. |
| `duration_ms` | integer | Wall-time. 0 on TEST-START / TEST-CASE / PERF-MEASUREMENT (no duration to measure yet). |
| `extra` | object | Event-specific payload — see per-code table below. Always a JSON object, possibly empty (`{}`). |

### Event codes (stable enum)

| code | when | `extra` fields |
|---|---|---|
| `TEST-START` | `perf_test_start <phase>` | `{}` (the phase is in the top-level `phase` field). |
| `TEST-CASE` | `perf_test_case <name>` | `{}`. |
| `TEST-PASS` | `perf_test_pass` (implicit-current-case) | `{}`. `duration_ms` is wall-time of the case. |
| `TEST-FAIL` | `perf_test_fail <reason>` | `failure_reason` (string), `stderr_tail` (string, last 20 lines captured via `perf_test_run_cargo`). |
| `TEST-SKIP` | `perf_test_skip <reason>` | `skip_reason` (string). |
| `TEST-SUMMARY` | `perf_test_summary` (end of phase) | `passed` / `failed` / `skipped` / `total` (integers). Returns non-zero iff any TEST-FAIL was emitted in the phase. |
| `PERF-MEASUREMENT` | `perf_test_measurement <metric> <value> <unit>` | `metric` (string), `value` (number — JSON-numeric), `unit` (string). |
| `BUILD-START` | `perf_test_run_cargo <args...>` (entry) | `{}`. `test_name` is the full `cargo <args>` text. |
| `BUILD-DONE` | `perf_test_run_cargo <args...>` (exit) | `exit_code` (integer). `duration_ms` is the cargo wall-time. |
| `HOOK-FIRED` | `perf_test_hook_fired <hook> <detail>` | `hook` (string), `detail` (string). For integrity hooks that fire mid-run (e.g. `ubs` flagged a regression). |

### Output streams

The harness writes to **both**:

1. **`$PERF_TEST_LOG`** — `tests/artifacts/perf/test_runs/<bead-id>_<ts>/test_log.jsonl`. One JSON object per line, no ANSI codes. This is the file `render_perf_test_summary.py` and the CI gate read.

2. **stdout** — pretty-printed, ANSI-coloured (✓ green on PASS, ✗ red on FAIL, durations dim-grey). Set `NO_COLOR=1` to strip ANSI. Stdout is for human eyeballs during interactive runs; the JSONL file is the ground truth.

### Run-id directory layout

```
tests/artifacts/perf/test_runs/
└── bd-98xo5.X.tests_20260521T054231Z/
    └── test_log.jsonl
```

`render_perf_test_summary.py` (`bd-98xo5.15.2`) walks this tree and
produces a single-table summary across all sibling runs.

## API reference

The harness exposes nine functions on the caller's shell namespace
once sourced:

| function | semantics |
|---|---|
| `perf_test_init <bead-id>` | Set `PERF_TEST_BEAD_ID`, derive `PERF_TEST_TRACE_ID` (uuidgen or fallback), create the run-id directory, truncate the JSONL log, reset per-phase counters. Call once at the top of the Tx.tests script. |
| `perf_test_start <phase>` | Begin a new phase (`build` / `unit` / etc.). Resets per-phase passed/failed/skipped counters. Emits `TEST-START`. |
| `perf_test_case <name>` | Begin a test case. Records start time so `perf_test_pass` / `perf_test_fail` can compute `duration_ms`. Emits `TEST-CASE`. |
| `perf_test_pass` | Mark the current case as passed. Bumps `passed`. Emits `TEST-PASS`. |
| `perf_test_fail <reason>` | Mark the current case as failed. Bumps `failed`. Emits `TEST-FAIL` with the reason + a tail of any stderr captured by the most recent `perf_test_run_cargo`. |
| `perf_test_skip <reason>` | Skip the current case (e.g. infra missing). Bumps `skipped`. Emits `TEST-SKIP`. |
| `perf_test_measurement <metric> <value> <unit>` | Record a quantitative reading during a test. Emits `PERF-MEASUREMENT`. |
| `perf_test_summary` | End the current phase. Emits `TEST-SUMMARY`. Returns non-zero iff any TEST-FAIL was emitted in this phase — exit on non-zero in your Tx.tests script. |
| `perf_test_run_cargo <args...>` | Wrap `rch exec -- cargo <args>`. Brackets the invocation with `BUILD-START` / `BUILD-DONE`. Captures stderr into a temp file so `perf_test_fail` can attach `stderr_tail`. Returns the cargo exit code unchanged. |
| `perf_test_hook_fired <hook> <detail>` | Emit `HOOK-FIRED` for an integrity hook (e.g. `ubs` flag, `cargo-deny` warning). Doesn't affect pass/fail counters. |

## Consuming a finished run

`scripts/render_perf_test_summary.py` (shipped by
[`bd-98xo5.15.2`](../../.beads/issues.jsonl)) reads the JSONL file
and prints a per-phase table:

```
$ python3 scripts/render_perf_test_summary.py \
    tests/artifacts/perf/test_runs/bd-98xo5.X.tests_20260521T054231Z/test_log.jsonl

bd-98xo5.X.tests — 2026-05-21T05:42:31Z — trace 7e0a3f...
┌──────────┬────────┬────────┬─────────┬──────────┐
│ phase    │ passed │ failed │ skipped │ duration │
├──────────┼────────┼────────┼─────────┼──────────┤
│ build    │      1 │      0 │       0 │  6m 04s  │
│ unit     │     12 │      0 │       0 │    142ms │
│ baseline │      0 │      0 │       0 │      8ms │
└──────────┴────────┴────────┴─────────┴──────────┘
PERF measurements:
  preparsed_sign_p95_us       = 26.0   microseconds
  wrapper_overhead_pct        =  8.7   percent
```

For ad-hoc inspection without the renderer, `jq` works on the raw
file:

```bash
# All fails across the run:
jq -c 'select(.event_code == "TEST-FAIL") | {phase, test_name, extra}' test_log.jsonl

# All measurements with their metric/value/unit:
jq -c 'select(.event_code == "PERF-MEASUREMENT") | .extra' test_log.jsonl

# Per-phase wall time:
jq -c 'select(.event_code == "TEST-SUMMARY") | {phase, ms: .duration_ms}' test_log.jsonl
```

## Troubleshooting

**The JSONL is missing a key on some lines.** Every line must have
every top-level field even when not relevant — `test_name` defaults
to literal `null` (not omitted), `extra` defaults to `{}` (not
omitted). If a custom event-emission site is bypassing `_perf_emit`,
fix it: only `_perf_emit` knows the schema.

**A failure reason has unescaped quotes / newlines.** Pass the raw
reason to `perf_test_fail` as-is; the harness's `_perf_escape_json_str`
handles `\`, `"`, `\n`, `\r`, `\t`, `\b`, `\f`. If your reason
contains other non-printable bytes, the JSON spec allows them via
`\uXXXX` — open a follow-on bead if you need that.

**`uuidgen` not on PATH.** The harness falls back to
`sha256sum(pid + nanosecond)` for the trace_id. Both forms are
acceptable to consumers (the trace_id is opaque — only equality
across lines of one run matters).

**`date +%N` printed `N` literally.** You're on a BSD / musl host
where `date` doesn't grok `%N`. The harness detects this and falls
back to `.000Z` millisecond precision. Time-resolution loss only
shows up if you have multiple cases finish within the same second;
on Linux+GNU it's full ms.

**Stdout is full of ANSI escape codes in a CI log.** Set `NO_COLOR=1`
in the workflow environment. The JSONL file is ANSI-free regardless.

## Out of scope (handled elsewhere)

- **Prometheus exporter.** The harness writes JSONL; if a production
  system needs Prometheus metrics, that's [`T13`](../../.beads/issues.jsonl)
  (perf-budget contract update), not T15.
- **Web UI to browse runs.** `render_perf_test_summary.py` + `jq`
  cover the CLI side. A web UI would be a separate ops concern.
- **Hooking into individual Tx tests.** Per-track test content lives
  in `tests/perf_beads/bd-98xo5.X.sh`; this doc describes the
  harness those scripts call, not the per-track test plans.

## Forward references

- [`bd-98xo5.15.2`](../../.beads/issues.jsonl) — `scripts/render_perf_test_summary.py` + the CI workflow that gates PRs on the JSONL output.
- [`bd-98xo5.15.3`](../../.beads/issues.jsonl) — Reference template at `tests/perf_beads/_template.sh` so new Tx.tests scripts have a starting point.
