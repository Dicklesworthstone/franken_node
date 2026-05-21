#!/usr/bin/env python3
"""Render a `tests/artifacts/perf/test_runs/<run>/test_log.jsonl` log.

Consumer side of the T15 perf-bead test harness (bd-98xo5.15.2). Reads
the canonical JSONL produced by `scripts/run_perf_bead_test.sh` (see
`docs/dev/perf_bead_testing.md` for the schema) and renders a single
summary across all `TEST-SUMMARY` events in the log.

Modes:
  render_perf_test_summary.py <test_log.jsonl>       # human table
  render_perf_test_summary.py --json <log>           # machine output
  render_perf_test_summary.py --ci <log>             # exit 0 iff PASS
  render_perf_test_summary.py --diff <old> <new>     # cross-run delta

Exit codes:
  0  every phase TEST-SUMMARY had failed=0
  1  at least one TEST-FAIL was emitted in the log
  2  malformed JSONL or schema mismatch (e.g. missing required key,
     duplicate trace_id across lines, unknown event_code)

The renderer is intentionally schema-strict: any line that lacks a
required top-level field (`timestamp`, `level`, `event_code`,
`bead_id`, `trace_id`, `phase`, `test_name`, `duration_ms`, `extra`)
counts as a schema mismatch. The shell producer emits all nine fields
on every line (see `_perf_emit` in `scripts/run_perf_bead_test.sh`),
so a missing key indicates either a non-harness producer or a
truncated file — both worth failing on.

Author: SilentCompass (bd-98xo5.15.2, parent: bd-98xo5.15).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REQUIRED_FIELDS: tuple[str, ...] = (
    "timestamp",
    "level",
    "event_code",
    "bead_id",
    "trace_id",
    "phase",
    "test_name",
    "duration_ms",
    "extra",
)

KNOWN_EVENT_CODES: frozenset[str] = frozenset(
    {
        "TEST-START",
        "TEST-CASE",
        "TEST-PASS",
        "TEST-FAIL",
        "TEST-SKIP",
        "TEST-SUMMARY",
        "PERF-MEASUREMENT",
        "BUILD-START",
        "BUILD-DONE",
        "HOOK-FIRED",
    }
)


@dataclass
class PhaseRow:
    phase: str
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    total: int = 0
    duration_ms: int = 0


@dataclass
class Measurement:
    metric: str
    value: float
    unit: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedRun:
    bead_id: str
    trace_id: str
    started_at: str
    phases: list[PhaseRow]
    measurements: list[Measurement]
    any_test_fail: bool
    hooks_fired: list[dict[str, Any]]


class SchemaError(Exception):
    """Raised when the JSONL log violates the harness schema."""


def parse_log(path: Path) -> ParsedRun:
    """Parse a single test_log.jsonl into a ParsedRun.

    Raises SchemaError on any structural problem (missing field,
    unknown event_code, mismatched trace_id, etc.).
    """
    if not path.exists():
        raise SchemaError(f"log file does not exist: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaError(f"could not read {path}: {exc}") from exc

    phases: dict[str, PhaseRow] = {}
    phase_order: list[str] = []
    measurements: list[Measurement] = []
    hooks_fired: list[dict[str, Any]] = []
    bead_id: str | None = None
    trace_id: str | None = None
    started_at: str | None = None
    any_test_fail = False

    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"line {lineno}: not valid JSON: {exc}") from exc
        if not isinstance(evt, dict):
            raise SchemaError(f"line {lineno}: expected JSON object, got {type(evt).__name__}")
        missing = [k for k in REQUIRED_FIELDS if k not in evt]
        if missing:
            raise SchemaError(f"line {lineno}: missing required fields {missing}")
        code = evt["event_code"]
        if code not in KNOWN_EVENT_CODES:
            raise SchemaError(f"line {lineno}: unknown event_code {code!r}")
        extra = evt["extra"]
        if not isinstance(extra, dict):
            raise SchemaError(f"line {lineno}: extra must be an object, got {type(extra).__name__}")

        if bead_id is None:
            bead_id = evt["bead_id"]
            trace_id = evt["trace_id"]
            started_at = evt["timestamp"]
        else:
            if evt["trace_id"] != trace_id:
                raise SchemaError(
                    f"line {lineno}: trace_id {evt['trace_id']!r} differs from run trace {trace_id!r}"
                )

        phase = evt["phase"]
        if code == "TEST-START":
            if phase not in phases:
                phases[phase] = PhaseRow(phase=phase)
                phase_order.append(phase)
        elif code == "TEST-PASS":
            row = _phase_row(phases, phase_order, phase)
            row.passed += 1
        elif code == "TEST-FAIL":
            row = _phase_row(phases, phase_order, phase)
            row.failed += 1
            any_test_fail = True
        elif code == "TEST-SKIP":
            row = _phase_row(phases, phase_order, phase)
            row.skipped += 1
        elif code == "TEST-SUMMARY":
            row = _phase_row(phases, phase_order, phase)
            row.duration_ms = int(evt["duration_ms"])
            try:
                row.total = int(extra.get("total", row.passed + row.failed + row.skipped))
            except (TypeError, ValueError) as exc:
                raise SchemaError(f"line {lineno}: TEST-SUMMARY total not an int: {exc}") from exc
        elif code == "PERF-MEASUREMENT":
            metric = extra.get("metric")
            value = extra.get("value")
            unit = extra.get("unit")
            if not isinstance(metric, str) or not isinstance(unit, str):
                raise SchemaError(
                    f"line {lineno}: PERF-MEASUREMENT extra.metric/unit must be strings"
                )
            if not isinstance(value, (int, float)):
                raise SchemaError(
                    f"line {lineno}: PERF-MEASUREMENT extra.value must be a number, got {value!r}"
                )
            decoration = {k: v for k, v in extra.items() if k not in {"metric", "value", "unit"}}
            measurements.append(Measurement(metric=metric, value=float(value), unit=unit, extra=decoration))
        elif code == "HOOK-FIRED":
            hooks_fired.append(
                {
                    "hook": extra.get("hook"),
                    "detail": extra.get("detail"),
                    "phase": phase,
                    "timestamp": evt["timestamp"],
                }
            )
        # TEST-CASE / BUILD-START / BUILD-DONE: tracked implicitly via duration columns.

    if bead_id is None or trace_id is None or started_at is None:
        raise SchemaError(f"log {path} is empty (no events)")

    phase_rows = [phases[name] for name in phase_order]
    for row in phase_rows:
        if row.total == 0:
            row.total = row.passed + row.failed + row.skipped

    return ParsedRun(
        bead_id=bead_id,
        trace_id=trace_id,
        started_at=started_at,
        phases=phase_rows,
        measurements=measurements,
        any_test_fail=any_test_fail,
        hooks_fired=hooks_fired,
    )


def _phase_row(phases: dict[str, PhaseRow], phase_order: list[str], phase: str) -> PhaseRow:
    if phase not in phases:
        phases[phase] = PhaseRow(phase=phase)
        phase_order.append(phase)
    return phases[phase]


def _fmt_duration(ms: int) -> str:
    """Format milliseconds as 'M:SS m' once we cross a second, else 'XXX ms'."""
    if ms < 1000:
        return f"{ms} ms"
    total_sec = ms // 1000
    minutes = total_sec // 60
    seconds = total_sec % 60
    return f"{minutes}:{seconds:02d} m"


def render_human(run: ParsedRun) -> str:
    """Pretty human-readable summary."""
    lines: list[str] = []
    short_trace = run.trace_id[:8] if len(run.trace_id) >= 8 else run.trace_id
    lines.append(f"{run.bead_id}   run {run.started_at}   trace {short_trace}")
    sep = "─" * 64
    lines.append(sep)
    header = f"{'phase':<11}{'cases':>6}  {'pass':>5}  {'fail':>5}  {'skip':>5}  {'duration':>10}"
    lines.append(header)
    lines.append(sep)
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_cases = 0
    total_ms = 0
    for row in run.phases:
        lines.append(
            f"{row.phase:<11}{row.total:>6}  {row.passed:>5}  {row.failed:>5}  {row.skipped:>5}  {_fmt_duration(row.duration_ms):>10}"
        )
        total_passed += row.passed
        total_failed += row.failed
        total_skipped += row.skipped
        total_cases += row.total
        total_ms += row.duration_ms
    lines.append(sep)
    verdict = "PASS" if total_failed == 0 and not run.any_test_fail else "FAIL"
    marker = "✓" if verdict == "PASS" else "✗"
    lines.append(
        f"{'TOTAL':<11}{total_cases:>6}  {total_passed:>5}  {total_failed:>5}  {total_skipped:>5}  "
        f"{_fmt_duration(total_ms):>10}   {marker} {verdict}"
    )

    if run.measurements:
        lines.append("")
        lines.append("Measurements:")
        for m in run.measurements:
            decoration = _render_measurement_extras(m)
            lines.append(f"  {m.metric} = {_fmt_value(m.value)} {m.unit}{decoration}")

    if run.hooks_fired:
        lines.append("")
        lines.append("Hooks fired:")
        for hook in run.hooks_fired:
            lines.append(
                f"  [{hook['phase']}] {hook['hook']} — {hook['detail']} @ {hook['timestamp']}"
            )

    return "\n".join(lines)


def _fmt_value(v: float) -> str:
    if v == int(v):
        return f"{int(v)}"
    if abs(v) >= 1000:
        return f"{v:.0f}"
    if abs(v) >= 10:
        return f"{v:.2f}"
    return f"{v:.3f}"


def _render_measurement_extras(m: Measurement) -> str:
    """If the extra payload carries known hints (target/baseline/delta), append them."""
    parts: list[str] = []
    target = m.extra.get("target")
    if isinstance(target, (int, float)):
        parts.append(f"target ≤ {_fmt_value(float(target))}")
    baseline = m.extra.get("baseline")
    if isinstance(baseline, (int, float)):
        parts.append(f"baseline {_fmt_value(float(baseline))}")
        if baseline != 0:
            delta_pct = ((m.value - float(baseline)) / float(baseline)) * 100.0
            parts.append(f"Δ {delta_pct:+.1f} %")
    note = m.extra.get("note")
    if isinstance(note, str) and note:
        parts.append(note)
    if not parts:
        return ""
    return "  (" + ", ".join(parts) + ")"


def render_json(run: ParsedRun) -> str:
    """Machine-readable JSON of the parsed run."""
    payload = {
        "bead_id": run.bead_id,
        "trace_id": run.trace_id,
        "started_at": run.started_at,
        "verdict": "PASS" if not run.any_test_fail else "FAIL",
        "phases": [
            {
                "phase": p.phase,
                "passed": p.passed,
                "failed": p.failed,
                "skipped": p.skipped,
                "total": p.total,
                "duration_ms": p.duration_ms,
            }
            for p in run.phases
        ],
        "measurements": [
            {
                "metric": m.metric,
                "value": m.value,
                "unit": m.unit,
                "extra": m.extra,
            }
            for m in run.measurements
        ],
        "hooks_fired": run.hooks_fired,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_diff(old: ParsedRun, new: ParsedRun) -> str:
    """Cross-run delta of per-metric values and per-phase wall-times."""
    lines: list[str] = []
    lines.append(f"diff: {old.bead_id} ({old.trace_id[:8]}) → {new.bead_id} ({new.trace_id[:8]})")
    lines.append("─" * 64)

    old_phases = {p.phase: p for p in old.phases}
    new_phases = {p.phase: p for p in new.phases}
    phase_keys = list(dict.fromkeys(list(old_phases) + list(new_phases)))
    lines.append("Phases (duration ms, then passed/failed counts):")
    for phase in phase_keys:
        op = old_phases.get(phase)
        np_ = new_phases.get(phase)
        if op is None:
            lines.append(
                f"  + {phase}: new ({np_.duration_ms} ms, {np_.passed}p/{np_.failed}f/{np_.skipped}s)"
            )
        elif np_ is None:
            lines.append(
                f"  - {phase}: gone (was {op.duration_ms} ms, {op.passed}p/{op.failed}f/{op.skipped}s)"
            )
        else:
            d_dur = np_.duration_ms - op.duration_ms
            d_fail = np_.failed - op.failed
            lines.append(
                f"    {phase}: {op.duration_ms} → {np_.duration_ms} ms (Δ {d_dur:+d}); "
                f"failed {op.failed} → {np_.failed} (Δ {d_fail:+d})"
            )

    old_metrics = {m.metric: m for m in old.measurements}
    new_metrics = {m.metric: m for m in new.measurements}
    keys = list(dict.fromkeys(list(old_metrics) + list(new_metrics)))
    if keys:
        lines.append("")
        lines.append("Measurements:")
        for metric in keys:
            om = old_metrics.get(metric)
            nm = new_metrics.get(metric)
            if om is None:
                lines.append(f"  + {metric} = {_fmt_value(nm.value)} {nm.unit} (new)")
            elif nm is None:
                lines.append(f"  - {metric} = {_fmt_value(om.value)} {om.unit} (gone)")
            else:
                if om.unit != nm.unit:
                    lines.append(
                        f"  ! {metric}: unit changed {om.unit!r} → {nm.unit!r} "
                        f"({_fmt_value(om.value)} → {_fmt_value(nm.value)})"
                    )
                    continue
                if om.value == 0:
                    delta_pct_str = "n/a"
                else:
                    delta_pct = ((nm.value - om.value) / om.value) * 100.0
                    delta_pct_str = f"{delta_pct:+.1f} %"
                lines.append(
                    f"    {metric}: {_fmt_value(om.value)} → {_fmt_value(nm.value)} {nm.unit} "
                    f"(Δ {delta_pct_str})"
                )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    group.add_argument("--ci", action="store_true", help="exit 0 iff PASS, suppress table output")
    group.add_argument("--diff", action="store_true", help="diff two runs: pass two paths")
    parser.add_argument(
        "logs",
        type=Path,
        nargs="+",
        help="path(s) to test_log.jsonl (one for default/--json/--ci, two for --diff)",
    )
    args = parser.parse_args(argv)

    if args.diff:
        if len(args.logs) != 2:
            print("error: --diff requires exactly two log paths (old, new)", file=sys.stderr)
            return 2
        try:
            old = parse_log(args.logs[0])
            new = parse_log(args.logs[1])
        except SchemaError as exc:
            print(f"schema error: {exc}", file=sys.stderr)
            return 2
        print(render_diff(old, new))
        # diff is informational; exit 0 unless either side is a FAIL.
        return 0 if not (old.any_test_fail or new.any_test_fail) else 1

    if len(args.logs) != 1:
        print(
            "error: pass exactly one log path (use --diff for cross-run delta)",
            file=sys.stderr,
        )
        return 2
    try:
        run = parse_log(args.logs[0])
    except SchemaError as exc:
        print(f"schema error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(run))
    elif args.ci:
        verdict = "PASS" if not run.any_test_fail else "FAIL"
        print(f"{run.bead_id}: {verdict}")
    else:
        print(render_human(run))

    return 0 if not run.any_test_fail else 1


if __name__ == "__main__":
    sys.exit(main())
