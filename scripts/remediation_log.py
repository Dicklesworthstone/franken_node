#!/usr/bin/env python3
"""Shared remediation logging for verification-scaffolding integrity (bd-rjc2m.A).

One JSONL record per verification target, consumed by:
  - scripts/check_verification_targets_compile.py  (the .G1 recurrence-prevention gate)
  - scripts/verify_all_verification_targets.sh      (the .E2E1 e2e acceptance gate)

Design goals: a single canonical, validated record shape + a human-readable summary so
every remediation run produces consistent, greppable, detailed logs.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict, field
from typing import Iterable, List, Optional

SCHEMA_VERSION = "remediation-log-v1"
LAYERS = ("conformance", "fuzz", "sdk")


@dataclass
class RemediationRecord:
    """One verification target's remediation/verification result."""

    target: str
    layer: str
    ts_rfc3339: str
    compiles: bool
    ran: bool = False
    errors_before: Optional[int] = None
    errors_after: int = 0
    tests_run: int = 0
    tests_passed: int = 0
    assertions_preserved: bool = True
    crashed: bool = False
    duration_ms: int = 0
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    def validate(self) -> List[str]:
        """Return a list of validation errors (empty == valid)."""
        errs: List[str] = []
        if not self.target:
            errs.append("target must be non-empty")
        if self.layer not in LAYERS:
            errs.append(f"layer must be one of {LAYERS}, got {self.layer!r}")
        if not self.ts_rfc3339:
            errs.append("ts_rfc3339 must be non-empty")
        if self.errors_after < 0 or self.tests_run < 0 or self.tests_passed < 0:
            errs.append("counts must be non-negative")
        if self.tests_passed > self.tests_run:
            errs.append("tests_passed cannot exceed tests_run")
        if self.duration_ms < 0:
            errs.append("duration_ms must be non-negative")
        # A target that 'ran' green must compile and have zero residual errors.
        if self.ran and not self.compiles:
            errs.append("ran=True requires compiles=True")
        if self.ran and self.errors_after != 0:
            errs.append("ran=True requires errors_after==0")
        return errs

    def is_green(self) -> bool:
        """True iff this target fully recovered: compiles, ran, zero failures/crash, assertions kept."""
        return (
            self.compiles
            and self.ran
            and self.errors_after == 0
            and not self.crashed
            and self.tests_passed == self.tests_run
            and self.assertions_preserved
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def write_jsonl(records: Iterable[RemediationRecord], path: str) -> int:
    """Write records as JSONL; returns count. Validates each first (raises on invalid)."""
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            errs = r.validate()
            if errs:
                raise ValueError(f"invalid record for {r.target!r}: {errs}")
            fh.write(r.to_json() + "\n")
            n += 1
    return n


def read_jsonl(path: str) -> List[RemediationRecord]:
    out: List[RemediationRecord] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            d.pop("schema_version", None)
            out.append(RemediationRecord(**d))
    return out


def render_summary(records: List[RemediationRecord]) -> str:
    """Human-readable summary table + totals; the operator-facing view."""
    total = len(records)
    green = sum(1 for r in records if r.is_green())
    by_layer: dict = {}
    for r in records:
        s = by_layer.setdefault(r.layer, [0, 0])
        s[0] += 1
        if r.is_green():
            s[1] += 1
    lines = [
        f"# Verification remediation summary ({SCHEMA_VERSION})",
        f"GREEN: {green}/{total} targets",
        "",
        "| layer | green / total |",
        "|---|---|",
    ]
    for layer in LAYERS:
        if layer in by_layer:
            t, g = by_layer[layer][0], by_layer[layer][1]
            lines.append(f"| {layer} | {g} / {t} |")
    reds = [r for r in records if not r.is_green()]
    if reds:
        lines += ["", "## RED targets", "| target | layer | compiles | ran | errs | tests | crash | assert |", "|---|---|---|---|---|---|---|---|"]
        for r in reds:
            lines.append(
                f"| {r.target} | {r.layer} | {r.compiles} | {r.ran} | {r.errors_after} "
                f"| {r.tests_passed}/{r.tests_run} | {r.crashed} | {r.assertions_preserved} |"
            )
    return "\n".join(lines) + "\n"


def all_green(records: List[RemediationRecord]) -> bool:
    return bool(records) and all(r.is_green() for r in records)


if __name__ == "__main__":
    # Render a summary for a JSONL file passed as argv[1]; exit non-zero if any RED.
    if len(sys.argv) != 2:
        print("usage: remediation_log.py <records.jsonl>", file=sys.stderr)
        sys.exit(2)
    recs = read_jsonl(sys.argv[1])
    sys.stdout.write(render_summary(recs))
    sys.exit(0 if all_green(recs) else 1)
