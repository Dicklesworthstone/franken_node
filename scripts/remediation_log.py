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
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional

SCHEMA_VERSION = "remediation-log-v1"
COMMAND_RECEIPT_SCHEMA_VERSION = "verification-command-receipt-v1"
LAYERS = ("conformance", "fuzz", "sdk")
COMMAND_PARSED_STATUSES = (
    "passed",
    "parsed_failure",
    "cargo_abort",
    "command_failed",
    "not_parsed",
    "unknown",
)


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


@dataclass
class CommandReceipt:
    """One top-level verification command execution receipt."""

    step_id: str
    command_digest: str
    exit_code: int
    duration_ms: int
    log_path: str
    parsed_status: str
    ts_rfc3339: str
    label: str = ""
    command: str = ""
    schema_version: str = COMMAND_RECEIPT_SCHEMA_VERSION

    def validate(self) -> List[str]:
        errs: List[str] = []
        if not self.step_id:
            errs.append("step_id must be non-empty")
        digest = self.command_digest.removeprefix("sha256:")
        if (
            not self.command_digest.startswith("sha256:")
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            errs.append("command_digest must be sha256:<64 hex chars>")
        if self.exit_code < 0:
            errs.append("exit_code must be non-negative")
        if self.duration_ms < 0:
            errs.append("duration_ms must be non-negative")
        if not self.log_path:
            errs.append("log_path must be non-empty")
        if self.parsed_status not in COMMAND_PARSED_STATUSES:
            errs.append(f"parsed_status must be one of {COMMAND_PARSED_STATUSES}, got {self.parsed_status!r}")
        if not self.ts_rfc3339:
            errs.append("ts_rfc3339 must be non-empty")
        return errs

    def command_succeeded(self) -> bool:
        return self.exit_code == 0

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


def write_command_receipts(records: Iterable[CommandReceipt], path: str) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            errs = r.validate()
            if errs:
                raise ValueError(f"invalid command receipt for {r.step_id!r}: {errs}")
            fh.write(r.to_json() + "\n")
            n += 1
    return n


def read_command_receipts(path: str) -> List[CommandReceipt]:
    out: List[CommandReceipt] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            d.pop("schema_version", None)
            receipt = CommandReceipt(**d)
            errs = receipt.validate()
            if errs:
                raise ValueError(f"invalid command receipt for {receipt.step_id!r}: {errs}")
            out.append(receipt)
    return out


def parsed_status_for_records(records: List[RemediationRecord], exit_code: Optional[int] = None) -> str:
    if any(r.target.endswith("_cargo_test_abort") for r in records):
        return "cargo_abort"
    if records:
        return "passed" if all(r.is_green() for r in records) else "parsed_failure"
    if exit_code is not None and exit_code != 0:
        return "command_failed"
    return "not_parsed"


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


def render_command_summary(records: List[CommandReceipt]) -> str:
    """Human-readable command receipt summary for the final verification report."""
    total = len(records)
    succeeded = sum(1 for r in records if r.command_succeeded())
    lines = [
        f"## Command receipts ({COMMAND_RECEIPT_SCHEMA_VERSION})",
        f"EXIT-0: {succeeded}/{total} commands",
        "",
        "| step | parsed_status | exit_code | duration_ms | log_path | command_digest |",
        "|---|---|---|---:|---|---|",
    ]
    for r in records:
        lines.append(
            f"| {r.step_id} | {r.parsed_status} | {r.exit_code} | {r.duration_ms} "
            f"| {r.log_path} | {r.command_digest} |"
        )

    command_failures = [
        r for r in records if r.exit_code != 0 and r.parsed_status not in ("parsed_failure", "cargo_abort")
    ]
    parsed_failures = [r for r in records if r.parsed_status == "parsed_failure"]
    cargo_aborts = [r for r in records if r.parsed_status == "cargo_abort"]

    if command_failures:
        lines += ["", "### Command failures", "| step | exit_code | parsed_status | log_path |", "|---|---:|---|---|"]
        for r in command_failures:
            lines.append(f"| {r.step_id} | {r.exit_code} | {r.parsed_status} | {r.log_path} |")
    if parsed_failures:
        lines += ["", "### Parsed verification failures", "| step | exit_code | log_path |", "|---|---:|---|"]
        for r in parsed_failures:
            lines.append(f"| {r.step_id} | {r.exit_code} | {r.log_path} |")
    if cargo_aborts:
        lines += ["", "### Cargo aborts", "| step | exit_code | log_path |", "|---|---:|---|"]
        for r in cargo_aborts:
            lines.append(f"| {r.step_id} | {r.exit_code} | {r.log_path} |")
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
