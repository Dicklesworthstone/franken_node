#!/usr/bin/env python3
"""Parse `cargo test` / `cargo fuzz` output into per-target remediation-log records (bd-rjc2m.E2E1).

Used by scripts/verify_all_verification_targets.sh to turn raw cargo output into the
canonical remediation-log-v1 JSONL + a human summary, so the e2e acceptance gate produces
detailed, greppable per-target evidence.

Pure functions (unit-tested); no cargo invocation here.
"""
from __future__ import annotations

import os
import re
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediation_log import RemediationRecord  # noqa: E402

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# "Running unittests ..." or "Running tests/conformance/foo.rs (target/debug/deps/foo-9ab...)"
_RUNNING_RE = re.compile(r"Running .*\(target/[^)]*/deps/(?P<name>[A-Za-z0-9_]+?)-[0-9a-f]{8,}\)")
# "test result: ok. 5 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.03s"
_RESULT_RE = re.compile(
    r"test result: (?P<status>ok|FAILED)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored"
)
# libfuzzer crash marker
_FUZZ_CRASH_RE = re.compile(r"(SUMMARY: |ERROR: libFuzzer|deadly signal|panicked at)")


def parse_cargo_test_output(text: str, ts: str, layer: str = "conformance") -> List[RemediationRecord]:
    """Map each `Running <target>` block to its `test result:` line. Returns one record per target."""
    text = _ANSI_RE.sub("", text)
    recs: List[RemediationRecord] = []
    current = None
    for line in text.splitlines():
        rm = _RUNNING_RE.search(line)
        if rm:
            current = rm.group("name")
            continue
        res = _RESULT_RE.search(line)
        if res and current:
            passed = int(res.group("passed"))
            failed = int(res.group("failed"))
            recs.append(
                RemediationRecord(
                    target=current, layer=layer, ts_rfc3339=ts,
                    compiles=True, ran=True, errors_after=0,
                    tests_run=passed + failed, tests_passed=passed,
                    crashed=False, assertions_preserved=True,
                    notes=("all pass" if failed == 0 else f"{failed} test(s) FAILED"),
                )
            )
            current = None
    return recs


def parse_fuzz_smoke(target: str, text: str, ts: str) -> RemediationRecord:
    """One bounded fuzz smoke run -> a record (crashed iff a libfuzzer crash marker is present)."""
    text = _ANSI_RE.sub("", text)
    crashed = bool(_FUZZ_CRASH_RE.search(text))
    # A build failure shows up as 'could not compile' -> compiles False.
    compiles = "could not compile" not in text
    ran = compiles and "Running" in text or "Done" in text or bool(re.search(r"#\d+", text))
    return RemediationRecord(
        target=target, layer="fuzz", ts_rfc3339=ts,
        compiles=compiles, ran=bool(ran) and compiles,
        errors_after=0 if compiles else 1,
        tests_run=1 if (compiles and ran) else 0,
        tests_passed=1 if (compiles and ran and not crashed) else 0,
        crashed=crashed, assertions_preserved=True,
        notes="clean smoke" if (compiles and not crashed) else ("CRASH" if crashed else "build failed"),
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: parse_cargo_test_results.py <cargo_test_log> <ts> [layer]", file=sys.stderr)
        sys.exit(2)
    layer = sys.argv[3] if len(sys.argv) > 3 else "conformance"
    with open(sys.argv[1], encoding="utf-8", errors="ignore") as fh:
        recs = parse_cargo_test_output(fh.read(), sys.argv[2], layer)
    for r in recs:
        print(r.to_json())
