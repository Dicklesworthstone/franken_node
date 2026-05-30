#!/usr/bin/env python3
"""Recurrence-prevention gate: fail if ANY verification target fails to compile (bd-rjc2m.G1).

Root cause this prevents: `cargo test`/`cargo fuzz` abort the whole build on a single
non-compiling target, silently dropping a slice of coverage with no signal. A Round-0
gauntlet census found 23/264 conformance + 45/146 fuzz targets rotted this way.

This gate runs (via rch) the two `--keep-going` census builds, parses the per-target
compile status, emits a remediation-log JSONL + a human summary, and EXITS NON-ZERO on
any broken target.

Modes:
  --run                 run the cargo censuses (default; needs rch/cargo)
  --from-log conf=PATH,fuzz=PATH   parse pre-captured cargo output (offline / CI artifact)
  --warn-only           always exit 0 (annotate only) — use while remediation is in flight
  --out DIR             write verify_run_<ts>.{jsonl,md} (default: artifacts/verification)

The parser is a pure function (parse_broken_targets) and is unit-tested separately.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediation_log import RemediationRecord, write_jsonl, render_summary  # noqa: E402

# Matches both:  could not compile `frankenengine-node` (test "X") due to N previous error
#         and:   could not compile `franken-node-fuzz` (bin "Y") due to N previous error[s]
_BROKEN_RE = re.compile(
    r'could not compile `(?P<crate>[a-z0-9_-]+)` \((?P<kind>test|bin) "(?P<name>[^"]+)"\)'
    r' due to (?P<n>\d+) previous error'
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_broken_targets(cargo_output: str) -> List[Tuple[str, str, int]]:
    """Pure function. Return sorted unique (target_name, kind, error_count) that failed to compile.

    kind is 'test' or 'bin'. Deduplicates (keeps max error_count per target).
    """
    text = _ANSI_RE.sub("", cargo_output)
    best: Dict[Tuple[str, str], int] = {}
    for m in _BROKEN_RE.finditer(text):
        key = (m.group("name"), m.group("kind"))
        n = int(m.group("n"))
        if n > best.get(key, -1):
            best[key] = n
    return sorted((name, kind, n) for (name, kind), n in best.items())


def _kind_to_layer(kind: str) -> str:
    return "fuzz" if kind == "bin" else "conformance"


def records_from_output(cargo_output: str, ts: str) -> List[RemediationRecord]:
    recs: List[RemediationRecord] = []
    for name, kind, n in parse_broken_targets(cargo_output):
        recs.append(
            RemediationRecord(
                target=name, layer=_kind_to_layer(kind), ts_rfc3339=ts,
                compiles=False, ran=False, errors_before=n, errors_after=n,
                assertions_preserved=True, notes="fails to compile (census)",
            )
        )
    return recs


_CONF_CMD = [
    "rch", "exec", "--", "cargo", "build", "-p", "frankenengine-node",
    "--tests", "--keep-going", "--features", "extended-surfaces,test-support",
]
_FUZZ_CMD = [
    "rch", "exec", "--", "cargo", "+nightly", "build",
    "--manifest-path", "fuzz/Cargo.toml", "--bins", "--keep-going",
]


def _run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return (p.stdout or "") + "\n" + (p.stderr or "")


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="verification-target compile-census gate")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--from-log", default=None, help="conf=PATH,fuzz=PATH")
    ap.add_argument("--warn-only", action="store_true")
    ap.add_argument("--out", default="artifacts/verification")
    ap.add_argument("--ts", default="now")  # caller may inject a stable ts
    args = ap.parse_args(argv)

    if args.ts == "now":
        # avoid importing datetime in tests; the caller/CI injects a real ts
        args.ts = os.environ.get("GATE_TS", "1970-01-01T00:00:00Z")

    output = ""
    if args.from_log:
        for part in args.from_log.split(","):
            _, path = part.split("=", 1)
            with open(path, encoding="utf-8") as fh:
                output += fh.read() + "\n"
    else:  # --run (default)
        output = _run(_CONF_CMD) + "\n" + _run(_FUZZ_CMD)

    recs = records_from_output(output, args.ts)
    os.makedirs(args.out, exist_ok=True)
    jsonl = os.path.join(args.out, f"compile_census_{args.ts.replace(':', '').replace('-', '')}.jsonl")
    write_jsonl(recs, jsonl)
    summary = render_summary(recs) if recs else "# Compile census: ALL verification targets compile ✓\n"
    sys.stdout.write(summary)
    sys.stdout.write(f"\n[gate] broken targets: {len(recs)}; report: {jsonl}\n")

    if args.warn_only:
        if recs:
            sys.stderr.write(f"::warning::{len(recs)} verification targets do not compile (warn-only mode)\n")
        return 0
    return 1 if recs else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
