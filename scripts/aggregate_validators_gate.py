#!/usr/bin/env python3
"""Manifest-driven aggregate validator gate (bd-rjc2m.VALWIRE).

NOTE: the repo already has scripts/run_all_checks.py (a BLIND orchestrator that runs every
scripts/*.py with --self-test) and scripts/lib/test_logger.py (structured logging). Neither
run_all_checks.py is referenced by any workflow (H-003: only ~30/425 check_*.py are CI-wired).
This gate adds the MISSING triage layer so validators can be wired into CI without blindly
failing on checks that need specific args/artifacts, and so NO validator is silently dropped.

Triage manifest: scripts/validators_manifest.json
  {"checks": {"check_foo.py": {"mode": "wired",   "args": ["--json"]},
              "check_bar.py": {"mode": "excluded", "rationale": "superseded by check_baz"}}}
Any check_*.py NOT in the manifest is 'untriaged' (counted + warned; the standing wire-or-exclude task).

The swarm should reconcile this with run_all_checks.py (adopt one path) — see the bead.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


@dataclass
class CheckResult:
    name: str
    mode: str
    rc: Optional[int]
    duration_ms: int
    passed: bool
    rationale: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def discover_checks(checks_dir: str) -> List[str]:
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(checks_dir, "check_*.py")))


def load_manifest(path: str) -> Dict[str, dict]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return (json.load(fh) or {}).get("checks", {})


def classify(checks: List[str], manifest: Dict[str, dict]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for name in checks:
        entry = manifest.get(name) or {}
        out[name] = {
            "mode": entry.get("mode", "untriaged"),
            "args": entry.get("args", []),
            "rationale": entry.get("rationale", ""),
        }
    return out


def run_check(checks_dir: str, name: str, args: List[str], runner=subprocess.run) -> CheckResult:
    t0 = time.monotonic()
    p = runner([sys.executable, os.path.join(checks_dir, name), *args], capture_output=True, text=True)
    dt = int((time.monotonic() - t0) * 1000)
    return CheckResult(name=name, mode="wired", rc=p.returncode, duration_ms=dt, passed=(p.returncode == 0))


def evaluate(classified: Dict[str, dict], checks_dir: str, strict: bool, runner=subprocess.run):
    results: List[CheckResult] = []
    failed_wired = 0
    untriaged = 0
    for name, info in classified.items():
        if info["mode"] == "wired":
            r = run_check(checks_dir, name, info["args"], runner=runner)
            results.append(r)
            failed_wired += 0 if r.passed else 1
        elif info["mode"] == "excluded":
            results.append(CheckResult(name, "excluded", None, 0, True, info.get("rationale", "")))
        else:
            untriaged += 1
            results.append(CheckResult(name, "untriaged", None, 0, True, "not yet wired-or-excluded"))
    rc = 1 if failed_wired else 0
    if strict and untriaged:
        rc = 1
    return results, rc, {"failed_wired": failed_wired, "untriaged": untriaged}


def render(results: List[CheckResult], stats: dict) -> str:
    wired = sum(1 for r in results if r.mode == "wired")
    excluded = sum(1 for r in results if r.mode == "excluded")
    lines = [
        "# Aggregate validator gate",
        f"checks: {len(results)} | wired: {wired} | excluded: {excluded} | "
        f"untriaged: {stats['untriaged']} | failed-wired: {stats['failed_wired']}",
        "",
    ]
    fails = [r for r in results if r.mode == "wired" and not r.passed]
    if fails:
        lines += ["## FAILED wired checks", "| check | rc | ms |", "|---|---|---|"]
        lines += [f"| {r.name} | {r.rc} | {r.duration_ms} |" for r in fails]
    if stats["untriaged"]:
        lines += ["", f"## {stats['untriaged']} UNTRIAGED (wire-or-exclude — standing debt)"]
        lines += [f"- {r.name}" for r in results if r.mode == "untriaged"][:50]
    return "\n".join(lines) + "\n"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checks-dir", default="scripts")
    ap.add_argument("--manifest", default="scripts/validators_manifest.json")
    ap.add_argument("--strict", action="store_true", help="also fail while any check is untriaged")
    ap.add_argument("--out", default="artifacts/validators")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)

    classified = classify(discover_checks(args.checks_dir), load_manifest(args.manifest))
    if args.list:
        for name, info in classified.items():
            print(f"{info['mode']:9s} {name}")
        return 0
    results, rc, stats = evaluate(classified, args.checks_dir, args.strict)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "validators_run.jsonl"), "w", encoding="utf-8") as fh:
        for r in results:
            fh.write(r.to_json() + "\n")
    sys.stdout.write(render(results, stats))
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
