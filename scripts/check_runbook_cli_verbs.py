#!/usr/bin/env python3
"""Verify all CLI commands referenced in operator runbooks exist in src/cli.rs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CLI_RS = ROOT / "crates" / "franken-node" / "src" / "cli.rs"
DEFAULT_RUNBOOKS_MD_DIR = ROOT / "docs" / "runbooks"
DEFAULT_RUNBOOKS_JSON_DIR = ROOT / "fixtures" / "runbooks"

SUBCOMMAND_ENUMS = {
    "runtime": "RuntimeCommand",
    "deploy": "DeployCommand",
    "safe-mode": "SafeModeCommand",
    "proofs": "ProofsCommand",
    "migrate": "MigrateCommand",
    "verify": "VerifyCommand",
    "trust": "TrustCommand",
    "remotecap": "RemoteCapCommand",
    "trust-card": "TrustCardCommand",
    "fleet": "FleetCommand",
    "ops": "OpsCommand",
    "incident": "IncidentCommand",
    "ltv": "LtvCommand",
    "registry": "RegistryCommand",
    "bench": "BenchCommand",
    "debug": "DebugCommand",
    "doctor": "DoctorCommand",
}

CLI_INVOCATION_RE = re.compile(
    r"\bfranken-node\s+([a-z][a-z0-9_-]*)(?:\s+([a-z][a-z0-9_-]*))?"
)
FORBIDDEN_BINARY_RE = re.compile(r"\bfranken-lab\b")


def camel_to_kebab(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


def parse_enum_variants(cli_source: str, enum_name: str) -> set[str]:
    match = re.search(rf"pub enum {re.escape(enum_name)}\s*\{{", cli_source)
    if not match:
        return set()
    idx = match.end()
    depth = 1
    top_chars: list[str] = []
    while idx < len(cli_source) and depth > 0:
        ch = cli_source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        if depth == 1:
            top_chars.append(ch)
        idx += 1

    variants: set[str] = set()
    pending_name: str | None = None
    for raw_line in "".join(top_chars).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("#["):
            nm = re.search(r'name\s*=\s*"([^"]+)"', line)
            if nm:
                pending_name = nm.group(1)
            continue
        vm = re.match(r"^([A-Z][A-Za-z0-9_]*)\b", line)
        if vm:
            variants.add(pending_name or camel_to_kebab(vm.group(1)))
            pending_name = None
    return variants


def load_cli_grammar(cli_rs: Path) -> tuple[set[str], dict[str, set[str]]]:
    src = cli_rs.read_text(encoding="utf-8")
    top_verbs = parse_enum_variants(src, "Command")
    sub_verbs = {
        verb: parse_enum_variants(src, enum_name)
        for verb, enum_name in SUBCOMMAND_ENUMS.items()
    }
    return top_verbs, sub_verbs


def scan_text_for_cli_errors(
    text: str,
    source_label: str,
    top_verbs: set[str],
    sub_verbs: dict[str, set[str]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    bad_items: list[str] = []

    for m in FORBIDDEN_BINARY_RE.finditer(text):
        bad_items.append(f"unshipped binary '{m.group(0)}'")

    for m in CLI_INVOCATION_RE.finditer(text):
        verb = m.group(1)
        subverb = m.group(2)
        if verb not in top_verbs:
            bad_items.append(f"unshipped top-level subcommand 'franken-node {verb}'")
            continue
        allowed_subs = sub_verbs.get(verb, set())
        if allowed_subs and subverb and subverb not in allowed_subs:
            bad_items.append(
                f"unshipped subcommand 'franken-node {verb} {subverb}' "
                f"(allowed: {sorted(allowed_subs)})"
            )

    findings.append(
        {
            "check": f"runbook_cli_truth:{source_label}",
            "pass": len(bad_items) == 0,
            "detail": "all CLI references shipped" if not bad_items else "; ".join(bad_items),
        }
    )
    return findings


def run_checks(
    cli_rs: Path = DEFAULT_CLI_RS,
    md_dir: Path = DEFAULT_RUNBOOKS_MD_DIR,
    json_dir: Path = DEFAULT_RUNBOOKS_JSON_DIR,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    if not cli_rs.is_file():
        checks.append({"check": "cli_rs_exists", "pass": False, "detail": f"missing {cli_rs}"})
        return _finalize(checks)

    top_verbs, sub_verbs = load_cli_grammar(cli_rs)
    checks.append(
        {
            "check": "cli_top_level_verbs_parsed",
            "pass": len(top_verbs) >= 15,
            "detail": f"count={len(top_verbs)} verbs={sorted(top_verbs)}",
        }
    )

    md_files = sorted(md_dir.glob("*.md")) if md_dir.is_dir() else []
    json_files = sorted(json_dir.glob("*.json")) if json_dir.is_dir() else []
    checks.append(
        {
            "check": "runbook_sources_discovered",
            "pass": len(md_files) > 0 and len(json_files) > 0,
            "detail": f"markdown={len(md_files)} json={len(json_files)}",
        }
    )

    for md_path in md_files:
        label = str(md_path.relative_to(ROOT)) if md_path.is_relative_to(ROOT) else md_path.name
        checks.extend(
            scan_text_for_cli_errors(
                md_path.read_text(encoding="utf-8"),
                label,
                top_verbs,
                sub_verbs,
            )
        )

    for json_path in json_files:
        label = (
            str(json_path.relative_to(ROOT))
            if json_path.is_relative_to(ROOT)
            else json_path.name
        )
        raw = json_path.read_text(encoding="utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            checks.append(
                {
                    "check": f"runbook_json_valid:{label}",
                    "pass": False,
                    "detail": str(exc),
                }
            )
            continue
        text_blobs: list[str] = []
        for cmd in payload.get("command_references", []):
            if isinstance(cmd, str):
                text_blobs.append(cmd)
        steps = payload.get("steps", {})
        if isinstance(steps, dict):
            for phase_steps in steps.values():
                if isinstance(phase_steps, list):
                    text_blobs.extend(s for s in phase_steps if isinstance(s, str))
        checks.extend(
            scan_text_for_cli_errors(
                "\n".join(text_blobs),
                label,
                top_verbs,
                sub_verbs,
            )
        )

    return _finalize(checks)


def _finalize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing
    overall = failing == 0 and len(checks) > 0
    return {
        "bead_id": "bd-reality-20260923-26n9r.38",
        "gate": "runbook_cli_verbs",
        "overall_pass": overall,
        "verdict": "PASS" if overall else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    report = run_checks()
    return report["overall_pass"], report["checks"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli-rs", type=Path, default=DEFAULT_CLI_RS)
    parser.add_argument("--md-dir", type=Path, default=DEFAULT_RUNBOOKS_MD_DIR)
    parser.add_argument("--json-dir", type=Path, default=DEFAULT_RUNBOOKS_JSON_DIR)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        payload = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("PASS" if ok else "FAIL")
        return 0 if ok else 1

    report = run_checks(cli_rs=args.cli_rs, md_dir=args.md_dir, json_dir=args.json_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"runbook_cli_verbs: {report['verdict']} "
            f"({report['summary']['passing']}/{report['summary']['total']})"
        )
        for check in report["checks"]:
            if not check["pass"]:
                print(f"  [FAIL] {check['check']}: {check['detail']}")
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
