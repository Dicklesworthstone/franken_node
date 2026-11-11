#!/usr/bin/env python3
"""Verify docs/CLAIMS_REGISTRY.md completeness and fail closed on failing verified gates."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = ROOT / "docs" / "CLAIMS_REGISTRY.md"

REQUIRED_FIELDS = (
    "Category",
    "Source",
    "Claim",
    "Evidence artifact",
    "Verification command",
    "Last verified",
    "Status",
)

# All 6 quantitative rows of docs/PRODUCT_CHARTER.md §5 plus Dual-Oracle and IBD adoption.
REQUIRED_CHARTER_CLAIMS = (
    "CLAIM-001",
    "CLAIM-002",
    "CLAIM-003",
    "CLAIM-004",
    "CLAIM-019",
    "CLAIM-020",
    "CLAIM-021",
    "CLAIM-022",
)

CLAIM_HEADER_RE = re.compile(r"^###\s+(CLAIM-\d+):\s*(.+?)\s*$", re.MULTILINE)
FIELD_RE = re.compile(r"^-\s+\*\*([^*]+)\*\*:\s*(.*)$")
SCRIPT_REF_RE = re.compile(r"\b(scripts/check_[A-Za-z0-9_]+\.py)\b")


def parse_claims(markdown: str) -> list[dict[str, Any]]:
    matches = list(CLAIM_HEADER_RE.finditer(markdown))
    claims: list[dict[str, Any]] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(markdown)
        body = markdown[start:end]
        fields: dict[str, str] = {}
        current_key: str | None = None
        for raw_line in body.splitlines():
            if raw_line.startswith("## "):
                break
            fm = FIELD_RE.match(raw_line)
            if fm:
                current_key = fm.group(1).strip()
                fields[current_key] = fm.group(2).strip()
            elif current_key is not None and (raw_line.startswith("  ") or raw_line.startswith("\t")):
                addition = raw_line.strip()
                if addition:
                    fields[current_key] = (
                        f"{fields[current_key]} {addition}".strip()
                        if fields[current_key]
                        else addition
                    )
            elif not raw_line.strip():
                continue
            else:
                current_key = None
        claims.append(
            {
                "id": match.group(1),
                "title": match.group(2),
                "fields": fields,
            }
        )
    return claims


def status_claims_verified(status_text: str) -> bool:
    normalized = status_text.strip().lower()
    return normalized.startswith("verified")


def execute_python_gate(script_path: Path, timeout_sec: int = 30) -> tuple[bool, str]:
    for args in ([sys.executable, str(script_path), "--json"], [sys.executable, str(script_path)]):
        proc = subprocess.run(
            args,
            cwd=str(script_path.parent.parent),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        if args[-1] == "--json" and proc.returncode == 2 and "unrecognized arguments: --json" in proc.stderr:
            continue

        parsed_verdict = None
        stdout = proc.stdout.strip()
        if stdout:
            # Some scripts emit structured log lines before the JSON object; locate last JSON object.
            brace_pos = stdout.find("{")
            if brace_pos != -1:
                try:
                    payload = json.loads(stdout[brace_pos:])
                    if isinstance(payload, dict):
                        if payload.get("verdict") == "FAIL" or payload.get("overall_pass") is False:
                            parsed_verdict = False
                        elif payload.get("release_qualified") is False:
                            parsed_verdict = False
                        elif payload.get("status") in {"FAIL", "RED"}:
                            parsed_verdict = False
                except json.JSONDecodeError:
                    pass

        ok = proc.returncode == 0 and (parsed_verdict is not False)
        detail = f"rc={proc.returncode}"
        if parsed_verdict is False:
            detail += " payload_verdict=FAIL"
        return ok, detail
    return False, "gate invocation failed"


def run_checks(registry_path: Path = DEFAULT_REGISTRY, repo_root: Path = ROOT) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    if not registry_path.is_file():
        checks.append(
            {
                "check": "claims_registry_exists",
                "pass": False,
                "detail": f"missing {registry_path}",
            }
        )
        return _finalize(checks)

    markdown = registry_path.read_text(encoding="utf-8")
    claims = parse_claims(markdown)
    checks.append(
        {
            "check": "claims_registry_non_empty",
            "pass": len(claims) > 0,
            "detail": f"parsed {len(claims)} claims",
        }
    )

    by_id = {c["id"]: c for c in claims}
    for req_id in REQUIRED_CHARTER_CLAIMS:
        checks.append(
            {
                "check": f"charter_claim_present:{req_id}",
                "pass": req_id in by_id,
                "detail": by_id[req_id]["title"] if req_id in by_id else "MISSING",
            }
        )

    for claim in claims:
        cid = claim["id"]
        fields = claim["fields"]
        missing = [f for f in REQUIRED_FIELDS if not fields.get(f)]
        checks.append(
            {
                "check": f"{cid}:required_fields",
                "pass": len(missing) == 0,
                "detail": "all present" if not missing else f"missing={missing}",
            }
        )

        status_text = fields.get("Status", "")
        is_verified = status_claims_verified(status_text)
        referenced_scripts = sorted(
            set(
                SCRIPT_REF_RE.findall(fields.get("Evidence artifact", ""))
                + SCRIPT_REF_RE.findall(fields.get("Verification command", ""))
            )
        )
        for rel_script in referenced_scripts:
            abs_script = repo_root / rel_script
            exists = abs_script.is_file()
            checks.append(
                {
                    "check": f"{cid}:gate_script_exists:{rel_script}",
                    "pass": exists,
                    "detail": str(rel_script) if exists else f"MISSING:{rel_script}",
                }
            )
            if exists and is_verified:
                gate_ok, gate_detail = execute_python_gate(abs_script)
                checks.append(
                    {
                        "check": f"{cid}:verified_gate_passes:{rel_script}",
                        "pass": gate_ok,
                        "detail": gate_detail,
                    }
                )

        if cid == "CLAIM-012" and is_verified:
            lib_rs = repo_root / "crates" / "franken-node" / "src" / "lib.rs"
            main_rs = repo_root / "crates" / "franken-node" / "src" / "main.rs"
            if lib_rs.is_file() and main_rs.is_file():
                forbid_ok = (
                    "#![forbid(unsafe_code)]" in lib_rs.read_text(encoding="utf-8")
                    and "#![forbid(unsafe_code)]" in main_rs.read_text(encoding="utf-8")
                )
                checks.append(
                    {
                        "check": "CLAIM-012:forbid_unsafe_code_present",
                        "pass": forbid_ok,
                        "detail": "present in lib.rs and main.rs" if forbid_ok else "missing forbid(unsafe_code)",
                    }
                )

    return _finalize(checks)


def _finalize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing
    overall = failing == 0 and len(checks) > 0
    return {
        "bead_id": "bd-reality-20260923-26n9r.16",
        "gate": "claims_registry_gates",
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
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
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

    report = run_checks(registry_path=args.registry)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"claims_registry_gates: {report['verdict']} "
            f"({report['summary']['passing']}/{report['summary']['total']})"
        )
        for check in report["checks"]:
            if not check["pass"]:
                print(f"  [FAIL] {check['check']}: {check['detail']}")
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
