#!/usr/bin/env python3
"""scripts/check_readme_cli_drift.py
============================================================================
README Command Reference vs. binary --help drift gate.

The README documents 60+ CLI commands across 14 top-level subcommands (Core,
Migration, Verification, Trust, Trust-card, Remote capabilities, Fleet,
Incident, Runtime/Safe-mode/Proofs, Ops/diagnostics, Registry, Bench, Debug,
Doctor). Operators rely on this listing to know what the binary actually
supports. Drift between README and the running binary is exactly the class
of bug the 2026-05-20 reality-check bridge plan surfaced (registry publish
clap panic; incident bundle/list missing --json; ops validation-readiness
positional rejected; verify recovery-runbook --readiness-input rejected).

This script catches:
  - Top-level subcommands documented in the README but missing from the
    binary's `--help` output (or vice versa).
  - Subcommand-level commands mentioned in the README that the binary does
    not surface as subcommands.
  - Commands whose `--help` invocation aborts (panic, exit code != 0, or
    empty stdout) — those would be invisible to operators trying to
    self-document.

This is intentionally a *coarse* check focused on "does the operator's
mental model match the binary's actual surface". It does NOT diff
per-flag schemas — that would require parsing every clap help block.
For full per-flag drift, run scripts/check_readme_quick_example.sh which
exercises the actual happy-path invocations end-to-end.

Usage:
    scripts/check_readme_cli_drift.py [--bin path/to/franken-node]
                                      [--json]

Exit codes:
    0  — no drift; README and binary surfaces agree at the command level
    1  — drift detected
    2  — invocation problem (binary not executable, README not found)
============================================================================
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DEFAULT_BIN = ROOT / "target" / "debug" / "franken-node"

# Top-level subcommands the README documents under "Command Reference"
# (README.md L611-727). Keep in sync with that section.
EXPECTED_TOP_LEVEL = {
    "init",
    "run",
    "doctor",
    "migrate",
    "migrate-report",
    "verify",
    "trust",
    "trust-card",
    "remotecap",
    "fleet",
    "incident",
    "ops",
    "registry",
    "bench",
    "debug",
    "runtime",
    "safe-mode",
    "proofs",
}

# Per-subcommand commands the README documents. Each tuple is (parent, child).
# Keep this list in lockstep with README's "Command Reference" tables.
EXPECTED_SUBCOMMANDS = {
    "migrate": {"audit", "rewrite", "validate"},
    # `migrate-report` is a TOP-LEVEL command, not a `migrate` subcommand.
    "verify": {
        "module",
        "migration",
        "compatibility",
        "corpus",
        "lockstep",
        "release",
        "transparency-log",
        "recovery-runbook",
    },
    "trust": {"card", "list", "scan", "sync", "revoke", "quarantine"},
    "trust-card": {"show", "export", "list", "compare", "diff"},
    "remotecap": {"issue", "verify", "use", "revoke"},
    "fleet": {"status", "describe", "release", "reconcile", "agent"},
    "incident": {"bundle", "replay", "counterfactual", "list"},
    "ops": {
        "health-check",
        "resource-governor",
        "validation-readiness",
        "validation-closeout",
        "config-audit",
        "metrics",
    },
    "registry": {"publish", "search", "verify", "gc"},
    "bench": {"run"},
    "debug": {"explain", "evidence", "trace"},
    "doctor": {"workspace-pressure", "close-condition", "evidence-readiness"},
    "runtime": {"lane", "epoch"},
    "safe-mode": {"enter", "status", "exit"},
    "proofs": {"queue", "workers"},
}


def run_help(bin_path: Path, args: list[str]) -> tuple[int, str, str]:
    """Invoke `<bin> <args> --help`; return (returncode, stdout, stderr).

    Returns ``(-1, "", "<exception>")`` if the process could not be launched
    at all — distinct from a clean non-zero exit.
    """
    try:
        proc = subprocess.run(
            [str(bin_path), *args, "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return (-1, "", f"<exception: {err}>")
    return (proc.returncode, proc.stdout, proc.stderr)


# Top-of-clap-help output lists subcommands in a block like:
#   Commands:
#     init     ...
#     run      ...
#     ...
#
# The block ends at the next blank line OR the "Options:" header that clap
# emits next. Match non-greedily so we don't also pick up the option list
# (where `-V,` and `-h,` look like word characters to a naive parser).
COMMANDS_BLOCK = re.compile(
    r"Commands:\s*\n((?:[ \t]+\S+.*\n)+)",
    re.MULTILINE,
)
# A valid clap subcommand name is alphanumeric (optionally with `-`/`_`),
# never starts with `-` (which is reserved for short/long options).
COMMAND_LINE = re.compile(r"^[ \t]+([A-Za-z][A-Za-z0-9_-]*)\s")


def extract_subcommands(help_text: str) -> set[str]:
    """Extract the subcommand names from a clap `--help` output block.

    Filters out flag-like entries (`-V`, `-h`, ...) and the canonical
    auto-injected `help` subcommand so the diff only surfaces real commands.
    """
    block = COMMANDS_BLOCK.search(help_text)
    if not block:
        return set()
    found: set[str] = set()
    for line in block.group(1).splitlines():
        m = COMMAND_LINE.match(line)
        if not m:
            continue
        name = m.group(1).strip()
        if name == "help":
            continue
        found.add(name)
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff README CLI surface against the binary's `--help` output."
    )
    parser.add_argument(
        "--bin",
        type=Path,
        default=DEFAULT_BIN,
        help=f"Path to franken-node binary (default: {DEFAULT_BIN})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON report on stdout.",
    )
    args = parser.parse_args(argv)

    if not args.bin.is_file() or not args.bin.stat().st_mode & 0o111:
        print(
            f"ERROR: binary not executable: {args.bin}\n"
            f"       build with: cargo build -p frankenengine-node --bin franken-node",
            file=sys.stderr,
        )
        return 2

    findings: dict[str, list[dict[str, str]]] = {
        "missing_top_level": [],
        "extra_top_level": [],
        "missing_subcommands": [],
        "extra_subcommands": [],
        "help_invocation_errors": [],
    }

    # --- Top-level surface --------------------------------------------------
    rc, stdout, stderr = run_help(args.bin, [])
    if rc != 0:
        findings["help_invocation_errors"].append(
            {"scope": "top-level", "rc": str(rc), "stderr": stderr.strip()[:200]}
        )
        return _report(findings, args.json)

    actual_top = extract_subcommands(stdout)
    for cmd in sorted(EXPECTED_TOP_LEVEL - actual_top):
        findings["missing_top_level"].append({"command": cmd})
    for cmd in sorted(actual_top - EXPECTED_TOP_LEVEL):
        findings["extra_top_level"].append({"command": cmd})

    # --- Per-subcommand surface --------------------------------------------
    for parent, expected_children in EXPECTED_SUBCOMMANDS.items():
        if parent not in actual_top:
            # Already flagged as missing top-level; skip drilldown.
            continue
        rc, stdout, stderr = run_help(args.bin, [parent])
        if rc != 0:
            findings["help_invocation_errors"].append(
                {
                    "scope": parent,
                    "rc": str(rc),
                    "stderr": stderr.strip()[:200],
                }
            )
            continue
        actual_children = extract_subcommands(stdout)
        for cmd in sorted(expected_children - actual_children):
            findings["missing_subcommands"].append(
                {"parent": parent, "command": cmd}
            )
        for cmd in sorted(actual_children - expected_children):
            findings["extra_subcommands"].append(
                {"parent": parent, "command": cmd}
            )

    return _report(findings, args.json)


def _report(findings: dict[str, list[dict[str, str]]], emit_json: bool) -> int:
    total = sum(len(v) for v in findings.values())
    if emit_json:
        print(
            json.dumps(
                {
                    "gate": "readme_cli_drift_gate",
                    "verdict": "pass" if total == 0 else "fail",
                    "total_findings": total,
                    "findings": findings,
                },
                indent=2,
            )
        )
    else:
        if total == 0:
            print("README CLI drift gate: PASS (README and binary surfaces agree)")
        else:
            print(f"README CLI drift gate: FAIL ({total} findings)\n")
            for kind, items in findings.items():
                if not items:
                    continue
                print(f"## {kind} ({len(items)})")
                for item in items:
                    print(f"   - {item}")
                print()

    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
