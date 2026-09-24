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

# A README command-table row: `| \`franken-node <command> [<subcommand>] ...\` |`.
# The documented surface is read from the README itself (a hand-kept copy of
# it here drifted from both the README and the binary).
README_COMMAND_ROW = re.compile(r"^\|\s*`franken-node ([^`]+)`", re.MULTILINE)
COMMAND_WORD = re.compile(r"^[a-z][a-z0-9-]*$")


def documented_commands(readme_text: str) -> tuple[set[str], dict[str, set[str]]]:
    """Top-level commands and per-parent subcommands the README documents.

    The first word after `franken-node` in a command-table row is the
    top-level command; a second plain word (not `<arg>`, `[opt]` or a flag)
    is its subcommand.
    """
    top: set[str] = set()
    subs: dict[str, set[str]] = {}
    for match in README_COMMAND_ROW.finditer(readme_text):
        words = match.group(1).split()
        if not words or not COMMAND_WORD.match(words[0]):
            continue
        top.add(words[0])
        subs.setdefault(words[0], set())
        if len(words) > 1 and COMMAND_WORD.match(words[1]):
            subs[words[0]].add(words[1])
    return top, subs


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

    if not README.is_file():
        print(f"ERROR: README not found: {README}", file=sys.stderr)
        return 2
    expected_top, expected_subs = documented_commands(README.read_text(encoding="utf-8"))

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
    for cmd in sorted(expected_top - actual_top):
        findings["missing_top_level"].append({"command": cmd})
    for cmd in sorted(actual_top - expected_top):
        findings["extra_top_level"].append({"command": cmd})

    # --- Per-subcommand surface --------------------------------------------
    # Every documented top-level command is drilled into, so a subcommand the
    # binary exposes but the README never mentions is reported too.
    for parent, expected_children in sorted(expected_subs.items()):
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
