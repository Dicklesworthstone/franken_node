#!/usr/bin/env python3
"""Gate cargo's inline library test harness for bd-rjc2m.21.

`cargo test -p frankenengine-node --lib -- --list` must discover at least
one test. This script keeps the CI check out of ad hoc shell grep so the
parser and exit behavior are unit-tested.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TEST_LINE_RE = re.compile(r"^[^\s:].*: test$")
DEFAULT_OVERRIDE_CFG = "franken_node_inline_tests"
SCHEMA_LIST = "franken-node/inline-lib-test-gate/v1"
SCHEMA_PREFLIGHT = "franken-node/inline-lib-test-preflight/v1"


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def inline_test_names(cargo_list_output: str) -> list[str]:
    """Return test names from `cargo test --lib -- --list` output."""
    names: list[str] = []
    for raw_line in strip_ansi(cargo_list_output).splitlines():
        line = raw_line.strip()
        if not TEST_LINE_RE.match(line):
            continue
        names.append(line.rsplit(": test", 1)[0])
    return names


def evaluate(cargo_list_output: str, min_tests: int) -> dict[str, object]:
    if min_tests < 1:
        raise ValueError("min_tests must be at least 1")

    tests = inline_test_names(cargo_list_output)
    return {
        "schema_version": SCHEMA_LIST,
        "test_count": len(tests),
        "min_tests": min_tests,
        "passed": len(tests) >= min_tests,
        "sample_tests": tests[:10],
    }


def cargo_lib_test_enabled(cargo_toml: Path) -> bool:
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    return data.get("lib", {}).get("test") is True


def cargo_lints_allow_override_cfg(cargo_toml: Path, override_cfg: str) -> bool:
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    check_cfgs = (
        data.get("lints", {})
        .get("rust", {})
        .get("unexpected_cfgs", {})
        .get("check-cfg", [])
    )
    return f"cfg({override_cfg})" in check_cfgs


def lib_rs_uses_override_gate(lib_rs: Path, override_cfg: str) -> bool:
    text = lib_rs.read_text(encoding="utf-8")
    gate = f"#![cfg(any(not(test), {override_cfg}))]"
    return gate in text and "#![cfg(not(test))]" not in text


def preflight(
    cargo_toml: Path,
    lib_rs: Path,
    override_cfg: str = DEFAULT_OVERRIDE_CFG,
) -> dict[str, object]:
    checks = {
        "cargo_lib_test_true": cargo_lib_test_enabled(cargo_toml),
        "lib_rs_override_gate": lib_rs_uses_override_gate(lib_rs, override_cfg),
        "cargo_lints_allow_override_cfg": cargo_lints_allow_override_cfg(
            cargo_toml, override_cfg
        ),
    }
    issues = [name for name, passed in checks.items() if not passed]
    return {
        "schema_version": SCHEMA_PREFLIGHT,
        "passed": not issues,
        "override_cfg": override_cfg,
        "checks": checks,
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if cargo test --lib -- --list discovers too few inline tests."
    )
    parser.add_argument(
        "list_output",
        nargs="?",
        type=Path,
        help="Path to captured cargo list output. Reads stdin when omitted.",
    )
    parser.add_argument("--min-tests", type=int, default=1)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Check that the dedicated inline-test override is wired.",
    )
    parser.add_argument(
        "--cargo-toml",
        type=Path,
        default=Path("crates/franken-node/Cargo.toml"),
    )
    parser.add_argument(
        "--lib-rs",
        type=Path,
        default=Path("crates/franken-node/src/lib.rs"),
    )
    parser.add_argument("--override-cfg", default=DEFAULT_OVERRIDE_CFG)
    args = parser.parse_args(argv)

    if args.preflight:
        result = preflight(args.cargo_toml, args.lib_rs, args.override_cfg)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                "Inline library test override preflight: "
                f"{'passed' if result['passed'] else 'failed'}"
            )
            for issue in result["issues"]:
                print(f"failed check: {issue}", file=sys.stderr)
        return 0 if result["passed"] else 1

    if args.list_output:
        output = args.list_output.read_text(encoding="utf-8")
    else:
        output = sys.stdin.read()

    result = evaluate(output, args.min_tests)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"Inline library tests discovered: {result['test_count']} "
            f"(minimum: {result['min_tests']})"
        )
        if not result["passed"]:
            print(
                "Expected cargo test --lib -- --list to discover inline tests; "
                "the library test harness may be disabled.",
                file=sys.stderr,
            )

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
