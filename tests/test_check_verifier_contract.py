#!/usr/bin/env python3
"""Unit tests for scripts/check_verifier_contract.py (bd-3ex)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_verifier_contract.py"
sys.path.insert(0, str(ROOT))

from scripts import check_verifier_contract as checker  # noqa: E402


def load_checker():
    return checker


SCENARIO_COMMANDS = {
    "verify_module_default": ("verify-module", None),
    "verify_migration_default": ("verify-migration", None),
    "verify_compatibility_default": ("verify-compatibility", None),
    "verify_corpus_default": ("verify-corpus", None),
    "verify_module_invalid_compat": ("verify-module", 9),
}


def write_contract(
    path: Path,
    *,
    previous_major: int,
    snapshots: dict[str, Path],
    contract_version: str = "2.0.0",
) -> None:
    commands = [
        ("verify-module", "module"),
        ("verify-migration", "migration"),
        ("verify-compatibility", "compatibility"),
        ("verify-corpus", "corpus"),
    ]
    scenarios = [
        ("verify_module_default", "verify-module", 0),
        ("verify_migration_default", "verify-migration", 0),
        ("verify_compatibility_default", "verify-compatibility", 0),
        ("verify_corpus_default", "verify-corpus", 0),
        ("verify_module_invalid_compat", "verify-module", 9),
    ]

    lines: list[str] = [
        'schema_version = "1.0"',
        'contract_name = "verifier-cli"',
        f'contract_version = "{contract_version}"',
        f"previous_contract_major = {previous_major}",
        "",
        "[exit_codes]",
        "pass = 0",
        "fail = 1",
        "error = 2",
        "skipped = 3",
        "",
        "[error_format]",
        'schema = "verifier-error-v1"',
        'required_fields = ["error_code", "message", "remediation"]',
        "",
    ]
    for cmd_id, sub in commands:
        lines.extend(
            [
                "[[commands]]",
                f'id = "{cmd_id}"',
                f'subcommand = "{sub}"',
                'output_schema = "verifier-cli-output-v1"',
                "supports_json = true",
                "supports_compat_version = true",
                'required_output_fields = ["command","contract_version","schema_version","compat_version","verdict","status","exit_code","reason"]',
                "",
            ]
        )
    for scenario_id, command_id, compat in scenarios:
        lines.extend(
            [
                "[[scenarios]]",
                f'scenario_id = "{scenario_id}"',
                f'command_id = "{command_id}"',
                f"compat_version = {compat}",
                f'snapshot = "{snapshots[scenario_id]}"',
                "",
            ]
        )

    path.write_text("\n".join(lines), encoding="utf-8")


def write_runner(path: Path, *, mismatch_exit_code: bool = False) -> Path:
    mismatch = "True" if mismatch_exit_code else "False"
    path.write_text(
        f"""#!/usr/bin/env python3
import json
import os
import sys

COMMAND_LABELS = {{
    "verify-module": "verify module",
    "verify-migration": "verify migration",
    "verify-compatibility": "verify compatibility",
    "verify-corpus": "verify corpus",
}}

args = sys.argv[1:]
if len(args) < 2 or args[0] != "verify":
    print(json.dumps({{"status": "error", "exit_code": 2, "reason": "bad invocation"}}))
    sys.exit(2)

subcommand = args[1]
command_id = {{
    "module": "verify-module",
    "migration": "verify-migration",
    "compatibility": "verify-compatibility",
    "corpus": "verify-corpus",
}}.get(subcommand)
if command_id is None:
    print(json.dumps({{"status": "error", "exit_code": 2, "reason": "bad subcommand"}}))
    sys.exit(2)

compat_version = None
if "--compat-version" in args:
    idx = args.index("--compat-version")
    compat_version = int(args[idx + 1])

contract_version = os.environ.get("FRANKEN_NODE_VERIFY_CONTRACT_VERSION", "2.0.0")
major = int(contract_version.split(".", 1)[0])
invalid_compat = compat_version is not None and (
    compat_version > major or compat_version + 1 < major
)
if invalid_compat:
    exit_code = 2
    payload = {{
        "command": COMMAND_LABELS[command_id],
        "contract_version": contract_version,
        "schema_version": "verifier-cli-contract-v1",
        "compat_version": compat_version,
        "verdict": "ERROR",
        "status": "error",
        "exit_code": exit_code,
        "reason": f"unsupported --compat-version={{compat_version}}; supported versions: {{major}} or {{max(major - 1, 0)}}",
    }}
else:
    exit_code = 0
    payload = {{
        "command": COMMAND_LABELS[command_id],
        "contract_version": contract_version,
        "schema_version": "verifier-cli-contract-v1",
        "compat_version": compat_version,
        "verdict": "PASS",
        "status": "pass",
        "exit_code": exit_code,
        "reason": "deterministic verifier checks passed",
    }}

if {mismatch} and command_id == "verify-module" and compat_version is None:
    payload["exit_code"] = 7

print(json.dumps(payload))
sys.exit(exit_code)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def run_runner_payload(
    runner: Path,
    command_id: str,
    compat_version: int | None,
    contract_version: str,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="bd3ex_payload_") as tmpdir:
        args, cwd = checker._scenario_invocation(command_id, compat_version, Path(tmpdir))
        env = os.environ.copy()
        env["FRANKEN_NODE_VERIFY_CONTRACT_VERSION"] = contract_version
        proc = subprocess.run(
            [str(runner), *args],
            capture_output=True,
            check=False,
            cwd=cwd,
            env=env,
            text=True,
            timeout=30,
        )
    try:
        payload = json.JSONDecoder().decode(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"runner stdout must be JSON: {proc.stdout}") from exc
    if not isinstance(payload, dict):
        raise AssertionError("runner payload must be a JSON object")
    return payload


def write_snapshots(
    snapshots: dict[str, Path],
    *,
    runner: Path,
    contract_version: str,
) -> None:
    for scenario, snapshot_path in snapshots.items():
        command_id, compat_version = SCENARIO_COMMANDS[scenario]
        payload = run_runner_payload(runner, command_id, compat_version, contract_version)
        snapshot_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class VerifierContractCheckerTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_checker()

    def test_self_test(self):
        self.assertTrue(self.mod.self_test())

    def test_run_checks_shape(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_shape_") as tmpdir:
            runner = write_runner(Path(tmpdir) / "franken-node")
            report = self.mod.run_checks(binary_path=runner)
        self.assertEqual(report["bead_id"], "bd-3ex")
        self.assertIn(report["verdict"], {"PASS", "FAIL"})
        self.assertIsInstance(report["checks"], list)
        self.assertGreaterEqual(len(report["checks"]), 10)

    def test_real_contract_passes(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_real_contract_") as tmpdir:
            runner = write_runner(Path(tmpdir) / "franken-node")
            report = self.mod.run_checks(binary_path=runner)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["failed"], 0)

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_cli_") as tmpdir:
            runner = write_runner(Path(tmpdir) / "franken-node")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--json", "--binary", str(runner)],
                capture_output=True,
                check=False,
                text=True,
                cwd=ROOT,
                timeout=30,
            )
        self.assertEqual(proc.returncode, 0)
        data = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3ex")
        self.assertEqual(data["verdict"], "PASS")

    def test_compare_snapshot_additive_only(self):
        diff = self.mod._compare_snapshot({"a": 1, "b": 2}, {"a": 1})
        self.assertTrue(diff["additive_only"])
        self.assertFalse(diff["breaking"])

    def test_compare_snapshot_breaking(self):
        diff = self.mod._compare_snapshot({"a": 2}, {"a": 1, "b": 2})
        self.assertTrue(diff["breaking"])
        self.assertIn("b", diff["removed_fields"])

    def test_missing_runner_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_missing_runner_") as tmpdir:
            missing_runner = Path(tmpdir) / "missing-franken-node"
            report = self.mod.run_checks(binary_path=missing_runner)
        self.assertEqual(report["verdict"], "FAIL")
        failing_names = {c["check"] for c in report["checks"] if not c["passed"]}
        self.assertIn("verifier_runner_available", failing_names)

    def test_reported_exit_code_must_match_process(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_exit_mismatch_") as tmpdir:
            tmp = Path(tmpdir)
            runner = write_runner(tmp / "franken-node", mismatch_exit_code=True)
            contract_path = tmp / "contract.toml"
            snapshot_paths = {name: (tmp / f"{name}.json") for name in SCENARIO_COMMANDS}
            write_snapshots(snapshot_paths, runner=runner, contract_version="2.0.0")
            write_contract(contract_path, previous_major=1, snapshots=snapshot_paths)

            report = self.mod.run_checks(
                contract_path=contract_path,
                binary_path=runner,
            )

        self.assertEqual(report["verdict"], "FAIL")
        failing_names = {c["check"] for c in report["checks"] if not c["passed"]}
        self.assertIn(
            "scenario:verify_module_default:exit_code_matches_process",
            failing_names,
        )

    def test_checker_no_longer_exposes_simulated_output(self):
        self.assertFalse(hasattr(self.mod, "_simulated_output"))

    def test_additive_snapshot_update_path(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_additive_") as tmpdir:
            tmp = Path(tmpdir)
            runner = write_runner(tmp / "franken-node")
            contract_path = tmp / "contract.toml"
            snapshot_paths = {name: (tmp / f"{name}.json") for name in SCENARIO_COMMANDS}
            write_snapshots(snapshot_paths, runner=runner, contract_version="2.0.0")

            # Introduce additive-only diff for one scenario.
            snapshot_paths["verify_module_default"].write_text(
                json.dumps({"command": "verify module"}, indent=2),
                encoding="utf-8",
            )
            write_contract(contract_path, previous_major=1, snapshots=snapshot_paths)

            report_no_update = self.mod.run_checks(
                update_snapshots=False,
                contract_path=contract_path,
                binary_path=runner,
            )
            self.assertEqual(report_no_update["verdict"], "PASS")

            report_update = self.mod.run_checks(
                update_snapshots=True,
                contract_path=contract_path,
                binary_path=runner,
            )
            self.assertEqual(report_update["verdict"], "PASS")
            refreshed = json.JSONDecoder().decode(
                snapshot_paths["verify_module_default"].read_text(encoding="utf-8")
            )
            self.assertEqual(refreshed["exit_code"], 0)
            self.assertEqual(refreshed["status"], "pass")

    def test_breaking_without_major_bump_fails(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_breaking_") as tmpdir:
            tmp = Path(tmpdir)
            runner = write_runner(tmp / "franken-node")
            contract_path = tmp / "contract.toml"
            snapshot_paths = {name: (tmp / f"{name}.json") for name in SCENARIO_COMMANDS}
            write_snapshots(snapshot_paths, runner=runner, contract_version="2.0.0")

            # Breaking change: mutate existing field value with no major bump.
            broken = json.JSONDecoder().decode(
                snapshot_paths["verify_module_default"].read_text(encoding="utf-8")
            )
            broken["reason"] = "different-reason"
            snapshot_paths["verify_module_default"].write_text(
                json.dumps(broken, indent=2),
                encoding="utf-8",
            )
            write_contract(contract_path, previous_major=2, snapshots=snapshot_paths)

            report = self.mod.run_checks(
                update_snapshots=False,
                contract_path=contract_path,
                binary_path=runner,
            )
            self.assertEqual(report["verdict"], "FAIL")
            failing_names = {c["check"] for c in report["checks"] if not c["passed"]}
            self.assertIn(
                "scenario:verify_module_default:snapshot_breaking_without_major_bump",
                failing_names,
            )


if __name__ == "__main__":
    unittest.main()
