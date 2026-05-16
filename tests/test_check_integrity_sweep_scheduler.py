"""Unit tests for check_integrity_sweep_scheduler.py verification script."""

import importlib.util
import os
import tempfile
import unittest
from unittest import mock


SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "check_integrity_sweep_scheduler.py",
)
spec = importlib.util.spec_from_file_location("check_mod", SCRIPT)
check_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_mod)


TYPES = [
    "pub enum Trend",
    "pub struct EvidenceTrajectory",
    "pub enum PolicyBand",
    "pub enum SweepDepth",
    "pub struct SweepScheduleDecision",
    "pub struct SweepSchedulerConfig",
    "pub struct IntegritySweepScheduler",
]

EVENT_CODES = ["EVD-SWEEP-001", "EVD-SWEEP-002", "EVD-SWEEP-003", "EVD-SWEEP-004"]

INVARIANTS = [
    "INV-SWEEP-ADAPTIVE",
    "INV-SWEEP-HYSTERESIS",
    "INV-SWEEP-DETERMINISTIC",
    "INV-SWEEP-BOUNDED",
]


def _required_test_names() -> list[str]:
    return [
        check["check"].removeprefix("test: ")
        for check in check_mod.run_checks()
        if check["check"].startswith("test: ")
    ]


def _write_comment_only_fixture(root: str) -> dict[str, str]:
    policy_dir = os.path.join(root, "crates/franken-node/src/policy")
    spec_dir = os.path.join(root, "docs/specs/section_10_14")
    artifact_dir = os.path.join(root, "artifacts/10.14")
    os.makedirs(policy_dir, exist_ok=True)
    os.makedirs(spec_dir, exist_ok=True)
    os.makedirs(artifact_dir, exist_ok=True)

    paths = {
        "impl": os.path.join(policy_dir, "integrity_sweep_scheduler.rs"),
        "mod": os.path.join(policy_dir, "mod.rs"),
        "spec": os.path.join(spec_dir, "bd-1fp4_contract.md"),
        "trajectory": os.path.join(artifact_dir, "sweep_policy_trajectory.csv"),
    }

    with open(paths["mod"], "w", encoding="utf-8") as f:
        f.write("// pub mod integrity_sweep_scheduler;\n")

    markers = [
        *TYPES,
        "Improving",
        "Stable",
        "Degrading",
        "Green",
        "Yellow",
        "Red",
        "Quick",
        "Standard",
        "Deep",
        "Full",
        "fn update_trajectory(",
        "fn next_sweep_interval(",
        "fn current_sweep_depth(",
        "fn classify_band(",
        "fn with_defaults(",
        "fn to_csv(",
        "fn current_band(",
        "fn hysteresis_counter(",
        "fn update_count(",
        "fn decisions(",
        *EVENT_CODES,
        *INVARIANTS,
        "Serialize",
        "Deserialize",
        "Duration",
        *[f"fn {name}(" for name in _required_test_names()],
        *["#[test]" for _ in range(40)],
    ]
    with open(paths["impl"], "w", encoding="utf-8") as f:
        f.write("// " + "\n// ".join(markers[:30]) + "\n")
        f.write("/*\n")
        f.write("\n".join(markers[30:]))
        f.write("\n*/\n")

    with open(paths["spec"], "w", encoding="utf-8") as f:
        f.write("# bd-1fp4 contract\n")

    with open(paths["trajectory"], "w", encoding="utf-8") as f:
        f.write("step,band\n")
        for idx in range(5):
            f.write(f"{idx},green\n")

    return paths


class TestRunChecks(unittest.TestCase):
    def test_returns_list(self):
        result = check_mod.run_checks()
        self.assertIsInstance(result, list)

    def test_all_entries_have_required_keys(self):
        for entry in check_mod.run_checks():
            self.assertIn("check", entry)
            self.assertIn("pass", entry)
            self.assertIn("detail", entry)

    def test_pass_values_are_bool(self):
        for entry in check_mod.run_checks():
            self.assertIsInstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = check_mod.run_checks()
        self.assertGreaterEqual(len(result), 70)

    def test_all_checks_pass(self):
        result = check_mod.run_checks()
        failing = [c for c in result if not c["pass"]]
        self.assertFalse(failing, f"Failing checks: {failing}")


class TestFileChecks(unittest.TestCase):
    def test_implementation_file(self):
        checks = check_mod.run_checks()
        self.assertTrue(next(c for c in checks if c["check"] == "file: implementation")["pass"])

    def test_spec_file(self):
        checks = check_mod.run_checks()
        self.assertTrue(next(c for c in checks if c["check"] == "file: spec contract")["pass"])

    def test_trajectory_file(self):
        checks = check_mod.run_checks()
        self.assertTrue(next(c for c in checks if c["check"] == "file: trajectory artifact")["pass"])


class TestTypeChecks(unittest.TestCase):
    def test_types_found(self):
        checks = check_mod.run_checks()
        for ty in TYPES:
            with self.subTest(ty=ty):
                check = next(c for c in checks if c["check"] == f"type: {ty}")
                self.assertTrue(check["pass"], f"Type not found: {ty}")


class TestEventCodes(unittest.TestCase):
    def test_event_codes_found(self):
        checks = check_mod.run_checks()
        for code in EVENT_CODES:
            with self.subTest(code=code):
                check = next(c for c in checks if c["check"] == f"event_code: {code}")
                self.assertTrue(check["pass"])


class TestInvariants(unittest.TestCase):
    def test_invariants_found(self):
        checks = check_mod.run_checks()
        for inv in INVARIANTS:
            with self.subTest(inv=inv):
                check = next(c for c in checks if c["check"] == f"invariant: {inv}")
                self.assertTrue(check["pass"])


class TestUnitTestCount(unittest.TestCase):
    def test_count_passes(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "unit test count")
        self.assertTrue(check["pass"])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(check_mod.self_test())


class TestCommentOnlyRustRegression(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = (
            'pub const KEEP: &str = "EVD-SWEEP-001 // literal"; // "EVD-SWEEP-002"\n'
            'pub const RAW: &str = r#"INV-SWEEP-ADAPTIVE /* literal */"#; /* "EVD-SWEEP-003" */\n'
        )

        stripped = check_mod._strip_rust_comments(source)

        self.assertIn('"EVD-SWEEP-001 // literal"', stripped)
        self.assertIn('r#"INV-SWEEP-ADAPTIVE /* literal */"#', stripped)
        self.assertNotIn('"EVD-SWEEP-002"', stripped)
        self.assertNotIn('"EVD-SWEEP-003"', stripped)

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            paths = _write_comment_only_fixture(root)
            with mock.patch.multiple(
                check_mod,
                ROOT=root,
                IMPL=paths["impl"],
                MOD_RS=paths["mod"],
                SPEC=paths["spec"],
                TRAJECTORY=paths["trajectory"],
            ):
                checks = check_mod.run_checks()

        by_name = {check["check"]: check for check in checks}
        self.assertTrue(by_name["file: implementation"]["pass"])
        self.assertTrue(by_name["file: spec contract"]["pass"])
        self.assertTrue(by_name["file: trajectory artifact"]["pass"])
        self.assertTrue(by_name["trajectory has header"]["pass"])
        self.assertTrue(by_name["trajectory has data rows"]["pass"])

        rust_backed_failures = [
            check
            for check in checks
            if check["check"]
            not in {
                "file: implementation",
                "file: spec contract",
                "file: trajectory artifact",
                "trajectory has header",
                "trajectory has data rows",
            }
        ]
        self.assertTrue(rust_backed_failures)
        for check in rust_backed_failures:
            self.assertFalse(check["pass"], check["check"])


class TestCheckHelper(unittest.TestCase):
    def test_pass_true(self):
        result = check_mod._check("t", True, "ok")
        self.assertTrue(result["pass"])

    def test_pass_false(self):
        result = check_mod._check("t", False)
        self.assertEqual(result["detail"], "NOT FOUND")
