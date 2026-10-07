"""Real metadata and scanner-CLI regressions for transitive npm inventory."""
import json
import ast
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import dependency_inventory as inventory
from scripts import project_scanner as scanner


class DependencyInventoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def scan(self):
        return scanner.scan_dependencies(self.root)

    def modern(self, records, version=3, **extra):
        self.write("package-lock.json", {"lockfileVersion": version, "packages": records, **extra})

    def test_transitive_native_addon_changes_actual_report_readiness(self):
        self.write("package.json", {"dependencies": {"web": "^1"}})
        self.modern({"": {}, "node_modules/web": {"version": "1.0.0"},
                     "node_modules/web/node_modules/sharp": {"version": "0.33.0"}})
        result = scanner.scan_project(self.root)
        self.assertEqual(result["summary"]["migration_readiness"], "not-ready")
        self.assertEqual(result["summary"]["risk_distribution"]["critical"], 1)
        sharp = next(row for row in result["dependencies"] if row["name"] == "sharp")
        self.assertEqual(sharp["package_path"], "node_modules/web/node_modules/sharp")
        self.assertEqual(sharp["version"], "0.33.0")

    def test_install_scripts_are_high_not_mislabeled_native(self):
        self.modern({"node_modules/assets": {"version": "1", "hasInstallScript": True}})
        report = scanner.scan_project(self.root)
        self.assertEqual(report["summary"]["migration_readiness"], "partial")
        row = report["dependencies"][0]
        self.assertFalse(row["has_native_addon"])
        self.assertTrue(row["has_install_script"])
        self.assertIn("install lifecycle", row["notes"])

    def test_preserves_multiple_versions_and_locations(self):
        self.modern({"node_modules/tool": {"version": "2"},
                     "node_modules/app/node_modules/tool": {"version": "1"},
                     "node_modules/other/node_modules/tool": {"version": "1"}})
        rows = self.scan()
        self.assertEqual([row["version"] for row in rows], ["1", "1", "2"])
        self.assertEqual(len({row["package_path"] for row in rows}), 3)

    def test_v2_uses_packages_not_outdated_legacy_projection(self):
        self.modern({"node_modules/safe": {"version": "1"}}, version=2,
                    dependencies={"sharp": {"version": "999"}})
        self.assertEqual([row["name"] for row in self.scan()], ["safe"])

    def test_v1_nested_tree_and_aliases(self):
        self.write("package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "web": {"version": "1", "dependencies": {
                "hash": {"version": "npm:bcrypt@5.1.0"},
                "@org/tool": {"version": "2", "optional": True}}}}})
        rows = self.scan()
        native = next(row for row in rows if row["has_native_addon"])
        self.assertEqual(native["name"], "bcrypt")
        self.assertEqual(native["package_path"], "node_modules/web/node_modules/hash")
        self.assertEqual(native["version"], "5.1.0")

    def test_modern_alias_uses_real_package_name(self):
        self.modern({"node_modules/innocent": {"name": "sharp", "version": "1"}})
        row = self.scan()[0]
        self.assertEqual(row["risk_level"], "critical")
        self.assertIn("innocent", row["notes"])

    def test_scoped_alias_in_manifest_is_not_hidden(self):
        self.write("package.json", {"dependencies": {"quiet": "npm:sharp@^0.33"},
                                   "peerDependencies": {"peer": "npm:@org/api@~2"},
                                   "optionalDependencies": {"optional": "1"}})
        rows = self.scan()
        self.assertEqual({r["name"] for r in rows}, {"sharp", "@org/api", "optional"})
        self.assertEqual(next(r for r in rows if r["name"] == "sharp")["risk_level"], "critical")

    def test_root_lock_record_replaces_manifest_range_only_at_root(self):
        self.write("package.json", {"dependencies": {"tool": "^2"}})
        self.modern({"node_modules/app/node_modules/tool": {"version": "1"}})
        rows = self.scan()
        unresolved = next(r for r in rows if r["source"] == "package.json")
        self.assertEqual(unresolved["version"], "^2")
        self.assertEqual(unresolved["risk_level"], "high")
        self.modern({"node_modules/tool": {"version": "2.4"}})
        self.assertEqual(len(self.scan()), 1)
        self.assertEqual(self.scan()[0]["version"], "2.4")

    def test_workspace_link_reads_only_captured_descriptor(self):
        self.modern({"packages/shared": {"name": "shared", "version": "1", "hasInstallScript": True},
                     "node_modules/shared": {"link": True, "resolved": "packages/shared"}})
        row = self.scan()[0]
        self.assertTrue(row["is_link"])
        self.assertTrue(row["has_install_script"])
        self.assertFalse(row["resolution_verified"])
        self.assertFalse((self.root / "packages").exists())

    def test_missing_link_target_is_reported_unresolved(self):
        self.modern({"node_modules/shared": {"link": True, "resolved": "packages/shared"}})
        self.assertEqual(self.scan()[0]["risk_level"], "high")

    def test_external_link_is_never_followed(self):
        self.modern({"node_modules/shared": {"link": True, "resolved": "../outside"}})
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_legacy_shrinkwrap_can_be_inventoried_but_ambiguous_pair_rejected(self):
        self.write("npm-shrinkwrap.json", {"lockfileVersion": 1,
                                          "dependencies": {"sharp": {"version": "1"}}})
        self.assertEqual(self.scan()[0]["source"], "npm-shrinkwrap.json")
        self.modern({})
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_malformed_explicit_input_never_falls_back_to_manifest(self):
        self.write("package.json", {"dependencies": {"safe": "1"}})
        for raw in ('{', '{}', '{"lockfileVersion":true}',
                    '{"lockfileVersion":3,"packages":[]}',
                    '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1","hasInstallScript":"false"}}}',
                    '{"lockfileVersion":3,"packages":{},"packages":{}}'):
            with self.subTest(raw=raw):
                (self.root / "package-lock.json").write_text(raw)
                with self.assertRaises(inventory.InventoryError):
                    self.scan()

    def test_invalid_package_metadata_is_not_empty_success(self):
        for value in ({"dependencies": []}, {"dependencies": {"a": {}}},
                      {"dependencies": {"../sharp": "1"}}):
            self.write("package.json", value)
            with self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_symlink_lockfile_is_rejected(self):
        self.write("outside.json", {"lockfileVersion": 3, "packages": {}})
        (self.root / "package-lock.json").symlink_to("outside.json")
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_byte_and_package_budgets_fail_closed(self):
        self.modern({"node_modules/a": {"version": "1"}, "node_modules/b": {"version": "1"}})
        with patch.object(inventory, "MAX_LOCK_BYTES", 10):
            with self.assertRaises(inventory.InventoryError):
                self.scan()
        with patch.object(inventory, "MAX_PACKAGES", 1):
            with self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_flags_and_absent_metadata_are_not_guessed(self):
        self.modern({"node_modules/a": {"version": "1", "optional": True, "dev": True}})
        row = self.scan()[0]
        self.assertTrue(row["optional"])
        self.assertTrue(row["dev"])
        self.assertFalse(row["has_install_script"])
        self.assertFalse(row["resolution_verified"])

    def test_empty_project_is_still_supported(self):
        self.assertEqual(self.scan(), [])

    def test_inventory_order_does_not_depend_on_json_key_order(self):
        records = {"node_modules/z": {"version": "1"}, "node_modules/a": {"version": "2"}}
        self.modern(records)
        original = self.scan()
        self.modern(dict(reversed(list(records.items()))))
        self.assertEqual(self.scan(), original)

    def test_scanner_cli_exposes_transitive_risk_and_reports_input_error(self):
        self.modern({"node_modules/app/node_modules/sharp": {"version": "1"}})
        command = [sys.executable, str(ROOT / "scripts/project_scanner.py"), str(self.root), "--json"]
        process = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["summary"]["migration_readiness"], "not-ready")
        (self.root / "package-lock.json").write_text("{")
        process = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("summary", result)

    def workspace(self, directory, package):
        target = self.root / directory
        target.mkdir(parents=True, exist_ok=True)
        (target / "package.json").write_text(json.dumps(package))

    def test_workspace_native_dependency_is_seen_without_a_lockfile(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/api", {"name": "api", "dependencies": {"sharp": "^1"}})
        report = scanner.scan_project(self.root)
        self.assertEqual(report["summary"]["migration_readiness"], "not-ready")
        self.assertEqual(report["dependencies"][0]["declared_in"], "packages/api/package.json")

    def test_workspace_hoisted_and_private_locks_avoid_phantom_unresolved_rows(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/api", {"name": "api", "dependencies": {"a": "^1", "b": "^2"}})
        self.modern({"node_modules/a": {"version": "1.2"},
                     "packages/api/node_modules/b": {"version": "2.5"}})
        rows = self.scan()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["source"] == "package-lock.json" for row in rows))
        self.assertTrue(all(row["risk_level"] == "low" for row in rows))

    def test_workspace_missing_lock_record_is_not_silently_dropped(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/api", {"name": "api", "dependencies": {"runtime": "^1"}})
        self.modern({"node_modules/unrelated": {"version": "1"}})
        row = next(row for row in self.scan() if row["name"] == "runtime")
        self.assertEqual(row["risk_level"], "high")
        self.assertEqual(row["source"], "packages/api/package.json")

    def test_stale_locked_alias_cannot_hide_new_workspace_native_dependency(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/api", {"name": "api", "dependencies": {"image": "npm:sharp@^1"}})
        self.modern({"node_modules/image": {"name": "old-pure-js-package", "version": "1"}})
        report = scanner.scan_project(self.root)
        self.assertEqual(report["summary"]["migration_readiness"], "not-ready")
        row = next(row for row in report["dependencies"] if row["name"] == "sharp")
        self.assertIn("identity differs", row["notes"])
        self.assertEqual(row["source"], "packages/api/package.json")

    def test_stale_root_lock_cannot_suppress_invalid_alias_declaration(self):
        self.write("package.json", {"dependencies": {"image": "npm:"}})
        self.modern({"node_modules/image": {"version": "1"}})
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_workspace_globstar_and_overlapping_selectors_are_deterministic(self):
        self.write("package.json", {"workspaces": ["packages/**", "packages/a/*"]})
        self.workspace("packages/a/b", {"name": "deep", "dependencies": {"canvas": "1"}})
        self.workspace("packages/z", {"name": "last", "dependencies": {"bcrypt": "2"}})
        rows = self.scan()
        self.assertEqual([row["name"] for row in rows], ["bcrypt", "canvas"])
        self.write("package.json", {"workspaces": ["packages/a/*", "packages/**"]})
        self.assertEqual(self.scan(), rows)

    def test_exact_workspace_does_not_scan_nested_packages(self):
        self.write("package.json", {"workspaces": ["packages/api"]})
        self.workspace("packages/api", {"name": "api", "dependencies": {"safe": "1"}})
        self.workspace("packages/api/fixtures", {"name": "fixture", "dependencies": {"sharp": "1"}})
        self.assertEqual([row["name"] for row in self.scan()], ["safe"])

    def test_unselected_or_installed_manifests_cannot_poison_workspace_inventory(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/api", {"name": "api"})
        self.workspace("elsewhere/trap", {"name": "trap", "dependencies": []})
        self.workspace("packages/node_modules/trap", {"name": "trap", "dependencies": []})
        self.assertEqual(self.scan(), [])

    def test_workspace_links_and_unsupported_globs_fail_explicitly(self):
        self.workspace("actual", {"name": "a"})
        (self.root / "packages").symlink_to("actual", target_is_directory=True)
        self.write("package.json", {"workspaces": ["packages"]})
        with self.assertRaises(inventory.InventoryError):
            self.scan()
        for pattern in ("../other", "packages/{a,b}", "!packages/a", "node_modules/*", "a/**b"):
            self.write("package.json", {"workspaces": [pattern]})
            with self.subTest(pattern=pattern), self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_duplicate_workspace_names_and_broken_manifest_refuse_clean_report(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/a", {"name": "duplicate"})
        self.workspace("packages/b", {"name": "duplicate"})
        with self.assertRaises(inventory.InventoryError):
            self.scan()
        (self.root / "packages/b/package.json").write_text("{")
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_workspace_resource_limits_do_not_truncate_to_success(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/a", {"name": "a"})
        self.workspace("packages/b", {"name": "b"})
        for key, value in (("MAX_WORKSPACES", 1), ("MAX_WORKSPACE_ENTRIES", 1),
                           ("MAX_LOCK_BYTES", 10), ("MAX_DEPTH", 1)):
            with self.subTest(limit=key), patch.object(inventory, key, value):
                with self.assertRaises(inventory.InventoryError):
                    self.scan()

    def test_workspace_cli_reports_dependency_outside_root_manifest(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.workspace("packages/runtime", {"name": "runtime", "optionalDependencies": {"ffi-napi": "4"}})
        process = subprocess.run([sys.executable, str(ROOT / "scripts/project_scanner.py"),
                                  str(self.root), "--json"], capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["summary"]["migration_readiness"], "not-ready")
        self.assertEqual(report["dependencies"][0]["source"], "packages/runtime/package.json")


class ReportDependencyAssessmentTests(unittest.TestCase):
    """Execute the checked-in report boundary without an execution backend.

    Inventory, files, scanning and report orchestration are real. Scoring,
    rewrite advice and execution observations are mocked explicitly; these are
    unit/integration boundary tests, not proof of native runtime execution.
    """

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

        def raise_walk_error(error):
            raise error

        self.scorer = Mock()
        self.scorer.score_report.return_value = {"risk_score": 0, "difficulty": {"level": "low"}}
        self.rewriter = Mock()
        self.rewriter.produce_report.side_effect = lambda _scan: {
            "suggestions": [], "summary": {"by_category": {}}}
        self.runner = SimpleNamespace(raise_walk_error=raise_walk_error,
                                      DEFAULT_BASELINE_COMMAND=("node",),
                                      DEFAULT_MIGRATION_COMMAND=("franken-node",))
        self.replay = SimpleNamespace(unique_object=inventory._unique, reject_constant=inventory._constant)
        self.namespace = {"Path": Path, "os": os, "json": json, "time": time,
                          "tempfile": tempfile, "datetime": datetime, "timezone": timezone,
                          "inventory_mod": inventory, "scanner_mod": scanner,
                          "scorer_mod": self.scorer, "rewrite_mod": self.rewriter,
                          "runner": self.runner, "replay": self.replay,
                          "MAX_SCAN_SOURCE_BYTES": 10 * 1024 * 1024}
        path = ROOT / "scripts/migrate_report.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {"assess_snapshot", "dependency_review_reasons", "generate_full_report", "preflight_destinations"}
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in functions}, names)
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), self.namespace)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def assess(self):
        return self.namespace["assess_snapshot"](self.root, "project", {}, time.monotonic() + 30)

    def test_actual_report_assessment_includes_transitive_native_risks(self):
        self.write("package.json", {"dependencies": {"web": "1"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "node_modules/web": {"version": "1"},
            "node_modules/web/node_modules/sharp": {"version": "2"}}})
        assessment = self.assess()
        scan = assessment["scan"]
        self.assertEqual(scan["summary"]["migration_readiness"], "not-ready")
        self.assertEqual(scan["summary"]["risk_distribution"]["critical"], 1)
        self.scorer.score_report.assert_called_once_with(scan)
        self.rewriter.produce_report.assert_called_once_with(scan)
        self.assertEqual(len(self.namespace["dependency_review_reasons"](scan)), 1)
        self.assertFalse(assessment["rewrite_suggestions"]["applied"])
        self.assertTrue(assessment["rewrite_suggestions"]["advisory_only"])

    def test_report_keeps_install_script_review_even_with_low_heuristic_score(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "node_modules/assets": {"version": "1", "hasInstallScript": True}}})
        assessment = self.assess()
        self.assertEqual(assessment["risk_assessment"]["risk_score"], 0)  # explicitly mocked
        self.assertEqual(assessment["scan"]["summary"]["migration_readiness"], "partial")
        self.assertEqual(assessment["scan"]["summary"]["risk_distribution"]["high"], 1)
        self.assertEqual(assessment["scan"]["recommendations"][0]["category"], "high-risk")
        self.assertTrue(self.namespace["dependency_review_reasons"](assessment["scan"]))

    def test_non_workspace_manifest_coverage_is_preserved_and_alias_is_resolved(self):
        self.write("examples/plugin/package.json", {"dependencies": {"hidden": "npm:sharp@1"}})
        assessment = self.assess()
        row = assessment["scan"]["dependencies"][0]
        self.assertEqual(row["name"], "sharp")
        self.assertEqual(row["source"], "examples/plugin/package.json")
        self.assertEqual(assessment["scan"]["summary"]["migration_readiness"], "not-ready")

    def test_report_does_not_double_count_workspace_declarations_and_locked_packages(self):
        self.write("package.json", {"workspaces": ["packages/*"]})
        self.write("packages/api/package.json", {"name": "api", "dependencies": {"sharp": "^1"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "node_modules/sharp": {"version": "1.2"}}})
        self.assertEqual(len(self.assess()["scan"]["dependencies"]), 1)

    def test_malformed_lock_stops_assessment_before_risk_or_rewrite_advice(self):
        (self.root / "package-lock.json").write_text("{")
        with self.assertRaises(inventory.InventoryError):
            self.assess()
        self.scorer.score_report.assert_not_called()
        self.rewriter.produce_report.assert_not_called()

    def test_assessment_metadata_budget_refuses_instead_of_truncating(self):
        self.write("examples/package.json", {"name": "example", "dependencies": {"sharp": "1"}})
        with patch.object(inventory, "MAX_MANIFEST_BYTES", 10):
            with self.assertRaises(ValueError):
                self.assess()

    def test_expired_assessment_deadline_does_not_produce_empty_success(self):
        with self.assertRaises(TimeoutError):
            self.namespace["assess_snapshot"](self.root, "project", {}, time.monotonic() - 1)

    def test_additional_manifest_observations_cannot_override_or_escape_root(self):
        self.write("package.json", {"dependencies": {"sharp": "1"}})
        for supplied in ({"package.json": {}}, {"../package.json": {}}, {"other.json": {}},
                         {"nested/package.json": []}):
            with self.subTest(manifests=supplied), self.assertRaises(inventory.InventoryError):
                inventory.scan_dependencies(self.root, scanner.NATIVE_ADDON_PACKAGES,
                                            additional_manifests=supplied)

    def test_report_decision_cannot_waive_dependency_review_after_optimistic_validation(self):
        # Controlled execution observations isolate report decision propagation.
        # No native process is executed or claimed to pass by this test.
        self.replay.LEGS = ("baseline", "migration")
        self.replay.checked_options = lambda _options: {"total_timeout_seconds": 30}
        self.replay.runtime_bindings = lambda *_args: ({"baseline": ["node"], "migration": ["franken-node"]}, {})
        self.runner.capture_project = lambda *_args: ({}, "captured-input")
        self.runner.stage_project = lambda _snapshot, path, _deadline: path.mkdir()
        self.runner.validate_project = lambda *_args, **_kwargs: {
            "summary": {"verdict": "PASS"},
            "inputs": {"baseline_sha256": "captured-input", "migration_sha256": "captured-input"},
            "errors": []}
        self.namespace["confidence_mod"] = SimpleNamespace(generate_report=lambda *_args: {
            "go_decision": {"proceed": True, "blocking_reasons": [], "rationale": "mock validation"},
            "confidence": {"confidence_score": 100}})
        self.namespace["planner_mod"] = SimpleNamespace(generate_plan=lambda *_args: {
            "phases": [{"name": "shadow"}, {"name": "canary"}]})
        for level in ("low", "high", "critical"):
            with self.subTest(level=level):
                assessment = {"scan": {"summary": {"total_apis_detected": 0},
                                       "dependencies": [{"name": "package", "risk_level": level}]},
                              "risk_assessment": {"risk_score": 0, "difficulty": {"level": "low"}},
                              "rewrite_suggestions": {"suggestions": [], "summary": {"by_category": {}}}}
                self.namespace["assess_snapshot"] = lambda *_args: copy.deepcopy(assessment)
                with patch.object(scanner, "load_registry", return_value={"present": True}):
                    report = self.namespace["generate_full_report"](self.root, execute=True)
                blocked = level != "low"
                self.assertEqual(report["errors"], [])
                self.assertEqual(report["executive_summary"]["go_decision"], "NO-GO" if blocked else "GO")
                self.assertEqual(report["workflow_status"], "BLOCKED" if blocked else "VALIDATED")
                self.assertEqual(report["confidence"]["go_decision"]["proceed"], not blocked)
                self.assertEqual(report["rollout_plan"]["validation_gate"]["passed"], not blocked)
                self.assertEqual(report["rollout_plan"]["phases"][0]["status"],
                                 "blocked" if blocked else "eligible_for_evaluation")
                self.assertFalse(report["rollout_plan"]["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
