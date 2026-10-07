"""Real metadata and scanner-CLI regressions for transitive npm inventory."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
