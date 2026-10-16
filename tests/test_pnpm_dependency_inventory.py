"""Actual filesystem/public-scanner-API tests; no package-manager execution."""
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import dependency_inventory as core
from scripts import pnpm_dependency_inventory as pnpm

NATIVE = {"sharp", "bcrypt", "canvas", "node-gyp"}
LOCK = """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      web:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  web@1.0.0:
    resolution: {integrity: sha512-web}
  sharp@0.33.0:
    resolution: {integrity: sha512-sharp}
    requiresBuild: true
    engines: {node: '>=18'}
    os: [linux, darwin]
    cpu: [x64, arm64]
snapshots:
  web@1.0.0:
    dependencies:
      image: sharp@0.33.0
  sharp@0.33.0: {}
"""


def basic():
    return {"lockfileVersion": "9.0", "importers": {".": {}}, "packages": {}, "snapshots": {}}


def add(lock, name, version="1.0.0", snapshot=None, **metadata):
    key = f"{name}@{version}"
    lock["packages"][key] = {"resolution": {"integrity": "sha512-test"}, **metadata}
    lock["snapshots"][key] = {} if snapshot is None else snapshot
    return key


class PnpmInventoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def write(self, name, data):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")

    def scan(self, **kwargs):
        return core.scan_dependencies(self.root, NATIVE, **kwargs)

    def test_public_scanner_captures_transitive_native_alias_without_installing(self):
        self.write("pnpm-lock.yaml", LOCK)
        self.write("package.json", {"dependencies": {"web": "^1.0.0"}})
        rows = self.scan()
        self.assertEqual([row["name"] for row in rows], ["sharp", "web"])
        self.assertEqual(rows[0]["risk_level"], "critical")
        self.assertTrue(rows[0]["requires_build"])
        self.assertFalse(rows[0]["has_install_script"])
        self.assertEqual(rows[0]["os"], ["linux", "darwin"])
        self.assertEqual(rows[0]["package_path"], "sharp@0.33.0")
        self.assertTrue(all(row["location_kind"] == "pnpm-dependency-path" for row in rows))
        self.assertTrue(all(row["resolution_verified"] is False for row in rows))
        self.assertFalse((self.root / "node_modules").exists())

    def test_scoped_alias_and_peer_contexts_remain_separate(self):
        lock = basic()
        add(lock, "@team/widget", peerDependencies={"react": "*"})
        lock["snapshots"] = {
            "@team/widget@1.0.0(react@18.0.0)": {"dependencies": {"react": "18.0.0"}},
            "@team/widget@1.0.0(react@19.0.0)": {"dependencies": {"react": "19.0.0"}},
        }
        add(lock, "react", "18.0.0")
        add(lock, "react", "19.0.0")
        lock["importers"]["."] = {"dependencies": {"ui": {
            "specifier": "npm:@team/widget@^1", "version": "@team/widget@1.0.0(react@18.0.0)"}}}
        self.write("pnpm-lock.yaml", lock)
        rows = self.scan()
        widgets = [row for row in rows if row["name"] == "@team/widget"]
        self.assertEqual(len(widgets), 2)
        self.assertEqual(len({row["package_path"] for row in widgets}), 2)
        self.assertTrue(all(row["risk_level"] == "low" for row in rows))

    def test_nested_peer_suffix_is_retained_and_unbalanced_suffix_rejected(self):
        key = "button@1.0.0(react@16.0.0(react-dom@16.0.0))"
        self.assertEqual(pnpm._identity(key), ("button@1.0.0", "button", "1.0.0"))
        for key in ["button@1.0.0(react@16", "button@1.0.0(react@16))", "button@1.0.0(x)tail"]:
            with self.subTest(key=key), self.assertRaises(core.InventoryError):
                pnpm._identity(key)

    def test_dependency_cycles_do_not_recurse_or_duplicate_rows(self):
        lock = basic()
        add(lock, "a", snapshot={"dependencies": {"b": "1.0.0"}})
        add(lock, "b", snapshot={"dependencies": {"a": "1.0.0"}})
        self.write("pnpm-lock.yaml", lock)
        self.assertEqual([row["name"] for row in self.scan()], ["a", "b"])

    def test_missing_transitive_snapshot_is_review_not_clean_graph(self):
        lock = basic()
        add(lock, "web", snapshot={"dependencies": {"image": "sharp@1.0.0"}})
        self.write("pnpm-lock.yaml", lock)
        sharp = next(row for row in self.scan() if row["name"] == "sharp")
        self.assertEqual(sharp["risk_level"], "critical")
        self.assertIsNone(sharp["package_path"])
        self.assertIn("snapshots/web", sharp["source"])

    def test_snapshot_without_package_metadata_fails_explicitly(self):
        lock = basic()
        lock["snapshots"]["web@1.0.0"] = {}
        self.write("pnpm-lock.yaml", lock)
        with self.assertRaises(core.InventoryError):
            self.scan()

    def test_unreferenced_package_metadata_is_not_discarded(self):
        lock = basic()
        key = add(lock, "sharp")
        lock["snapshots"].pop(key)
        self.write("pnpm-lock.yaml", lock)
        row = self.scan()[0]
        self.assertEqual(row["name"], "sharp")
        self.assertEqual(row["location_kind"], "pnpm-dependency-id")
        self.assertIn("closure is unknown", row["notes"])

    def test_stale_root_alias_cannot_hide_new_native_request(self):
        lock = basic()
        add(lock, "ordinary")
        lock["importers"]["."] = {"dependencies": {"image": {
            "specifier": "npm:ordinary@1", "version": "ordinary@1.0.0"}}}
        self.write("pnpm-lock.yaml", lock)
        self.write("package.json", {"dependencies": {"image": "npm:sharp@1"}})
        self.assertTrue(any(row["name"] == "sharp" and row["source"] == "package.json" for row in self.scan()))

    def test_stale_range_is_visible_without_claiming_semver_satisfaction(self):
        lock = basic()
        add(lock, "ordinary")
        lock["importers"]["."] = {"dependencies": {"ordinary": {
            "specifier": "^1", "version": "1.0.0"}}}
        self.write("pnpm-lock.yaml", lock)
        self.write("package.json", {"dependencies": {"ordinary": "^2"}})
        rows = self.scan()
        self.assertEqual(len(rows), 2)
        self.assertEqual(next(row for row in rows if row["source"] == "package.json")["risk_level"], "high")

    def test_locked_importers_are_inventoried_without_opening_their_paths(self):
        lock = basic()
        lock["importers"]["packages/unavailable"] = {"dependencies": {
            "sharp": {"specifier": "1", "version": "1.0.0"}}}
        self.write("pnpm-lock.yaml", lock)
        rows = self.scan()
        self.assertEqual(rows[0]["name"], "sharp")
        self.assertFalse((self.root / "packages").exists())
        lock["importers"]["../outside"] = {}
        self.write("pnpm-lock.yaml", lock)
        with self.assertRaises(core.InventoryError):
            self.scan()

    def test_current_workspace_manifest_is_seen_when_lock_importer_is_missing(self):
        self.write("pnpm-lock.yaml", basic())
        self.write("package.json", {})
        self.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
        self.write("packages/api/package.json", {"name": "api", "dependencies": {"sharp": "1"}})
        rows = self.scan()
        self.assertEqual(rows[0]["name"], "sharp")
        self.assertEqual(rows[0]["declared_in"], "packages/api/package.json")

    def test_additional_captured_manifests_are_checked_and_not_overwritten(self):
        self.write("pnpm-lock.yaml", basic())
        self.write("package.json", {})
        rows = self.scan(additional_manifests={"examples/app/package.json": {"dependencies": {"sharp": "1"}}})
        self.assertEqual(rows[0]["name"], "sharp")
        with self.assertRaises(core.InventoryError):
            self.scan(additional_manifests={"package.json": {"changed": True}})
        with self.assertRaises(core.InventoryError):
            self.scan(additional_manifests={"../package.json": {}})

    def test_local_git_tarball_and_missing_integrity_remain_review_items(self):
        for resolution in [{}, {"tarball": "https://example.invalid/a.tgz"}, {"directory": "../outside"}]:
            lock = basic()
            add(lock, "ordinary", resolution=resolution)
            self.write("pnpm-lock.yaml", lock)
            row = self.scan()[0]
            self.assertEqual(row["risk_level"], "high")
            self.assertFalse(row["resolution_verified"])
        lock = basic()
        lock["importers"]["."] = {"dependencies": {"local": {"specifier": "workspace:*", "version": "link:../outside"}}}
        self.write("pnpm-lock.yaml", lock)
        row = self.scan()[0]
        self.assertTrue(row["is_link"])
        self.assertEqual(row["risk_level"], "high")

    def test_missing_optional_and_peer_edges_are_visible(self):
        lock = basic()
        add(lock, "web", snapshot={"optionalDependencies": {"sharp": "1.0.0"}}, peerDependencies={"canvas": "*"})
        self.write("pnpm-lock.yaml", lock)
        self.assertEqual({row["name"] for row in self.scan()}, {"web", "sharp", "canvas"})

    def test_mixed_managers_and_unsupported_schema_never_fall_back(self):
        self.write("pnpm-lock.yaml", basic())
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        with self.assertRaisesRegex(core.InventoryError, "multiple lockfiles"):
            self.scan()
        for version in ["5.4", "6.0", True, 9, None, "10.0"]:
            lock = basic()
            lock["lockfileVersion"] = version
            with self.subTest(version=version), self.assertRaises(core.InventoryError):
                pnpm.inventory(lock, NATIVE, {})

    def test_hooks_and_unsupported_resolution_configuration_fail_before_execution(self):
        self.write("pnpm-lock.yaml", basic())
        self.write(".pnpmfile.cjs", "throw 'MUST_NOT_EXECUTE';")
        with self.assertRaisesRegex(core.InventoryError, "hooks"):
            self.scan()
        for field in ["catalogs", "packageExtensionsChecksum", "configDependencies", "packageManagerDependencies"]:
            lock = basic()
            lock[field] = {"sharp": "1"}
            with self.subTest(field=field), self.assertRaises(core.InventoryError):
                pnpm.inventory(lock, NATIVE, {})

    def test_symlink_lock_and_workspace_selection_are_not_followed(self):
        self.write("outside", LOCK)
        (self.root / "pnpm-lock.yaml").symlink_to("outside")
        with self.assertRaises(core.InventoryError):
            self.scan()
        other = self.root / "other"
        other.mkdir()
        (other / "pnpm-lock.yaml").write_text(LOCK)
        (other / "pnpm-workspace.yaml").write_text("packages:\n  - 'packages/*'\n")
        (other / "packages").symlink_to(self.root)
        with self.assertRaises(core.InventoryError):
            core.scan_dependencies(other, NATIVE)

    def test_special_files_and_byte_limits_fail_without_blocking(self):
        (self.root / "pnpm-lock.yaml").mkdir()
        with self.assertRaises(core.InventoryError):
            self.scan()
        self.write("large", LOCK)
        with self.assertRaises(core.InventoryError):
            pnpm.read_yaml(self.root / "large", 10)

    def test_node_line_edge_and_row_budgets_do_not_return_partial_inventory(self):
        with patch.object(pnpm, "MAX_YAML_NODES", 2), self.assertRaises(core.InventoryError):
            pnpm._Yaml(LOCK.encode()).parse()
        with patch.object(pnpm, "MAX_YAML_LINES", 2), self.assertRaises(core.InventoryError):
            pnpm._Yaml(LOCK.encode()).parse()
        lock = basic()
        add(lock, "web", snapshot={"dependencies": {"sharp": "1.0.0"}})
        with patch.object(core, "MAX_DEPENDENCY_EDGES", 0), self.assertRaises(core.InventoryError):
            pnpm.inventory(lock, NATIVE, {})
        with patch.object(core, "MAX_PACKAGES", 1), self.assertRaises(core.InventoryError):
            pnpm.inventory(lock, NATIVE, {})

    def test_large_inventory_is_deterministic(self):
        lock = basic()
        for number in range(1024):
            add(lock, f"pkg-{number}")
        self.write("pnpm-lock.yaml", lock)
        first = self.scan()
        self.assertEqual(len(first), 1024)
        lock["snapshots"] = dict(reversed(list(lock["snapshots"].items())))
        self.write("pnpm-lock.yaml", lock)
        self.assertEqual(self.scan(), first)

    def test_yaml_scalar_quotes_comments_and_flow_shapes(self):
        raw = b"a: 'it''s # quoted' # comment\nb: {x: [linux, '!win32'], y: true}\nc: \"escaped\\nline\"\nd: https://example.invalid/a#fragment\n"
        expected = {"a": "it's # quoted", "b": {"x": ["linux", "!win32"], "y": True},
                    "c": "escaped\nline", "d": "https://example.invalid/a#fragment"}
        self.assertEqual(pnpm._Yaml(raw).parse(), expected)

    def test_yaml_ambiguous_or_unsupported_input_is_never_clean(self):
        for raw in [
            "a: 1\na: 2", 'a: 1\n"\\u0061": 2', "a: {x: 1, x: 2}",
            "a: &anchor {}\nb: *anchor", "a: !!python/object:os.system {}", "a: {<<: {x: 1}}",
            "---\na: 1\n---\nb: 2", "a: |\n  multiline", "a: 'unterminated", 'a: "unterminated',
            "a: [1, 2", "a: {x: 1", "a: 1\n  hidden: 2", "a:\n\tbad: 1",
            "a: [,,]", "a: {} trailing", "a: 1\n...", "a: \"\\ud800\"",
        ]:
            with self.subTest(raw=raw), self.assertRaises(core.InventoryError):
                pnpm._Yaml(raw.encode()).parse()

    def test_yaml_utf8_and_depth_limits(self):
        with self.assertRaises(core.InventoryError):
            pnpm._Yaml(b"a: \xff").parse()
        for raw in ["a: " + "[" * 70 + "0" + "]" * 70,
                    "\n".join(" " * number + "a:" for number in range(70))]:
            with self.assertRaises(core.InventoryError):
                pnpm._Yaml(raw.encode()).parse()

    def test_json_compatible_flow_metadata_preserves_strings(self):
        rng = random.Random(71931)
        alphabet = "abc'\"{}[]:#,!*&β \\"
        for _ in range(256):
            value = "".join(rng.choice(alphabet) for _ in range(rng.randrange(80)))
            data = {"key": value, "bool": True, "null": None, "list": [value, 42]}
            self.assertEqual(pnpm._Yaml(json.dumps(data).encode()).parse(), data)

    def test_wrong_metadata_types_fail_explicitly(self):
        for field, value in [("optional", "false"), ("dependencies", []), ("transitivePeerDependencies", "sharp")]:
            lock = basic()
            add(lock, "web", snapshot={field: value})
            with self.subTest(field=field), self.assertRaises(core.InventoryError):
                pnpm.inventory(lock, NATIVE, {})

    def catalog_fixture(self, current="npm:ordinary@1", label="default"):
        lock = basic()
        add(lock, "ordinary")
        lock["catalogs"] = {label: {"image": {"specifier": "npm:ordinary@1", "version": "ordinary@1.0.0"}}}
        lock["importers"]["."] = {"dependencies": {"image": {
            "specifier": "catalog:" if label == "default" else f"catalog:{label}",
            "version": "ordinary@1.0.0"}}}
        self.write("pnpm-lock.yaml", lock)
        self.write("package.json", {"dependencies": {"image": "catalog:" if label == "default" else f"catalog:{label}"}})
        self.write("pnpm-workspace.yaml", {"catalog": {"image": current}} if label == "default"
                   else {"catalogs": {label: {"image": current}}})
        return lock

    def test_default_and_named_catalogs_resolve_exact_captured_declarations(self):
        for label in ["default", "legacy"]:
            self.catalog_fixture(label=label)
            rows = self.scan()
            self.assertEqual([row["name"] for row in rows], ["ordinary"])
            self.assertFalse(rows[0]["resolution_verified"])

    def test_changed_catalog_alias_exposes_native_target_behind_stale_lock(self):
        self.catalog_fixture(current="npm:sharp@1")
        rows = self.scan()
        sharp = next(row for row in rows if row["name"] == "sharp")
        self.assertEqual(sharp["source"], "package.json")
        self.assertEqual(sharp["risk_level"], "critical")

    def test_missing_recursive_and_ambiguous_catalogs_fail_explicitly(self):
        self.catalog_fixture()
        for workspace in [{}, {"catalog": {"image": "catalog:"}},
                          {"catalog": {}, "catalogs": {"default": {}}},
                          {"catalog": {"image": {"specifier": "1"}}}]:
            self.write("pnpm-workspace.yaml", workspace)
            with self.subTest(workspace=workspace), self.assertRaises(core.InventoryError):
                self.scan()

    def test_catalog_changes_in_selected_workspace_are_not_hidden(self):
        self.catalog_fixture(current="npm:canvas@1")
        self.write("package.json", {})
        self.write("pnpm-workspace.yaml", {"packages": ["packages/*"], "catalog": {"image": "npm:canvas@1"}})
        self.write("packages/app/package.json", {"name": "app", "dependencies": {"image": "catalog:"}})
        self.assertTrue(any(row["name"] == "canvas" and row["source"] == "packages/app/package.json" for row in self.scan()))

    def test_native_override_targets_are_visible_from_all_captured_sources(self):
        for source in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "package.json"]:
            lock = basic()
            add(lock, "ordinary")
            self.write("pnpm-lock.yaml", lock)
            self.write("package.json", {})
            self.write("pnpm-workspace.yaml", {})
            if source == "pnpm-lock.yaml":
                lock["overrides"] = {"parent@1>ordinary": "npm:sharp@1"}
                self.write(source, lock)
            elif source == "package.json":
                self.write(source, {"pnpm": {"overrides": {"ordinary": "npm:sharp@1"}}})
            else:
                self.write(source, {"overrides": {"ordinary": "npm:sharp@1"}})
            sharp = next(row for row in self.scan() if row["name"] == "sharp")
            self.assertEqual(sharp["risk_level"], "critical")
            self.assertEqual(sharp["dependency_kind"], "override")
            self.assertTrue(sharp["source"].startswith(source))

    def test_override_references_resolve_source_alias_not_old_snapshot(self):
        self.write("pnpm-lock.yaml", basic())
        self.write("package.json", {"dependencies": {"replacement": "npm:sharp@1"},
                                   "pnpm": {"overrides": {"ordinary": "$replacement"}}})
        row = next(row for row in self.scan() if row.get("dependency_kind") == "override")
        self.assertEqual(row["name"], "sharp")
        self.assertEqual(row["override_selector"], "ordinary")
        self.assertEqual(row["risk_level"], "critical")

    def test_unresolved_and_ambiguous_override_references_are_errors(self):
        self.write("pnpm-lock.yaml", basic())
        for request, dependencies in [("$missing", {}), ("$tool", {"tool": "$tool"})]:
            self.write("package.json", {"dependencies": dependencies, "pnpm": {"overrides": {"other": request}}})
            with self.assertRaises(core.InventoryError):
                self.scan()
        self.write("package.json", {"dependencies": {"tool": "1"}, "devDependencies": {"tool": "2"},
                                   "pnpm": {"overrides": {"other": "$tool"}}})
        with self.assertRaises(core.InventoryError):
            self.scan()

    def test_patches_and_removal_requests_remain_review_without_opening_targets(self):
        lock = basic()
        add(lock, "ordinary")
        lock["patchedDependencies"] = {"ordinary@1.0.0": {"path": "../not-opened.patch", "hash": "recorded"}}
        self.write("pnpm-lock.yaml", lock)
        self.write("pnpm-workspace.yaml", {"overrides": {"parent@1>ordinary": "-"}})
        rows = self.scan()
        patch_row = next(row for row in rows if row.get("dependency_kind") == "patch")
        removal = next(row for row in rows if row.get("dependency_kind") == "override")
        self.assertEqual(patch_row["patch_reference"], "../not-opened.patch")
        self.assertEqual(patch_row["risk_level"], "high")
        self.assertEqual(removal["version"], "-")
        self.assertEqual(removal["risk_level"], "high")

    def test_catalog_override_and_patch_entries_share_edge_budget(self):
        lock = basic()
        lock["overrides"] = {"a": "1", "b": "2"}
        with patch.object(core, "MAX_DEPENDENCY_EDGES", 1), self.assertRaises(core.InventoryError):
            pnpm.inventory(lock, NATIVE, {})
        lock = basic()
        lock["catalogs"] = {"default": {"a": {"specifier": "1", "version": "1.0.0"}}}
        with patch.object(core, "MAX_DEPENDENCY_EDGES", 0), self.assertRaises(core.InventoryError):
            pnpm.inventory(lock, NATIVE, {})

    def test_standalone_script_import_uses_the_same_inventory(self):
        self.write("pnpm-lock.yaml", LOCK)
        program = "import json,sys; from pathlib import Path; from dependency_inventory import scan_dependencies; print(json.dumps(scan_dependencies(Path(sys.argv[1]), {'sharp'})))"
        process = subprocess.run([sys.executable, "-c", program, str(self.root)],
                                 cwd=ROOT / "scripts", capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(any(row["name"] == "sharp" for row in json.loads(process.stdout)))

    def test_missing_bare_peer_pin_is_not_misread_as_an_alias(self):
        lock = basic()
        add(lock, "web", snapshot={"dependencies": {"widget": "1.0.0(react@18.0.0)"}})
        rows = pnpm.inventory(lock, NATIVE, {})
        missing = next(row for row in rows if row["name"] == "widget")
        self.assertEqual(missing["version"], "1.0.0")
        self.assertEqual(missing["risk_level"], "high")

    def test_additional_root_configuration_cannot_bypass_hook_review(self):
        self.write("pnpm-lock.yaml", basic())
        with self.assertRaises(core.InventoryError):
            self.scan(additional_manifests={"package.json": {"pnpm": {"packageExtensions": {"web": {}}}}})


if __name__ == "__main__":
    unittest.main()
