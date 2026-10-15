"""Real-tree regressions for the product scanner's bounded source inventory.

No JavaScript is executed. The source scanner remains a lexical risk detector,
not a parser, installed-tree validator, sandbox, or engine compatibility test.
"""
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
from scripts import project_scanner as scanner
from scripts.dependency_inventory import InventoryError


class SourceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def source(self, name, text='process.env.MODE;'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def scan(self):
        return scanner.scan_project(self.root)

    def test_root_and_source_names_containing_node_modules_are_not_excluded(self):
        self.root = self.root / 'node_modules-migration-project'
        self.source('node_modules_tools.js', 'eval("blocked");')
        self.source('src/not_node_modules/app.mts', 'new Function("blocked");')
        report = self.scan()
        self.assertEqual(report['summary']['migration_readiness'], 'not-ready')
        self.assertEqual(report['summary']['risk_distribution']['critical'], 2)

    def test_all_eight_extensions_and_hidden_sources_are_scanned_once(self):
        paths = [self.source('src/file' + ext) for ext in scanner.JS_EXTENSIONS]
        paths.append(self.source('src/.hidden.js'))
        report = self.scan()
        self.assertEqual(len(report['api_usage']), 9)
        self.assertEqual({row['source_file'] for row in report['api_usage']}, set(map(str, paths)))

    def test_installed_and_metadata_trees_are_pruned_before_enumeration(self):
        self.source('src/app.js')
        for name in scanner.SOURCE_EXCLUSIONS:
            self.source(f'{name}/nested/poison.js', 'eval("not application code");')
        # A malformed installed source and cyclic installed symlink must not
        # be read or traversed. That data has a separate dependency inspector.
        (self.root / 'node_modules/loop').symlink_to('../node_modules', target_is_directory=True)
        visited = []
        scandir = os.scandir
        def observe(fd):
            visited.append((os.fstat(fd).st_dev, os.fstat(fd).st_ino))
            return scandir(fd)
        with patch.object(scanner.os, 'scandir', observe), patch.object(
                scanner.os, 'supports_fd', {*os.supports_fd, observe}):
            report = self.scan()
        expected = [self.root.stat(), (self.root / 'src').stat()]
        self.assertEqual(visited, [(item.st_dev, item.st_ino) for item in expected])
        self.assertEqual(report['summary']['total_apis_detected'], 1)

    def test_nested_workspace_installs_are_pruned_but_sources_are_retained(self):
        self.source('packages/api/main.ts')
        self.source('packages/api/node_modules/.bun/pkg/node_modules/pkg/native.js', 'eval("bad");')
        self.source('packages/ui/main.tsx')
        self.assertEqual(len(self.scan()['api_usage']), 2)

    def test_filesystem_creation_order_does_not_change_source_order(self):
        for name in ['z.cjs', 'src/b.ts', 'src/a.js', '.hidden.mjs', 'a.js']:
            self.source(name)
        first = self.scan()['api_usage']
        other = self.root / 'other'
        other.mkdir()
        for row in reversed(first):
            relative = Path(row['source_file']).relative_to(self.root)
            target = other / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('process.env.MODE;')
        second = scanner.scan_project(other)['api_usage']
        self.assertEqual([Path(r['source_file']).relative_to(self.root) for r in first],
                         [Path(r['source_file']).relative_to(other) for r in second])

    def test_current_api_rules_and_registry_bands_are_preserved(self):
        file = self.source('app.js', "fs.readFileSync('x'); path.join('a','b'); process.env.KEY; eval('x');")
        registry = {('path', 'join'): {'band': 'core', 'shim_type': 'native'}}
        with patch.object(scanner, 'load_registry', return_value=registry):
            rows = self.scan()['api_usage']
        self.assertEqual(rows, scanner.scan_file(file, registry))
        self.assertEqual([r['risk_level'] for r in rows], ['medium', 'low', 'medium', 'critical'])

    def test_newline_and_invalid_utf8_handling_match_the_existing_detector(self):
        file = self.root / 'app.js'
        file.write_bytes(b'\xff\r\nprocess.env.X;\reval("x");')
        rows = self.scan()['api_usage']
        self.assertEqual([r['api_name'] for r in rows], ['env', 'eval'])

    def test_missing_and_non_directory_roots_cannot_report_ready(self):
        with self.assertRaises(OSError):
            scanner.scan_project(self.root / 'missing')
        file = self.source('app.js')
        with self.assertRaises(OSError):
            scanner.scan_project(file)

    def test_source_symlink_is_rejected_without_reading_its_target(self):
        target = self.source('target.txt', 'eval("secret");')
        (self.root / 'app.js').symlink_to(target)
        with patch.object(scanner.os, 'read', side_effect=AssertionError('must not read')):
            with self.assertRaises(InventoryError):
                self.scan()

    def test_directory_and_root_symlinks_are_rejected(self):
        target = self.root / 'target'
        target.mkdir()
        (self.root / 'src').symlink_to(target, target_is_directory=True)
        with self.assertRaises(InventoryError):
            self.scan()
        with self.assertRaises(OSError):
            scanner.scan_project(self.root / 'src')

    def test_fifo_source_is_refused_without_blocking(self):
        os.mkfifo(self.root / 'stream.js')
        with self.assertRaises(InventoryError):
            self.scan()

    def test_standalone_missing_and_linked_sources_are_not_silently_empty(self):
        with self.assertRaises(OSError):
            scanner.scan_file(self.root / 'missing.js', {})
        target = self.source('target.js')
        (self.root / 'alias.js').symlink_to(target)
        with self.assertRaises(InventoryError):
            scanner.scan_file(self.root / 'alias.js', {})

    def test_unreadable_source_propagates_instead_of_becoming_zero_risk(self):
        self.source('app.js')
        with patch.object(scanner.os, 'read', side_effect=PermissionError('source denied')):
            with self.assertRaises(PermissionError):
                self.scan()

    def test_source_growth_during_read_is_rejected(self):
        file = self.source('app.js')
        read = os.read
        changed = False
        def mutate(fd, length):
            nonlocal changed
            if not changed:
                changed = True
                with file.open('ab') as writer:
                    writer.write(b'eval("late");')
            return read(fd, length)
        with patch.object(scanner.os, 'read', mutate):
            with self.assertRaisesRegex(InventoryError, 'source changed during capture'):
                self.scan()

    def test_directory_replacement_cannot_redirect_source_reads(self):
        self.source('src/app.js')
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'secret.js').write_text('eval("secret");')
        scandir = os.scandir
        replaced = False
        def swap(fd):
            nonlocal replaced
            entries = scandir(fd)
            if replaced:
                return entries
            replaced = True
            # Replace the child only after its original DirEntry was recorded.
            class Enumeration:
                def __enter__(self):
                    return iter(list(entries))
                def __exit__(self, *args):
                    entries.close()
                    (self_root / 'src').rename(self_root / 'original-src')
                    (self_root / 'src').symlink_to(outside, target_is_directory=True)
            return Enumeration()
        self_root = self.root
        with patch.object(scanner.os, 'scandir', swap), patch.object(
                scanner.os, 'supports_fd', {*os.supports_fd, swap}):
            with self.assertRaises((InventoryError, OSError)):
                self.scan()

    def test_file_and_total_byte_limits_never_truncate_to_success(self):
        self.source('a.js', 'process.env.X;')
        self.source('b.js', 'process.env.Y;')
        for limit in [('MAX_SOURCE_BYTES', 2), ('MAX_TOTAL_SOURCE_BYTES', 20), ('MAX_SOURCE_FILES', 1)]:
            with self.subTest(limit=limit), patch.object(scanner, *limit):
                with self.assertRaises(InventoryError):
                    self.scan()

    def test_entry_directory_depth_and_deadline_limits_are_enforced(self):
        self.source('src/deep/app.js')
        for limit in [('MAX_SOURCE_ENTRIES', 1), ('MAX_SOURCE_DIRECTORIES', 1),
                      ('MAX_SOURCE_DEPTH', 1), ('MAX_SOURCE_PATH_BYTES', 1), ('MAX_SOURCE_SECONDS', 0)]:
            with self.subTest(limit=limit), patch.object(scanner, *limit):
                with self.assertRaises(InventoryError):
                    self.scan()

    def test_descriptors_are_closed_on_every_failure_path(self):
        self.source('src/app.js')
        if not Path('/proc/self/fd').is_dir():
            self.skipTest('Linux descriptor inventory')
        before = set(os.listdir('/proc/self/fd'))
        for _ in range(20):
            with patch.object(scanner, 'MAX_TOTAL_SOURCE_BYTES', 0):
                with self.assertRaises(InventoryError):
                    self.scan()
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_cli_reports_incomplete_input_as_error_not_partial_summary(self):
        (self.root / 'bad.js').symlink_to('missing.js')
        run = subprocess.run([sys.executable, str(ROOT / 'scripts/project_scanner.py'),
                              str(self.root), '--json'], capture_output=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 2, run.stderr)
        output = json.loads(run.stdout)
        self.assertEqual(output['status'], 'error')
        self.assertNotIn('summary', output)
        self.assertIn(b'starting project_scanner', run.stderr)

    def test_cli_preserves_real_dependency_risk_and_source_findings(self):
        self.source('app.js', 'process.env.MODE;')
        (self.root / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
            'node_modules/web': {'version': '1.0.0'},
            'node_modules/web/node_modules/sharp': {'version': '0.33.0'}}}))
        run = subprocess.run([sys.executable, str(ROOT / 'scripts/project_scanner.py'),
                              str(self.root), '--json'], capture_output=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        output = json.loads(run.stdout)
        self.assertEqual(output['summary']['migration_readiness'], 'not-ready')
        self.assertEqual(output['summary']['total_apis_detected'], 1)
        self.assertEqual(len(output['dependencies']), 2)


if __name__ == '__main__':
    unittest.main()
