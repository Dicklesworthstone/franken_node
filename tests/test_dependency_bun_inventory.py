"""Bun text-lock metadata inventory, not Bun installation or native admission.

Use actual files and the scanner CLI. Literal tuples follow Bun's published
BunLockFile contract; no package manager, network, install script or JS runs.
"""
import copy
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import dependency_inventory as inventory
from scripts import project_scanner as scanner


def registry(name, version='1.0.0', **info):
    return [name + '@' + version, '', info, 'sha512-unverified-fixture']


class BunInventoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding='utf-8')

    def lock(self, records, **extra):
        data = {'lockfileVersion': 1, 'workspaces': {'': {}}, 'packages': records}
        data.update(extra)
        self.write('bun.lock', data)
        return data

    def scan(self, **kwargs):
        return inventory.scan_dependencies(self.root, scanner.NATIVE_ADDON_PACKAGES, **kwargs)

    def test_v1_and_v2_metadata_expose_transitive_native_risk_in_actual_report(self):
        self.write('package.json', {'dependencies': {'app': '^1'}})
        for version in (1, 2):
            self.lock({'app': registry('app', dependencies={'image': 'npm:sharp@^0.33'}),
                       'app/image': registry('sharp', '0.33.0')}, lockfileVersion=version,
                      configVersion=1)
            report = scanner.scan_project(self.root)
            self.assertEqual(report['summary']['migration_readiness'], 'not-ready')
            self.assertEqual(report['summary']['risk_distribution']['critical'], 1)
            row = next(row for row in report['dependencies'] if row['name'] == 'sharp')
            self.assertEqual(row['package_path'], 'app/image')
            self.assertEqual(row['location_kind'], 'bun-logical')
            self.assertEqual(row['version'], '0.33.0')
            self.assertIn('image', row['notes'])
            self.assertFalse(row['resolution_verified'])

    def test_scoped_nested_packages_and_duplicate_versions_retain_each_location(self):
        self.lock({'@scope/tool': registry('@scope/tool', '2.0.0'),
                   '@scope/app/@scope/tool': registry('@scope/tool'),
                   'other/@scope/tool': registry('@scope/tool')})
        rows = self.scan()
        self.assertEqual([row['version'] for row in rows], ['1.0.0', '1.0.0', '2.0.0'])
        self.assertEqual(len({row['package_path'] for row in rows}), 3)
        self.assertTrue(all(row['location_kind'] == 'bun-logical' for row in rows))

    def test_missing_transitive_dependency_and_native_alias_cannot_be_silent(self):
        self.lock({'app': registry('app', dependencies={'image': 'npm:sharp@^1'},
                                   optionalDependencies={'addon': '^2'})})
        rows = self.scan()
        sharp = next(row for row in rows if row['name'] == 'sharp')
        self.assertEqual(sharp['risk_level'], 'critical')
        self.assertEqual(sharp['source'], 'bun.lock#packages/app')
        self.assertIsNone(sharp['package_path'])
        addon = next(row for row in rows if row['name'] == 'addon')
        self.assertEqual(addon['risk_level'], 'high')
        self.assertEqual(addon['dependency_kind'], 'optionalDependencies')

    def test_root_declaration_cannot_match_only_a_nested_package(self):
        self.write('package.json', {'dependencies': {'tool': '^2'}})
        self.lock({'app/tool': registry('tool')})
        rows = self.scan()
        self.assertEqual(len(rows), 2)
        self.assertEqual(next(r for r in rows if r['source'] == 'package.json')['risk_level'], 'high')

    def test_current_alias_identity_is_checked_before_suppressing_declarations(self):
        self.write('package.json', {'dependencies': {'quiet': 'npm:sharp@^1'}})
        self.lock({'quiet': registry('pure-js')})
        rows = self.scan()
        self.assertEqual({r['name'] for r in rows}, {'sharp', 'pure-js'})
        self.assertEqual(next(r for r in rows if r['name'] == 'sharp')['source'], 'package.json')

    def test_workspace_private_dependencies_use_logical_name_not_disk_directory(self):
        self.write('package.json', {'workspaces': ['packages/*']})
        workspace = {'name': '@scope/app', 'version': '1.0.0',
                     'dependencies': {'tool': '^2', 'common': '^1'}}
        self.write('packages/service/package.json', workspace)
        self.lock({'@scope/app': ['@scope/app@workspace:packages/service'],
                   '@scope/app/tool': registry('tool', '2.1.0'), 'common': registry('common')},
                  workspaces={'': {}, 'packages/service': workspace}, configVersion=1)
        rows = self.scan()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row['source'] == 'bun.lock' for row in rows))
        self.assertEqual(next(row for row in rows if row['name'] == 'tool')['risk_level'], 'low')
        link = next(row for row in rows if row['name'] == '@scope/app')
        self.assertTrue(link['is_link'])
        self.assertEqual(link['risk_level'], 'high')
        self.assertFalse((self.root / 'node_modules').exists())

    def test_lock_only_workspaces_keep_missing_requests_without_fabricated_file_reads(self):
        self.lock({'api': ['api@workspace:packages/api']}, workspaces={
            '': {'dependencies': {'api': 'workspace:*'}},
            'packages/api': {'name': 'api', 'dependencies': {'sharp': '^1'}}})
        rows = self.scan()
        native = next(row for row in rows if row['name'] == 'sharp')
        self.assertEqual(native['source'], 'bun.lock#workspaces/packages/api')
        self.assertFalse((self.root / 'packages').exists())

    def test_current_workspace_identity_mismatch_refuses_stale_resolution(self):
        self.write('package.json', {'workspaces': ['packages/*']})
        self.write('packages/api/package.json', {'name': 'renamed', 'dependencies': {'tool': '^1'}})
        self.lock({}, workspaces={'': {}, 'packages/api': {'name': 'old-name'}})
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_workspace_directory_named_catalog_is_not_a_catalog_definition(self):
        self.lock({'app': ['app@workspace:catalog'], 'tool': registry('tool')},
                  workspaces={'': {}, 'catalog': {'name': 'app', 'dependencies': {'tool': '^1'}}})
        rows = self.scan()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['source'] == 'bun.lock' for row in rows))

    def test_workspace_links_require_a_canonical_matching_descriptor(self):
        for target in ('../outside', 'missing', 'packages/other'):
            self.lock({'api': ['api@workspace:' + target]},
                      workspaces={'': {}, 'packages/other': {'name': 'different'}})
            with self.subTest(target=target), self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_local_git_and_tarball_sources_are_review_items_never_opened(self):
        self.lock({'local': ['local@file:../outside', {}],
                   'linked': ['linked@link:/private/data', {}],
                   'remote': ['remote@https://example.invalid/pkg.tgz', {}],
                   'git': ['git@git+ssh://git@example.invalid/repo#abc', {}, 'tag']})
        rows = self.scan()
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row['risk_level'] == 'high' for row in rows))
        self.assertTrue(all('no target was opened' in row['notes'] for row in rows))
        self.assertTrue(all(not row['resolution_verified'] for row in rows))
        self.assertEqual({p.name for p in self.root.iterdir()}, {'bun.lock'})

    def test_explicit_trust_does_not_invent_script_presence_or_execution(self):
        self.write('package.json', {'trustedDependencies': ['from-manifest']})
        self.lock({'assets': registry('assets'), 'other': registry('other'),
                   'from-manifest': registry('from-manifest')}, trustedDependencies=['assets'])
        rows = {row['name']: row for row in self.scan()}
        for name in ('assets', 'from-manifest'):
            self.assertTrue(rows[name]['explicitly_trusted'])
            self.assertFalse(rows[name]['has_install_script'])
            self.assertFalse(rows[name]['has_native_addon'])
            self.assertEqual(rows[name]['risk_level'], 'high')
        self.assertFalse(rows['other']['explicitly_trusted'])
        self.assertNotIn('install_scripts_allowed', rows['other'])

    def test_patch_and_missing_integrity_are_reported_as_unverified_risk(self):
        missing = registry('missing')
        missing[3] = ''
        self.lock({'assets': registry('assets'), 'missing': missing},
                  patchedDependencies={'assets@1.0.0': 'patches/assets.patch'})
        rows = self.scan()
        self.assertTrue(all(row['risk_level'] == 'high' for row in rows))
        self.assertEqual(rows[0]['patch_reference'], 'patches/assets.patch')
        self.assertFalse((self.root / 'patches').exists())
        self.assertIsNone(rows[1]['integrity'])

    def test_catalogs_resolve_alias_identity_without_claiming_range_satisfaction(self):
        self.write('package.json', {'dependencies': {'image': 'catalog:', 'lib': 'catalog:tools'},
                                   'catalog': {'image': 'npm:sharp@^0.33'},
                                   'catalogs': {'tools': {'lib': 'npm:@scope/lib@^1'}}})
        self.lock({'image': registry('sharp', '0.33.0'), 'lib': registry('@scope/lib', '1.2.3')},
                  catalog={'image': 'npm:sharp@^0.33'}, catalogs={'tools': {'lib': 'npm:@scope/lib@^1'}})
        rows = self.scan()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['source'] == 'bun.lock' for row in rows))
        self.assertTrue(all(row['resolution_verified'] is False for row in rows))
        self.assertEqual({row['name'] for row in rows}, {'sharp', '@scope/lib'})

    def test_current_catalog_alias_cannot_be_hidden_by_a_stale_lock_catalog(self):
        self.write('package.json', {'dependencies': {'image': 'catalog:'},
                                   'catalog': {'image': 'npm:sharp@^0.33'}})
        self.lock({'image': registry('pure-js')}, catalog={'image': 'npm:pure-js@^1'})
        rows = self.scan()
        sharp = next(row for row in rows if row['name'] == 'sharp')
        self.assertEqual(sharp['source'], 'package.json')
        self.assertEqual(sharp['risk_level'], 'critical')

    def test_bun_workspace_object_and_default_catalog_share_the_bounded_walker(self):
        root = {'workspaces': {'packages': ['packages/*'],
                              'catalogs': {'default': {'tool': '^1'}}}}
        workspace = {'name': 'app', 'dependencies': {'tool': 'catalog:default'}}
        self.write('package.json', root)
        self.write('packages/app/package.json', workspace)
        self.lock({'tool': registry('tool')}, workspaces={'': {}, 'packages/app': workspace})
        self.assertEqual(len(self.scan()), 1)

    def test_ambiguous_and_overlapping_catalog_definitions_are_not_guessed(self):
        self.lock({})
        for root in ({'catalog': {'a': '^1'}, 'catalogs': {'default': {'a': '^2'}}},
                     {'catalog': {}, 'workspaces': {'packages': [], 'catalog': {}}}):
            self.write('package.json', root)
            with self.subTest(root=root), self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_current_override_alias_remains_visible_even_with_an_old_locked_name(self):
        self.write('package.json', {'dependencies': {'image': '^1'},
                                   'overrides': {'image': 'npm:sharp@0.33.0'}})
        self.lock({'image': registry('image')})
        rows = self.scan()
        sharp = next(row for row in rows if row['name'] == 'sharp')
        self.assertEqual(sharp['source'], 'package.json#overrides')
        self.assertEqual(sharp['risk_level'], 'critical')
        self.assertIn('Override', sharp['notes'])

    def test_current_manifest_patch_is_not_hidden_by_a_stale_lock(self):
        self.write('package.json', {'patchedDependencies': {'assets@1.0.0': 'new.patch'}})
        self.lock({'assets': registry('assets')})
        row = self.scan()[0]
        self.assertEqual(row['patch_reference'], 'new.patch')
        self.assertEqual(row['risk_level'], 'high')

    def test_unresolved_catalog_is_not_a_clean_inventory(self):
        self.write('package.json', {'dependencies': {'safe': 'catalog:missing'}})
        self.lock({'safe': registry('safe')})
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_optional_platform_records_are_kept_not_filtered_using_host_architecture(self):
        self.lock({'native': registry('sharp', os=['darwin'], cpu='arm64', optionalPeers=['peer']),
                   'optional': registry('optional', optionalDependencies={'missing': '*'},
                                        hasInstallScript=True)})
        rows = self.scan()
        native = next(row for row in rows if row['name'] == 'sharp')
        self.assertEqual(native['os'], ['darwin'])
        self.assertEqual(native['cpu'], 'arm64')
        self.assertEqual(native['risk_level'], 'critical')
        self.assertTrue(next(row for row in rows if row['name'] == 'optional')['has_install_script'])

    def test_jsonc_preserves_strings_urls_comments_and_escaped_quotes(self):
        raw = r'''{/*header*/"lockfileVersion":2,"workspaces":{"":{},},
"packages":{"safe":["safe@1.0.0","https://example.invalid/a/*literal*/",{},"sha512-a//b",],},
"ignored":"quote\"slash\\///*,}",// final comment
}'''
        (self.root / 'bun.lock').write_text(raw)
        row = self.scan()[0]
        self.assertEqual(row['integrity'], 'sha512-a//b')
        self.assertEqual(row['name'], 'safe')

    def test_seeded_jsonc_string_preservation_against_literal_json_values(self):
        rng = random.Random(20261015)
        alphabet = 'abc"\\/\r\n\t[]{}:,/*é😀'
        for _ in range(512):
            value = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(64)))
            raw = ('{/* before */"value":' + json.dumps(value, ensure_ascii=False) + ',// after\n}').encode()
            self.assertEqual(json.loads(inventory._jsonc(raw)), {'value': value})

    def test_malformed_jsonc_remains_invalid_not_silently_normalized(self):
        cases = [b'{', b'{/*unterminated', b'{"a":"unterminated}', b'{"a":,}',
                 b'{"a":[,]}', b'{"a":[1,,]}', b'{"a":NaN}', b'{"a":1,"a":2}',
                 b'{"a":\'single\'}', b'{unquoted:1}', b'{//\xff\n}',
                 b'{"a":1,/*ok*/,"b":2}']
        for raw in cases:
            (self.root / 'bun.lock').write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_jsonc_syntax_is_not_accidentally_enabled_for_npm(self):
        (self.root / 'package-lock.json').write_text('{"lockfileVersion":3,"packages":{},}')
        with self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_schema_and_tuple_corruption_do_not_fall_back_to_package_json(self):
        self.write('package.json', {'dependencies': {'safe': '^1'}})
        bad = [[], ['safe'], ['safe@^1', '', {}, 'digest'],
               ['safe@1.0.0', '', [], 'digest'], ['safe@1.0.0', '', {}, False],
               ['safe@1.0.0', '', {}, 'digest', 'extra'],
               ['safe@1.0.0', '', {'dependencies': []}, 'digest'],
               ['safe@1.0.0', '', {'hasInstallScript': 'true'}, 'digest'],
               ['safe@1.0.0', '', {'optionalPeers': 'peer'}, 'digest']]
        for values in bad:
            self.lock({'safe': values})
            with self.subTest(values=values), self.assertRaises(inventory.InventoryError):
                self.scan()
        for override in ({'lockfileVersion': 3}, {'lockfileVersion': True}, {'configVersion': 2},
                         {'packages': []}, {'workspaces': {}}, {'trustedDependencies': {}},
                         {'catalogs': []}, {'overrides': []}):
            self.lock({}, **override)
            with self.subTest(override=override), self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_invalid_logical_paths_cannot_be_projected_into_a_false_inventory(self):
        for key in ('../safe', '/safe', 'a//b', '@scope', 'a/./b', 'a\\b', 'a:b'):
            self.lock({key: registry('safe')})
            with self.subTest(key=key), self.assertRaises(inventory.InventoryError):
                self.scan()

    def test_binary_and_mixed_manager_inputs_require_explicit_authority_selection(self):
        (self.root / 'bun.lockb').write_bytes(b'not text')
        with self.assertRaisesRegex(inventory.InventoryError, 'binary bun.lockb'):
            self.scan()
        self.lock({})
        with self.assertRaisesRegex(inventory.InventoryError, 'multiple lockfiles'):
            self.scan()
        for filename in ('package-lock.json', 'npm-shrinkwrap.json'):
            with tempfile.TemporaryDirectory() as directory:
                project = Path(directory)
                (project / filename).write_text('{"lockfileVersion":3,"packages":{}}')
                (project / 'bun.lock').write_text('{"lockfileVersion":1,"workspaces":{"":{}},"packages":{}}')
                with self.assertRaises(inventory.InventoryError):
                    inventory.scan_dependencies(project, set())

    def test_symlink_and_fifo_locks_are_rejected_without_reading(self):
        for kind in ('link', 'fifo'):
            with tempfile.TemporaryDirectory() as directory:
                project = Path(directory)
                target = project / 'bun.lock'
                if kind == 'link':
                    target.symlink_to('missing')
                else:
                    os.mkfifo(target)
                with self.assertRaises(inventory.InventoryError):
                    inventory.scan_dependencies(project, set())

    def test_byte_package_depth_workspace_and_edge_limits_fail_explicitly(self):
        self.lock({'a': registry('a', dependencies={'b': '*', 'c': '*'}), 'b': registry('b')})
        for limit in [('MAX_LOCK_BYTES', 10), ('MAX_PACKAGES', 1),
                      ('MAX_DEPTH', 1), ('MAX_DEPENDENCY_EDGES', 1)]:
            with self.subTest(limit=limit), patch.object(inventory, *limit):
                with self.assertRaises(inventory.InventoryError):
                    self.scan()
        self.lock({}, workspaces={'': {}, 'one': {'name': 'one'}, 'two': {'name': 'two'}})
        with patch.object(inventory, 'MAX_WORKSPACES', 1), self.assertRaises(inventory.InventoryError):
            self.scan()

    def test_bounded_many_package_inventory_is_deterministic(self):
        packages = {f'app/{index}': registry('tool', f'1.0.{index}') for index in range(2048)}
        self.lock(packages)
        first = self.scan()
        self.lock(dict(reversed(list(packages.items()))))
        self.assertEqual(first, self.scan())
        self.assertEqual(len(first), 2048)
        self.assertEqual(len({row['package_path'] for row in first}), 2048)

    def test_additional_captured_workspace_declarations_share_bun_scope_lookup(self):
        record = {'name': 'app', 'dependencies': {'tool': '^1'}}
        self.lock({'app/tool': registry('tool')}, workspaces={'': {}, 'packages/app': record})
        rows = self.scan(additional_manifests={'packages/app/package.json': copy.deepcopy(record)})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['source'], 'bun.lock')

    def test_cli_combines_application_api_and_bun_risk_without_running_code(self):
        (self.root / 'app.js').write_text('process.env.MODE; throw Error("must not execute");')
        self.lock({'app': registry('app', dependencies={'sharp': '^0.33'}),
                   'app/sharp': registry('sharp', '0.33.0')})
        command = [sys.executable, str(ROOT / 'scripts/project_scanner.py'), str(self.root), '--json']
        process = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report['summary']['migration_readiness'], 'not-ready')
        self.assertEqual(report['summary']['total_apis_detected'], 1)
        self.assertEqual(len(report['dependencies']), 2)
        (self.root / 'bun.lock').write_text('{')
        process = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertNotIn('summary', json.loads(process.stdout))
        self.assertIn(b'starting project_scanner', process.stderr)

    def test_npm_v1_v2_v3_and_workspace_behavior_remain_available(self):
        for version in (1, 2, 3):
            with tempfile.TemporaryDirectory() as directory:
                project = Path(directory)
                packages = ({'dependencies': {'image': {'version': 'npm:sharp@0.33.0'}}}
                            if version == 1 else
                            {'packages': {'node_modules/image': {'name': 'sharp', 'version': '0.33.0'}}})
                (project / 'package-lock.json').write_text(json.dumps({'lockfileVersion': version, **packages}))
                rows = inventory.scan_dependencies(project, scanner.NATIVE_ADDON_PACKAGES)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['risk_level'], 'critical')
                self.assertEqual(rows[0]['package_path'], 'node_modules/image')
                self.assertNotIn('location_kind', rows[0])


if __name__ == '__main__':
    unittest.main()
