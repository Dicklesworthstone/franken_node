"""Reference expectations for direct Web stages in the shared Node pipeline.

These trusted local fixture programs are not sandboxed. Native compatibility
requires the existing project_compat_runner.py and a real FRANKEN_NODE_BIN.
No reference runtime is substituted for the native candidate.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / 'fixtures/compatibility/projects/stream-pipeline.corpus.json'


class PipelineProjectTests(unittest.TestCase):
    def test_five_complete_projects_with_independent_file_expectations(self):
        corpus = json.loads(CORPUS.read_text(encoding='utf-8'))
        self.assertEqual(corpus['schema_version'], 'franken-node/project-compat-corpus/v1')
        self.assertEqual(len(corpus['cases']), 5)
        self.assertEqual(len({case['id'] for case in corpus['cases']}), 5)
        self.assertTrue(all(len(case['files']) > 1 and case['expected']['files'] for case in corpus['cases']))

    @unittest.skipUnless(shutil.which('node'), 'requires a real Node reference')
    def test_every_project_matches_exact_streams_exit_status_and_files(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('FRANKEN_NODE_') and key not in
                       {'NODE_OPTIONS', 'NODE_PATH', 'BUN_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'}}
        corpus = json.loads(CORPUS.read_text(encoding='utf-8'))
        for case in corpus['cases']:
            with self.subTest(case=case['id']), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, source in case['files'].items():
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.encode('utf-8'))
                result = subprocess.run([shutil.which('node'), './' + case['entry']], cwd=root,
                                        env=environment, capture_output=True, timeout=15, check=False)
                expected = case['expected']
                self.assertEqual(result.returncode, expected['exit_code'], result.stderr)
                self.assertEqual(result.stdout, expected['stdout'].encode('utf-8'))
                self.assertEqual(result.stderr, expected['stderr'].encode('utf-8'))
                for name, contents in expected['files'].items():
                    target = root / name
                    self.assertFalse(target.is_symlink(), name)
                    if contents is None:
                        self.assertFalse(target.exists(), name)
                    else:
                        self.assertEqual(target.read_bytes(), contents.encode('utf-8'), name)

    @unittest.skipUnless(os.environ.get('FRANKEN_NODE_BIN'), 'set FRANKEN_NODE_BIN for actual native execution')
    def test_actual_native_project_runner(self):
        binary = os.environ['FRANKEN_NODE_BIN']
        with tempfile.TemporaryDirectory() as directory:
            command = [shutil.which('python3'), str(ROOT / 'scripts/project_compat_runner.py'),
                       '--corpus', str(CORPUS), '--bin', binary, '--node', shutil.which('node'),
                       '--artifacts-dir', str(Path(directory) / 'results')]
            if shutil.which('bun'):
                command.extend(['--bun', shutil.which('bun')])
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
