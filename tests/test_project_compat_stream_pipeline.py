"""Reference expectations for shared Node/Web pipelines and reusable composition.

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
    corpus_path = CORPUS
    case_count = 7

    def test_complete_projects_with_independent_file_expectations(self):
        corpus = json.loads(self.corpus_path.read_text(encoding='utf-8'))
        self.assertEqual(corpus['schema_version'], 'franken-node/project-compat-corpus/v1')
        self.assertEqual(len(corpus['cases']), self.case_count)
        self.assertEqual(len({case['id'] for case in corpus['cases']}), self.case_count)
        self.assertTrue(all(len(case['files']) > 1 and case['expected']['files'] for case in corpus['cases']))

    @unittest.skipUnless(shutil.which('node'), 'requires a real Node reference')
    def test_every_project_matches_exact_streams_exit_status_and_files(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('FRANKEN_NODE_') and key not in
                       {'NODE_OPTIONS', 'NODE_PATH', 'BUN_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'}}
        corpus = json.loads(self.corpus_path.read_text(encoding='utf-8'))
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
                       '--corpus', str(self.corpus_path), '--bin', binary, '--node', shutil.which('node'),
                       '--artifacts-dir', str(Path(directory) / 'results')]
            if shutil.which('bun'):
                command.extend(['--bun', shutil.which('bun')])
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class CompositionProjectTests(PipelineProjectTests):
    # Apply the same exact-output and opt-in native checks to the new cohort.
    # The original pipeline corpus and its seven-case requirement are unchanged.
    corpus_path = ROOT / 'fixtures/compatibility/projects/stream-compose.corpus.json'
    case_count = 5


class CallbackFilesystemProjectTests(PipelineProjectTests):
    # Callback-based file workflows use the same exact-output and native gate.
    corpus_path = ROOT / 'fixtures/compatibility/projects/fs_callbacks.corpus.json'
    case_count = 5


class PromiseFilesystemWriteProjectTests(PipelineProjectTests):
    # Exercise the shared descriptor writer without changing any prior cohort.
    corpus_path = ROOT / 'fixtures/compatibility/projects/fs_promise_writes.corpus.json'
    case_count = 10


class DiagnosticsProjectTests(PipelineProjectTests):
    # Shared diagnostics are exercised across package and ESM boundaries.
    corpus_path = ROOT / 'fixtures/compatibility/projects/diagnostics.corpus.json'
    case_count = 4


class RecursiveReaddirProjectTests(PipelineProjectTests):
    # Nested package discovery must produce complete files, not a shallow list.
    corpus_path = ROOT / 'fixtures/compatibility/projects/fs_recursive_readdir.corpus.json'
    case_count = 9


class WindowsPathProjectTests(PipelineProjectTests):
    # First-class namespaces are shared by package imports and escaped helpers.
    corpus_path = ROOT / 'fixtures/compatibility/projects/path-win32.corpus.json'
    case_count = 5


class ByteStreamProjectTests(PipelineProjectTests):
    # Caller-owned buffers and byte tees use the same shared runtime owner.
    corpus_path = ROOT / 'fixtures/compatibility/projects/stream-byob.corpus.json'
    case_count = 5


class ConstructorSignalProjectTests(PipelineProjectTests):
    # Constructor signals must cancel pipelines and complete owned cleanup.
    corpus_path = ROOT / 'fixtures/compatibility/projects/stream-constructor-signals.corpus.json'
    case_count = 5


class ReadLinesProjectTests(PipelineProjectTests):
    # File lines use the shared descriptor, stream, decoder and readline owners.
    corpus_path = ROOT / 'fixtures/compatibility/projects/fs-read-lines.corpus.json'
    case_count = 6


class IterableStreamProjectTests(PipelineProjectTests):
    # Cursor records must be read exactly once through shared stream pipelines.
    corpus_path = ROOT / 'fixtures/compatibility/projects/stream-iterables.corpus.json'
    case_count = 3


class WebAdoptionProjectTests(PipelineProjectTests):
    # Web endpoint resources must be released before an aborted adapter closes.
    corpus_path = ROOT / 'fixtures/compatibility/projects/stream-web-adoption.corpus.json'
    case_count = 6


class ZlibExportProjectTests(PipelineProjectTests):
    # Package helpers pass native codec functions as values and promisify them.
    corpus_path = ROOT / 'fixtures/compatibility/projects/zlib-exports.corpus.json'
    case_count = 6


if __name__ == '__main__':
    unittest.main()
