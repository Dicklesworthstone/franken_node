# Executable multi-file project corpus

These 19 hand-authored programs exercise real CommonJS/ESM module graphs,
`node_modules` packages, scoped and conditional exports, nested dependency
precedence, package imports/self-reference, builtins through dependencies, and
filesystem effects. Every case is a complete captured project; execution never
runs an install command or downloads packages. These are package-shaped fixtures,
not third-party npm packages or npm compatibility certification.

## Run against a native build

```bash
python3 scripts/project_compat_runner.py \
  --bin target/release/franken-node \
  --node node \
  --artifacts-dir /tmp/franken-project-compat-001
```

The binary must already exist. The runner invokes `franken-node init --profile
balanced`, then `franken-node run <entry> --policy balanced --runtime franken-engine
--console-only`. `--policy strict` selects strict for both initialization and run;
no capability grants, degraded-runtime overrides, or policy downgrades are added.
A denial under the chosen profile remains a failed case, not a skipped case.

The selected artifacts directory must not exist. `--case <id>` is repeatable;
unknown IDs are errors. `--wall-time-ms` and `--max-output-bytes` apply separately
to every supervised initialization/execution. POSIX process groups are required.
Unset `NODE_OPTIONS`, `NODE_PATH`, preload hooks, and `FRANKEN_NODE_*` overrides
(other than the supported `FRANKEN_NODE_BIN` binary selector) before running.

Every case requires **both** the Node reference and native candidate to match
literal UTF-8 stdout/stderr and the declared exit code. No whitespace, float,
path, or timestamp normalization can hide a difference. Expected nonzero exits
are supported, but deadlines, signals, output truncation, failed initialization,
and incomplete evidence never count as compatible. Cases continue after an
ordinary failure. Exit 0 means all selected cases passed; exit 1 means a case or
initialization failed (or the run was cancelled); exit 2 means input/preflight
failure. A reference that disagrees with the golden result is `REFERENCE_FAILED`.

## Filesystem expectations and artifacts

Each case's `files` map contains the initial project files as text, including
package manifests and captured dependencies. `expected.files` optionally maps
relative paths to exact text; `null` requires absence. File checks reject symlinks,
symlink parents, devices, FIFOs, changing files, and oversized outputs. The Node
and native processes run in independent workspaces so one cannot seed the other
with cached results or written files.

`report.json` is atomically checkpointed after each case and records per-category
counts, runtime/runner hashes, corpus/case hashes, selected/full case counts,
limits, mismatch fields, and paths to raw watchdog receipts and stdout/stderr.
`corpus.json`, each `case.json`, and both staged project directories are retained.
The report is separate from the legacy micro-corpus score: a selected subset
passing is **not** a claim of overall Node compatibility.

A frozen input can be rerun without the original source tree:

```bash
python3 scripts/project_compat_runner.py \
  --corpus /tmp/franken-project-compat-001/corpus.json \
  --expect-corpus-sha256 'sha256:<64 hexadecimal characters from the prior report>' \
  --case commonjs-cycle-partial-exports \
  --bin target/release/franken-node \
  --artifacts-dir /tmp/franken-project-compat-rerun
```

Pass the complete `corpus_sha256` field as the flag value. This reruns captured
project inputs; it is **not** native host-I/O replay or a hermetic environment
replay. Other environment variables are inherited. Only run trusted fixtures:
the Node reference is an ordinary local process, not a sandbox, and can perform
filesystem/network operations allowed to its user.

## Test the harness and the reference expectations

```bash
python3 -m unittest discover -s tests -p 'test_project_compat*.py' -v
```

The harness tests use a clearly marked synthetic candidate command adapter to
exercise success, failure, timeout, isolation and observation logic. The corpus
test executes every fixture under a real Node reference. Neither test suite
reports synthetic candidate results as native-engine compatibility evidence;
that requires the native-binary command above.
