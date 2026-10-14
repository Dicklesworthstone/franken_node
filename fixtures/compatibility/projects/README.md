# Executable multi-file project corpus

These 19 hand-authored programs exercise real CommonJS/ESM module graphs,
node_modules packages, scoped and conditional exports, nested dependency
precedence, package imports/self-reference, builtins through dependencies, and
filesystem effects. Every case is a complete captured project; execution never
runs an install command or downloads packages. These are package-shaped fixtures,
not third-party npm packages or npm compatibility certification.

## Run against a native build

Two-runtime comparison remains available:

    python3 scripts/project_compat_runner.py \
      --bin target/release/franken-node \
      --node node \
      --artifacts-dir /tmp/franken-project-compat-001

For the plan's L1 product oracle, add a separately selected Bun reference:

    python3 scripts/project_compat_runner.py \
      --bin target/release/franken-node \
      --node node \
      --bun bun \
      --artifacts-dir /tmp/franken-project-compat-001

The binary must already exist. The runner invokes franken-node init --profile
balanced, then franken-node run <entry> --policy balanced --runtime franken-engine
--console-only. --policy strict selects strict for both initialization and run;
no capability grants, degraded-runtime overrides, or policy downgrades are added.
A denial under the chosen profile remains a failed case, not a skipped case.

The selected artifacts directory must not exist. --case <id> is repeatable;
unknown IDs are errors. --wall-time-ms and --max-output-bytes apply separately
to every supervised initialization/execution. POSIX process groups are required.
Unset NODE_OPTIONS, NODE_PATH, BUN_OPTIONS, preload hooks, and FRANKEN_NODE_*
overrides (other than the supported FRANKEN_NODE_BIN binary selector) before
running.

Every case requires the selected references and native candidate to match the
literal UTF-8 stdout/stderr, declared exit code, and file expectations. No
whitespace, float, path, or timestamp normalization can hide a difference.
Expected nonzero exits are supported, but deadlines, signals, output truncation,
failed initialization, and incomplete evidence never count as compatible. Cases
continue after an ordinary failure.

When --bun is selected, Node and Bun execute independent copies of the same
captured original project. A disagreement between their measured termination,
stdout, stderr, completeness, or expected file observations is INCONCLUSIVE,
not a native regression and not a majority-vote pass. If the references agree
with each other but disagree with the frozen golden expectation, the case is
REFERENCE_FAILED. Only agreeing references that satisfy the golden oracle may
classify a native-only mismatch as FAIL. PASS requires all three roles to satisfy
the same frozen expectation.

The three executables must have distinct byte fingerprints. The runner records
the Node and Bun fingerprints separately; a wrapper used by harness unit tests
is not independent Bun evidence. A real compatibility campaign should select
the actual Bun executable.

Exit 0 means all selected cases passed. Exit 1 means a case failed, setup failed,
the run was cancelled, or reference evidence was inconclusive. Exit 2 means an
input/preflight failure.

## Filesystem expectations and artifacts

Each case's files map contains the initial project files as text, including
package manifests and captured dependencies. expected.files optionally maps
relative paths to exact text; null requires absence. File checks reject symlinks,
symlink parents, devices, FIFOs, changing files, and oversized outputs. Node,
optional Bun, and native processes run in independent workspaces so one role
cannot seed another with cached results or written files.

report.json is atomically checkpointed after each case and records per-category
counts, runtime/runner hashes, corpus/case hashes, selected/full case counts,
limits, mismatch fields, and paths to raw watchdog receipts and stdout/stderr.
Three-runtime reports also record oracle=node-bun-native, bun_reference,
inconclusive_cases, and per-case reference_disagreements. corpus.json, each
case.json, and every staged project directory are retained.

The report is separate from the legacy micro-corpus score: a selected subset
passing is not a claim of overall Node compatibility.

A frozen input can be rerun without the original source tree:

    python3 scripts/project_compat_runner.py \
      --corpus /tmp/franken-project-compat-001/corpus.json \
      --expect-corpus-sha256 'sha256:<64 hexadecimal characters from the prior report>' \
      --case commonjs-cycle-partial-exports \
      --bin target/release/franken-node \
      --bun bun \
      --artifacts-dir /tmp/franken-project-compat-rerun

Pass the complete corpus_sha256 field as the flag value. This reruns captured
project inputs; it is not native host-I/O replay or a hermetic environment
replay. Other environment variables are inherited. Only run trusted fixtures:
the references are ordinary local processes, not sandboxes, and can perform
filesystem/network operations allowed to their user.

## Test the harness and the reference expectations

    python3 -m unittest discover -s tests -p 'test_project_compat*.py' -v

The harness tests use a clearly marked synthetic native candidate adapter. Their
three-runtime cases use a distinct executable wrapper around real Node solely to
exercise reference orchestration and disagreement classification. Neither is
Bun or native-engine compatibility evidence. The corpus test executes every
fixture under a real Node reference. Genuine product-oracle evidence requires
the actual Node, Bun, and franken-node executables selected in one run.
