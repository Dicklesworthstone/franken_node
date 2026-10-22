# Executable multi-file project corpus

The collection contains 161 fixture cases in 24 manifests. They exercise CommonJS/ESM module graphs,
node_modules packages, scoped and conditional exports, nested dependency
precedence, package imports/self-reference, builtins through dependencies, and
filesystem effects. Every case is a complete captured project; execution never
runs an install command or downloads packages. Most cases use hand-authored
package-shaped fixtures. `npm-packages.corpus.json` adds unchanged runtime
specimens from three real npm releases; this small band is not npm compatibility
certification or a representative top-N package sample.

## Run against a native build

Two-runtime comparison remains available:

    python3 scripts/project_compat_runner.py \
      --corpus-dir fixtures/compatibility/projects \
      --bin target/release/franken-node \
      --node node \
      --artifacts-dir /tmp/franken-project-compat-001

For the plan's L1 product oracle, add a separately selected Bun reference:

    python3 scripts/project_compat_runner.py \
      --corpus-dir fixtures/compatibility/projects \
      --bin target/release/franken-node \
      --node node \
      --bun bun \
      --artifacts-dir /tmp/franken-project-compat-001

The binary must already exist. The runner invokes franken-node init --profile
balanced, then franken-node run <entry> --policy balanced --runtime franken-engine
--console-only. --policy strict selects strict for both initialization and run;
no capability grants, degraded-runtime overrides, or policy downgrades are added.
A denial under the chosen profile remains a failed case, not a skipped case.
Omitting both corpus flags selects only the 42-case `corpus.json` manifest;
`--corpus <file>` selects one manifest. Directory mode validates the complete
collection and rejects duplicate case IDs before executing any runtime.

The selected artifacts directory must not exist. --case <id> is repeatable;
unknown IDs are errors. --wall-time-ms and --max-output-bytes apply separately
to every supervised initialization/execution. Each `--version` probe has the
smaller of those limits and 5 seconds / 8 KiB per stream. POSIX process groups are required.
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
It also records UTC start/end, host OS/architecture/load, Python version, the
watchdog hash, and each executable's actual `--version` output and receipt.
Failed, empty, invalid UTF-8, incomplete, or over-budget version probes fail the
campaign before project execution. Binary hashes are checked again after the
probes and after the campaign; a detected change prevents PASS.
Three-runtime reports also record oracle=node-bun-native, bun_reference,
inconclusive_cases, and per-case reference_disagreements. corpus.json, each
case.json, and every staged project directory are retained.

The report is separate from the legacy micro-corpus score: a selected subset
passing is not a claim of overall Node compatibility.
`candidate_source_binding` is explicitly `not_established_by_this_runner`.
A version string or nearby Git checkout does not prove which engine source
was linked into the selected binary.

A frozen input can be rerun without the original source tree:

    python3 scripts/project_compat_runner.py \
      --corpus /tmp/franken-project-compat-001/corpus.json \
      --expect-corpus-sha256 'sha256:<64 hexadecimal characters from the prior report>' \
      --baseline-report /tmp/franken-project-compat-001/report.json \
      --case commonjs-cycle-partial-exports \
      --bin target/release/franken-node \
      --bun bun \
      --artifacts-dir /tmp/franken-project-compat-rerun

Pass the complete corpus_sha256 field as the flag value. This reruns captured
project inputs; it is not native host-I/O replay or a hermetic environment
replay. Other environment variables are inherited. Only run trusted fixtures:
the references are ordinary local processes, not sandboxes, and can perform
filesystem/network operations allowed to their user.

`--baseline-report` pins the reference roles, executable hashes and exact
version stdout/stderr from a prior report. A changed Node or Bun reference
retains a failed report with the old/new identities and runs no project cases.
For an intentional reference update, supply `--reference-change 'reason'` with
the baseline. The reason and every drift remain in the new report. This cannot
approve failed version probes or case mismatches. Candidate builds may change
without changing reference pins. Baselines without valid version evidence and
two-reference-to-one-reference downgrades are rejected; the original report is
never edited. The baseline pins references only, not the corpus, policy or host
environment, and its previous native verdict is never a new pass oracle.

## Test the harness and the reference expectations

The npm band pins `is-number@7.0.0`, `isarray@2.0.5` and
`escape-string-regexp@4.0.0`. Each project's lockfile records the official npm
archive URL and SHA-512 integrity value. The runtime `index.js`, original
`package.json` and original MIT license match those verified archives
byte-for-byte. Readmes, development dependencies and type declarations are not
included. Original package scripts remain inert metadata; execution uses the
already captured `node_modules` files. No install script or package manager runs.

Tests pin all nine upstream file hashes and verify lock/source identity before
executing actual package API calls on real Node. Drivers include finite-value
and coercion boundaries, arrays versus array-like/prototype shapes, literal
Unicode regex construction, empty strings and exact type-error behavior.
For this reference band alone:

    python3 tests/test_project_compat_corpus.py \
      CorpusTests.test_pinned_npm_publication_bytes_and_lock_identity \
      CorpusTests.test_pinned_npm_specimens_match_exact_reference_observations -v

Run the same manifest through `project_compat_runner.py --corpus` to measure
real Node/Bun/native agreement. A source-integrity or reference-test pass does
not establish native compatibility.

    python3 -m unittest discover -s tests -p 'test_project_compat*.py' -v

The harness tests use a clearly marked synthetic native candidate adapter. Their
three-runtime cases use a distinct executable wrapper around real Node solely to
exercise reference orchestration and disagreement classification. Neither is
Bun or native-engine compatibility evidence. The corpus test executes every
fixture under a real Node reference. Genuine product-oracle evidence requires
the actual Node, Bun, and franken-node executables selected in one run.
