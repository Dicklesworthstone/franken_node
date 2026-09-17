# Native migration suite operator

`franken-migration-suite` is the Linux operator built by this standalone Cargo package. It includes the product's actual capture, test selection, subprocess supervision and comparison modules by path. It does not substitute Node for the native candidate runtime.

## Select the project's real harnesses

The optional project file `.franken-node/migration-tests.json` replaces filename-based discovery with an explicit, nonempty test inventory:

```json
{
  "schema_version": "franken-node/migration-tests/v1",
  "tests": [
    "packages/api/scripts/check.mjs",
    "packages/worker/scripts/verify.cjs"
  ]
}
```

Paths are relative to the project root. Each selected file must be an ordinary captured `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` or `.cts` file. Cases execute in sorted path order, each with the project root as its working directory and a fresh workspace for each runtime. Dependencies and fixture helpers remain available in the captured workspace without being inferred as extra entrypoints.

This selects standalone harnesses; it does not install packages, interpret `package.json` shell commands, inject Jest/Mocha globals, or transpile TypeScript. Both selected runtimes must support the harness syntax and required APIs. The operator is responsible for choosing meaningful coverage; a passing selection says nothing about omitted behavior.

Manifests are limited to 64 KiB and 1,024 cases. Unknown fields/schema versions, duplicate entries, missing files, noncanonical or escaping paths, symlinks, and selections inside vendor dependencies or reserved metadata fail closed. A malformed explicit manifest never falls back to a smaller implicit suite.

Without a manifest, existing discovery remains unchanged: supported `*.test.*`/`*.spec.*` files and supported files under `test` or `__tests__`, excluding `node_modules`, `.git`, `.migrate-backup` and `.franken-node`. Projects with no selected tests cannot pass this operator.

## Inspect before granting execution permission

With the built operator on `PATH`:

```bash
franken-migration-suite ./original-project --list-tests
```

This captures bounded inputs and prints sorted paths, their count and the complete captured input hash. It does not resolve Node or a native executable, prepare rewrites, run project code, or modify the project. The result uses `verdict: "INVENTORY"` and `execution_performed: false`, not `PASS`.

`--list-tests` cannot be combined with `--execute`, `--native-bin`, `--migrated-project` or `--compare-filesystem`. A later execution captures its own inputs; an inventory report is not a reusable execution approval or a compatibility certificate.

## Compare original and rewritten inputs

```bash
franken-migration-suite ./original-project \
  --migrated-project ./rewritten-project \
  --native-bin /trusted/bin/franken-node \
  --compare-filesystem \
  --execute \
  --out ./migration-comparison.json
```

Omit `--migrated-project` to run the same captured tree on both runtimes. Node must be available through an absolute `PATH` entry. Both runtime executables must resolve outside both measured projects. The native invocation explicitly selects `franken-engine` and disables degraded runtime fallback.

Both input trees are captured before execution. Their selected test identities must match exactly; a candidate cannot silently drop or substitute a reference case. The manifest bytes are included in the input hash. The product's checked rewrite path uses the same selection logic, refuses rewrites of reserved manifest metadata, and checks both input hashes, every test counterpart, complete success evidence and the filesystem comparison scope before installation.

Successful validation requires successful exits and exact stdout/stderr bytes for every selected case. `--compare-filesystem` additionally compares final persistent workspace deltas, excluding `.git` trees and the root `.franken-node` directory. Those exclusions are explicitly reported; transient writes and external effects are not measured. A matching pair of failures is still a failure.

## Reports and boundaries

JSON is printed to stdout. Optional `--out` works for both inspection and execution: its parent must exist outside both input trees, the destination must not exist, and a new report is written privately with mode 0600 and fsynced. Publication failure returns `ERROR` while retaining completed evidence on stdout; an incomplete new file can remain after an I/O failure.

Exit codes are 0 for `INVENTORY` or `PASS`, 1 for measured `FAIL`, and 2 for invalid inputs, missing runtimes, incomplete execution, publication failures or other errors. Inspection success is not execution success; inspect the verdict and schema, not only the exit code.

Execute only trusted code. Workspace copies are not an OS sandbox: ambient credentials, absolute paths, network access and external services remain available. Runtime byte hashes and captured input hashes establish measured identities, not signed authenticity or full environmental replay. `release_certification` remains false. The Rust regression suite includes explicit real Node/Node orchestration cases and deliberate `/bin/false` failures; neither establishes native Franken compatibility.
