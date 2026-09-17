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

`--list-tests` cannot be combined with execution, runtime-comparison or capsule modes. A later execution captures its own inputs; an inventory report is not a reusable execution approval or a compatibility certificate.

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

## Capture a failure for native reexecution

Add `--capture-capsule` to persist the actual pre-execution inputs and completed measurement, including a measured `FAIL`:

```bash
franken-migration-suite ./original-project \
  --migrated-project ./rewritten-project \
  --native-bin /trusted/bin/franken-node \
  --compare-filesystem --execute \
  --capture-capsule ./migration-capsule.json \
  --out ./capture-report.json
```

The capsule and report destinations must be distinct, new files outside both projects; their parent directories must already exist. A measured failure still returns exit 1 and publishes the capsule. An incomplete/`ERROR` run is never presented as replayable. If publication fails, the command returns `ERROR` while retaining measured case evidence and a publication diagnostic in its JSON output.

Capsules contain sensitive source, dependency and configuration bytes, potentially including `.env` files and keys. Their contents are not printed to stdout. Files are private (0600), create-only and fsynced. Do not upload them as ordinary public test artifacts.

## Inspect, replay, and verify a fix

Inspect without resolving any executable or executing captured code:

```bash
franken-migration-suite ./migration-capsule.json --inspect-capsule
```

This returns `INTEGRITY_VALID`, captured case identities and the content hash. A valid unpinned checksum is not authenticated provenance: a malicious editor can recompute it. For replay, obtain `CAPSULE_SHA256` from your own trusted capture output or another independently trusted channel, not by trusting an unfamiliar capsule's inspection result.

```bash
franken-migration-suite ./migration-capsule.json --replay --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --out ./replay-report.json
```

Replay reconstructs the original and candidate snapshots in memory, then uses the same production executor, process supervision, per-case staging and comparison logic as live validation. It never recaptures the later source trees. Recorded executable paths/arguments are evidence, not commands to run: invocations are constructed from local Node discovery and your explicit native binary selection. Ordinary replay requires matching executable hashes and arguments; a byte-identical native executable may relocate.

`REPRODUCED` means the newly measured observations equal the captured observations. A faithfully reproduced migration failure is still a migration failure; its nested validation verdict remains `FAIL`. `DIVERGED` means complete new observations differ. Incomplete execution is `ERROR`, not reproduction.

Verify an updated candidate runtime explicitly:

```bash
franken-migration-suite ./migration-capsule.json --replay --verify-fix --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --native-bin /trusted/bin/fixed-franken-node \
  --out ./fix-report.json
```

Fix verification requires a captured `FAIL` with a successful reference execution for every case. It permits a different candidate executable, but the reference runtime identity and every reference observation must remain unchanged. `FIX_VERIFIED` requires all captured cases to pass. Remaining failures produce `FIX_NOT_VERIFIED`; changed reference observations produce `REFERENCE_DRIFT`, even if both current runtimes agree. No source rewrite is installed by this mode.

Replay refuses input/comparison overrides (`--migrated-project`, `--compare-filesystem`) and cannot be combined with capture or inspection. Replay requires `--execute`, `--expected-sha256` and `--native-bin`. Offline inspection forbids execution/runtime flags.

## Capsule contract and limits

The native schema is `franken-node/native-migration-capsule/v1`, separate from the standalone Python replay schema. It records both input identities, sorted entry inventories, ordinary permission modes, contained symlink chains, deduplicated hex-encoded file bytes, test-manifest contents and complete per-case observations. An unchanged candidate shares the original snapshot.

Import validates canonical relative paths, declared directory parents, link containment/cycles, unique entries and blobs, referenced file hashes, reconstructed snapshot hashes, exact test counterparts, comparison scope and consistency between observations and verdicts before staging. Capsules use compact canonical JSON: do not pretty-print, append whitespace or edit their encoding. Round-trip canonical checks also reject unknown/duplicate data silently ignored by nested report deserializers.

Capsule-specific limits: 128 MiB serialized input, 32 MiB combined expanded snapshot file bytes, 8 MiB entry metadata, 50,000 entries per snapshot and 64 symlink-resolution hops. The shared executor retains its 1,024-case, 4 KiB path, 300-second operation and 30-second leg limits. Incomplete execution or resource refusal cannot produce a passing/reproduced result.

The capsule binds the replay, capture, supervision, inventory and workspace-comparison source implementations. Reexecution requires matching source fingerprints; retain the validator revision. This is not a binding of its full compiled dependency graph. Runtime hashes likewise do not capture dynamically linked libraries. Clocks, environment variables, random values, temporary absolute paths, external modules and network state can still make exact-input reexecution diverge. `environment_reproduced` and `release_certification` remain false.

The native library implementation lives in `crates/franken-node/src/migration/native_replay.rs` and is consumed directly by this operator. Automatic capture from every primary `franken-node` CLI failure and automatic minimization remain separate work; this operator does not close those broader delivery obligations.

## Reports and boundaries

JSON is printed to stdout. Optional `--out` works for inspection, validation and replay: the destination must not exist, and a new report is written privately with mode 0600 and fsynced. For project modes its parent must be outside both input trees. Publication failure returns `ERROR` while retaining completed evidence on stdout; an incomplete new file can remain after an I/O failure.

Exit codes:

| Exit | Verdicts |
|---|---|
| 0 | `INVENTORY`, `PASS`, `INTEGRITY_VALID`, `REPRODUCED`, `FIX_VERIFIED` |
| 1 | `FAIL`, `DIVERGED`, `FIX_NOT_VERIFIED` |
| 2 | `ERROR`, `REFERENCE_DRIFT`, invalid arguments or other failures |

Inspection success is not execution success, and reproduction success is not migration success. Inspect the verdict, schema and nested validation, not only the exit code.

Execute only trusted code. Workspace copies are not an OS sandbox: ambient credentials, absolute paths, network access and external services remain available. Sequential filesystem capture and runtime identity rechecks are not atomic snapshots or defenses against every active swap-and-restore race. Runtime byte hashes and captured input hashes establish measured identities, not signed authenticity or full environmental replay. The Rust regression suite includes explicit real Node/Node orchestration cases and deliberate `/bin/false` failures; neither establishes native Franken compatibility.
