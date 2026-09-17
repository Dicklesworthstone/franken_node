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

## Compare against both Node and Bun

Add an explicitly selected Bun executable to measure the captured project inventory on all three runtimes:

```bash
franken-migration-suite ./original-project \
  --migrated-project ./rewritten-project \
  --native-bin /trusted/bin/franken-node \
  --bun-bin /trusted/bin/bun \
  --compare-filesystem --execute \
  --out ./three-runtime-comparison.json
```

Node and Bun each receive the original captured project. Native Franken receives the optional rewritten candidate, or the original capture when `--migrated-project` is omitted. Each selected test runs exactly once per role, with fresh workspace copies and the shared subprocess supervisor. This extends the captured migration-suite operator; it does not replace the separate single-target/corpus lockstep harness or the L2 engine-boundary oracle.

Reference agreement is required, not majority voting. Classification is deliberately ordered:

| Case outcome | Meaning |
|---|---|
| `ERROR` | A leg or filesystem observation is incomplete. Completed observations from other legs remain available. |
| `REFERENCE_FAILURE` | Node or Bun exited unsuccessfully or by signal, including matching failures. |
| `REFERENCE_DIVERGENCE` | Both references succeeded but their stdout, stderr or requested filesystem deltas disagree. |
| `NATIVE_DIVERGENCE` | Both references succeeded and agreed, but the native candidate failed or differed. |
| `MATCH` | All three succeeded and agreed in the requested comparison scope. |

The suite returns `ERROR` for incomplete cases, skipped work, or runtime identity errors; otherwise `INCONCLUSIVE` if any reference failed or disagreed; otherwise `FAIL` for native divergences; otherwise `PASS`. `INCONCLUSIVE` exits 2 and cannot authorize migration. In particular, native agreement with only one disagreeing reference is not a pass. Each case retains available observations for all three roles and labeled divergence channels, including native differences even when the reference outcome takes precedence. Aggregate outcome counters are disjoint; `failed` counts all three complete nonmatching outcomes.

The report schema is `franken-node/product-validation-suite/v1`. It records original/candidate input hashes, all three executable hashes and arguments, the exact selected tests, exit/signal observations, output byte counts and hashes, comparison exclusions and optional workspace summaries. Comparisons use complete raw output bytes and complete filesystem deltas, not the summary preview. All runtime binaries are fingerprinted before any case and rechecked after the suite. The operation retains the 300-second total and 30-second per-leg limits. Errors do not erase earlier results or permit smoke fallback.

All three executables must be ordinary executable files outside both projects. Node and Bun must have different executable hashes, so a renamed or copied Node binary cannot accidentally satisfy the second reference. This checks byte distinction, not authenticated runtime brands or independence: the operator must select trusted genuine runtime binaries. Missing Bun is an error, not permission to silently downgrade to two runtimes.

Three-runtime reports are not accepted as two-runtime replay capsules. `--bun-bin` conflicts with capture, replay, minimization, fix-verification and offline inspection/export modes, and requires explicit execution approval. Three-runtime capsule persistence is not integrated yet. Primary `migrate validate` and `migrate-report` retain their two-runtime path; checked apply has the explicit three-runtime option below. `release_certification` remains false.

The targeted product-oracle checks exercise the production orchestration with explicitly identified role-argument Node processes. The `Native product oracle` workflow also installs real Bun, runs real Node/Bun reference agreement and disagreement through the executable CLI, and deliberately uses `/bin/false` for the native leg to prove failure classification. Neither test category establishes successful native Franken compatibility.

## Require three-runtime agreement before checked installation

The primary Linux checked-rewrite command can require both references:

```bash
FRANKEN_NODE_CHECKED_REWRITE_BUN_BIN=/trusted/bin/bun \
  franken-node migrate rewrite ./project --apply --verify --json
```

This is an explicit operator-selected absolute Bun path. It does not read a runtime selection from project files, and it does not grant execution under dry-run semantics: `--verify` still requires `--apply`. With the variable unset, the existing Node/native checked-apply path is unchanged. Empty, relative, missing or byte-identical-to-Node Bun selections fail closed; they never trigger a fallback pair comparison. The Rust API `migration::verified_rewrite::run_product(project, native, bun)` selects the same three-runtime path directly, without consulting the primary command's environment selection or requesting capsule retention.

The shared checked pipeline captures inputs, checks static prerequisites, plans and prepares replacements, then executes Node and Bun on the original snapshot and native Franken on the prepared candidate. It does not recapture the unchanged source directory in place of the candidate or run a second pairwise validation. The existing writer lock covers planning, all three runtime legs and installation. Static failures and unresolved manual-review findings still block runtime dispatch. After a passing measurement, the complete source tree must still match the original snapshot, including unchanged dependencies/configuration, before the transaction writer may install anything.

The installation decision requires both exact input hashes, the complete sorted captured test inventory, successful termination and matching output/workspace observations for every case, distinct reference hashes and the mandatory filesystem-comparison scope. It checks raw observation summaries independently of reported outcome/divergence lists. A summary-only `PASS`, missing Bun row, duplicate/substituted test, weakened exclusion scope or inconsistent counter cannot authorize installation. These checks validate live evidence consistency, not the authenticity of unsigned reports imported from disk; the command has no report-import approval path.

Checked reports keep schema `franken-node/checked-rewrite/v1`. Three-runtime measurements appear in `product_validation`; `validation` is null, not a two-runtime projection. Two-runtime reports continue using `validation`, with `product_validation` omitted. Human output includes the product oracle and separate reference/native divergence counts. Complete `FAIL` or `INCONCLUSIVE` measurements produce `REJECTED` (primary command exit 1) and retain all observations without applying new rewrites. Infrastructure/configuration failures produce `ERROR` (exit 2). `APPLIED` and `UNCHANGED` exit 0; even an unchanged plan requires all three successful legs.

Do not combine this primary three-runtime mode with `FRANKEN_NODE_MIGRATION_FAILURE_DIR`: the current capsule schema cannot retain Bun evidence. The command refuses that combination before runtime dispatch instead of silently omitting the requested archive or saving an incomplete pair projection. Retain the full checked-rewrite JSON privately instead; it includes source preimages as well as validation evidence. Three-runtime capsule persistence remains separate work.

The checked-apply regressions use real Node/Bun/Node processes for positive installation orchestration, with Node explicitly identified as the test-only candidate, and `/bin/false` for public native-failure cases. They exercise backups, file modes, writer locking, source drift, reference disagreements, complete evidence and no-fallback behavior; they do not establish successful native Franken compatibility or whole-environment equivalence.

## Retain primary-command failures automatically

The primary Linux `franken-node migrate validate`, `franken-node migrate-report` and two-runtime checked-rewrite validation paths can retain a replay capsule from the measurement that actually failed. Select an existing absolute directory outside the project:

```bash
FRANKEN_NODE_MIGRATION_FAILURE_DIR=/private/migration-failures \
  franken-node migrate validate ./project --json
```

No source archive is persisted by default. Setting this environment variable explicitly opts into retaining sensitive source, dependency and configuration bytes. The directory must already exist and must not be a symlink; relative paths and paths inside either measured project are refused before runtime dispatch. Static-only validation and failed static prerequisites do not reserve storage or run code.

Each eligible invocation reserves a unique private (0700) child directory before resolving or launching runtimes. A complete measured `FAIL` publishes a private (0600) `failure.json` there. A `PASS` removes its unused reservation. Archive limits, deadlines, publication errors and incomplete execution produce a separate `UNAVAILABLE` diagnostic rather than changing the original measurement, weakening admission, or fabricating a replayable capsule. The caller owns retention and removal of successfully saved archives.

The JSON attachment is `test_suite.failure_capture` for validation, `validation.test_suite.failure_capture` for `migrate-report`, and `validation.failure_capture` for two-runtime checked-rewrite reports. A saved attachment has `status: "SAVED"`, `capsule_path` and `content_sha256`; an unavailable attachment has `status: "UNAVAILABLE"` and `reason`. Without retention configured, the field is omitted. Capture status does not replace the suite verdict or the report's go/no-go decision.

Checked rewrites archive both the original and prepared candidate, even when that candidate is rejected and never installed. The archive uses the exact pre-execution snapshots and original report: it does not rerun the project to manufacture a failure or recapture the subsequently mutable source tree. Failed validation still refuses installation. The directory configuration is removed from both guest runtime environments to avoid propagating operator capture settings into nested executions; this is not an OS isolation boundary.

Use the saved path and hash from your trusted primary-command output with this operator's `--inspect-capsule`, `--replay`, `--minimize-capsule` and `--export-inputs` modes below. Retain the producing validator revision. Static failures, empty-suite smoke fallback, failures before a complete suite report exists, and archive-limit refusals are not replayable captures. The standalone operator retains its explicit `--capture-capsule` behavior and does not read this automatic-retention setting.

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

## Reduce a reproduced failure

Minimize the captured failing entrypoints while retaining every recorded case observation:

```bash
franken-migration-suite ./migration-capsule.json --replay --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --minimize-capsule ./reduced-capsule.json \
  --out ./reduction-report.json
```

This is native, execution-backed line-complement reduction. It never edits the source projects or the seed capsule. The seed must be a complete `FAIL` with successful reference executions and ordinary, non-signal candidate exits. Captured runtime identities and replay implementation fingerprints must match; reduction cannot be combined with `--verify-fix`.

The initial seed, each accepted candidate and the final retained result require repeated full-suite executions. All original observations must remain identical: passing cases as well as failing cases, stdout/stderr byte counts and hashes, termination outcomes, divergence channels, and any captured filesystem effects. A new syntax error, a missing test or an unrelated failure cannot replace the recorded behavior. Rejected candidates are cached by both complete input hashes; incomplete trials are never cached as evidence of rejection.

By default, the reducer selects the failing test entrypoints. Use repeated `--source-file src/helper.js` arguments to select supporting sources instead. At most 16 canonical project-relative source paths are allowed. They must be ordinary UTF-8 JS/TS files, each no larger than 1 MiB or 4,096 lines. Explicit selections must exist in both trees when the capsule contains distinct original/candidate inputs; each leg is then reduced independently. Dependencies, configuration, manifests, paths, file modes, links and the test inventory remain unchanged. Newline ranges preserve CRLF, Unicode and unterminated final lines. AST-aware and token-level reduction are not implemented by this operator.

Defaults are `--max-executions 128`, `--minimize-seconds 120`, and `--confirmations 2`. Execution counts include complete-suite attempts, initial confirmations and final confirmations, not individual child processes. Confirmations may be raised to 8; execution budgets must reserve both initial and final confirmations and cannot exceed 4,096. The time budget is 1–3,600 seconds, with the last 20 percent reserved for final checking. The shared 30-second per-leg cap still applies.

Search budget exhaustion retains the last confirmed candidate, but never waives fresh final verification. A failed or incomplete final check returns `ERROR` without publishing a reduced capsule. `REDUCED` means fewer selected source bytes with preserved observations, not a fixed migration. `UNCHANGED` means no reduction was retained. `search_complete=false` identifies budget-limited or unresolved searches; even a completed line search is not proof of a global minimum or of deterministic environmental behavior. Statistics include executions, accepted/rejected/unresolved trials, cache hits and the last unresolved diagnostic.

The output is an ordinary native replay capsule, usable with `--inspect-capsule`, `--replay` and `--verify-fix`. Its new content hash, parent capsule hash, reducer fingerprint, selected sources, byte counts and final measured evidence are reported in the separate reduction report. The reduced capsule remains sensitive material and is created privately without overwriting an existing path. Publication errors retain completed reduction evidence in JSON output.

## Export a debugging fixture without execution

Restore a pinned capsule into a new private directory:

```bash
franken-migration-suite ./reduced-capsule.json \
  --export-inputs ./debug-fixture \
  --expected-sha256 "$REDUCED_CAPSULE_SHA256"
```

Use the reduced hash from your trusted reduction result, not the parent capsule's hash. Export also works on unreduced capsules. No `--execute` or `--native-bin` is accepted, and no recorded command or runtime is resolved. Unlike reexecution, offline export does not require the producing validator/runtime revision to remain installed.

The new directory is mode 0700 and contains `original/`, `candidate/` and `reproducer.json`. Both trees retain captured bytes, ordinary file modes and contained links. Their input hashes are recomputed and checked before the private (0600) completion manifest is written. The manifest records the expected observations and relative project roots; it does not execute them. `EXPORTED` is a successful extraction, not a successful migration or fresh behavioral validation.

The destination must not exist, including as a symlink. Its parent must already exist. Existing files and directories are never merged, replaced or deleted. On an I/O failure a private partial export can remain; export is not an atomic multi-file transaction. Extracted sources may contain secrets or executable project configuration: review and contain them before opening them in tools that automatically execute workspace code.

## Capsule contract and limits

The native schema is `franken-node/native-migration-capsule/v1`, separate from the standalone Python replay schema. It records both input identities, sorted entry inventories, ordinary permission modes, contained symlink chains, deduplicated hex-encoded file bytes, test-manifest contents and complete per-case observations. An unchanged candidate shares the original snapshot.

Import validates canonical relative paths, declared directory parents, link containment/cycles, unique entries and blobs, referenced file hashes, reconstructed snapshot hashes, exact test counterparts, comparison scope and consistency between observations and verdicts before staging. Capsules use compact canonical JSON: do not pretty-print, append whitespace or edit their encoding. Round-trip canonical checks also reject unknown/duplicate data silently ignored by nested report deserializers.

Capsule-specific limits: 128 MiB serialized input, 32 MiB combined expanded snapshot file bytes, 8 MiB entry metadata, 50,000 entries per snapshot and 64 symlink-resolution hops. The shared executor retains its 1,024-case, 4 KiB path and 30-second leg limits. Ordinary capture/replay/export have a 300-second operation budget; minimization uses its separately bounded budget above. Incomplete execution or resource refusal cannot produce a passing/reproduced result.

The capsule binds the replay, capture, supervision, inventory and workspace-comparison source implementations. Reexecution requires matching source fingerprints; retain the validator revision. This is not a binding of its full compiled dependency graph. Runtime hashes likewise do not capture dynamically linked libraries. Clocks, environment variables, random values, temporary absolute paths, external modules and network state can still make exact-input reexecution diverge. `environment_reproduced` and `release_certification` remain false.

The native implementations live in `crates/franken-node/src/migration/native_replay.rs` and `native_minimizer.rs` and are consumed directly by this operator. Automatic capture beyond the supported complete primary two-runtime validation/checked-rewrite failures, three-runtime capsules, AST/token minimization and whole-environment replay remain separate work; this operator does not close those broader delivery obligations.

## Reports and boundaries

JSON is printed to stdout. Optional `--out` works for inspection, validation, replay, reduction and export: the destination must not exist, and a new report is written privately with mode 0600 and fsynced. For project modes its parent must be outside both input trees. Publication failure returns `ERROR` while retaining completed evidence on stdout; an incomplete new file can remain after an I/O failure.

Standalone operator exit codes (primary checked-apply status/exit mapping is described separately above):

| Exit | Verdicts |
|---|---|
| 0 | `INVENTORY`, `PASS`, `INTEGRITY_VALID`, `REPRODUCED`, `FIX_VERIFIED`, `REDUCED`, `EXPORTED` |
| 1 | `FAIL`, `DIVERGED`, `FIX_NOT_VERIFIED`, `UNCHANGED` |
| 2 | `ERROR`, `INCONCLUSIVE`, `REFERENCE_DRIFT`, invalid arguments or other failures |

Inspection success is not execution success, reproduction success is not migration success, and reduction/export do not fix the captured failure. Inspect the verdict, schema and nested validation, not only the exit code.

Validation execution and checked-rewrite staging create their enclosing temporary directories with explicit owner-only permissions before copying source bytes. Archive reservations are likewise private from creation, independent of a permissive umask. These permissions protect against access by other local users, not code running as the same user or privileged processes.

Execute only trusted code. Workspace copies are not an OS sandbox: ambient credentials, absolute paths, network access and external services remain available. Sequential filesystem capture and runtime identity rechecks are not atomic snapshots or defenses against every active swap-and-restore race. Runtime byte hashes and captured input hashes establish measured identities, not signed authenticity or full environmental replay. The Rust regression suite includes explicit real Node/Node and Node/Bun/Node orchestration cases and deliberate `/bin/false` failures; none establishes native Franken compatibility.
