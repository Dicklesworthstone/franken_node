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

This selects standalone harnesses; it does not install packages, interpret `package.json` shell commands, inject Jest/Mocha globals, or transpile TypeScript. The selected runtimes must support the harness syntax and required APIs. The operator is responsible for choosing meaningful coverage; a passing selection says nothing about omitted behavior.

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

Three-runtime reports use their own replay capsule schema; they are never projected into two-runtime capsules. `--bun-bin` supports live comparison, capture, replay, explicit fix verification and three-runtime minimization. It conflicts with offline inspection/export. Primary `migrate validate` and `migrate-report` retain their two-runtime path; checked apply has the explicit three-runtime option below. `release_certification` remains false.

The targeted product-oracle checks exercise the production orchestration with explicitly identified role-argument Node processes. The `Native product oracle` workflow also installs real Bun and exercises reference agreement/disagreement, capture, replay, reduction, offline export and Bun-only reference drift through the executable CLI, with `/bin/false` as a deliberately failing candidate. These checks do not establish successful native Franken compatibility.

## Require three-runtime agreement before checked installation

The primary Linux checked-rewrite command can require both references:

```bash
FRANKEN_NODE_CHECKED_REWRITE_BUN_BIN=/trusted/bin/bun \
  franken-node migrate rewrite ./project --apply --verify --json
```

This is an explicit operator-selected absolute Bun path. It does not read a runtime selection from project files, and it does not grant execution under dry-run semantics: `--verify` still requires `--apply`. With the variable unset, the existing Node/native checked-apply path is unchanged. Empty, relative, missing or byte-identical-to-Node Bun selections fail closed; they never trigger a fallback pair comparison. The Rust API `migration::verified_rewrite::run_product(project, native, bun)` selects the same three-runtime path directly, without consulting the primary command's environment selection or requesting capsule retention.

The shared checked pipeline captures inputs, checks static prerequisites, plans and prepares replacements, then executes Node and Bun on the original snapshot and native Franken on the prepared candidate. It does not recapture the unchanged source directory in place of the candidate or run a second pairwise validation. The existing writer lock covers planning, all three runtime legs and installation. Static failures and unresolved manual-review findings still block runtime dispatch. After a passing measurement, the complete source tree must still match the original snapshot, including unchanged dependencies/configuration, before the transaction writer may install anything.

The installation decision requires both exact input hashes, the complete sorted captured test inventory, successful termination and matching output/workspace observations for every case, distinct reference hashes and the mandatory filesystem-comparison scope. It checks raw observation summaries independently of reported outcome/divergence lists. A summary-only `PASS`, missing Bun row, duplicate/substituted test, weakened exclusion scope or inconsistent counter cannot authorize installation. These checks validate live evidence consistency, not the authenticity of unsigned reports imported from disk; the command has no report-import approval path.

Checked reports keep schema `franken-node/checked-rewrite/v1`. Three-runtime measurements appear in `product_validation`; `validation` is null, not a two-runtime projection. Two-runtime reports continue using `validation`, with `product_validation` omitted. Human output identifies the product oracle and any requested failure-retention result. Complete `FAIL` or `INCONCLUSIVE` measurements produce `REJECTED` (primary command exit 1) and retain all observations without applying new rewrites. Infrastructure/configuration failures produce `ERROR` (exit 2). `APPLIED` and `UNCHANGED` exit 0; even an unchanged plan requires all three successful legs.

To retain the exact rejected candidate, enable failure retention together with the Bun selection:

```bash
FRANKEN_NODE_CHECKED_REWRITE_BUN_BIN=/trusted/bin/bun \
FRANKEN_NODE_MIGRATION_FAILURE_DIR=/private/migration-failures \
  franken-node migrate rewrite ./project --apply --verify --json
```

The existing absolute failure directory must be outside the project. A complete `FAIL` or `INCONCLUSIVE` measurement can save a three-runtime capsule. The attachment is `product_validation.failure_capture`; it includes the saved path and independently usable content hash. Retention consumes the same immutable original and prepared candidate already measured, without rerunning code or installing a failed candidate. The full checked-rewrite JSON also remains available; handle it privately because it contains source preimages.

The checked-apply regressions use real Node/Bun/Node processes for positive installation orchestration, with Node explicitly identified as the test-only candidate, and `/bin/false` for public native-failure cases. They exercise backups, file modes, writer locking, source drift, reference disagreements, complete evidence, no-fallback behavior and primary-command failure capture. They do not establish successful native Franken compatibility or whole-environment equivalence.

## Retain primary-command failures automatically

The primary Linux `franken-node migrate validate`, `franken-node migrate-report` and checked-rewrite validation paths can retain a replay capsule from the measurement that actually failed. Select an existing absolute directory outside the project:

```bash
FRANKEN_NODE_MIGRATION_FAILURE_DIR=/private/migration-failures \
  franken-node migrate validate ./project --json
```

No source archive is persisted by default. Setting this environment variable explicitly opts into retaining sensitive source, dependency and configuration bytes. The directory must already exist and must not be a symlink; relative paths and paths inside either measured project are refused before runtime dispatch. Static-only validation and failed static prerequisites do not reserve storage or run code.

Each eligible invocation reserves a unique private (0700) child directory before resolving or launching runtimes. A complete measured `FAIL`, or a three-runtime `INCONCLUSIVE` measurement, publishes a private (0600) `failure.json` there. A `PASS` removes its unused reservation. Archive limits, deadlines, publication errors and incomplete execution produce a separate `UNAVAILABLE` diagnostic rather than changing the original measurement, weakening admission, or fabricating a replayable capsule. The caller owns retention and removal of successfully saved archives.

The JSON attachment is `test_suite.failure_capture` for validation, `validation.test_suite.failure_capture` for `migrate-report`, `validation.failure_capture` for two-runtime checked rewrites, and `product_validation.failure_capture` for three-runtime checked rewrites. A saved attachment has `status: "SAVED"`, `capsule_path` and `content_sha256`; an unavailable attachment has `status: "UNAVAILABLE"` and `reason`. Without retention configured, the field is omitted. Capture status does not replace the suite verdict or the report's go/no-go decision.

Checked rewrites archive both the original and prepared candidate, even when that candidate is rejected and never installed. The archive uses the exact pre-execution snapshots and original report: it does not rerun the project to manufacture a failure or recapture the subsequently mutable source tree. Failed validation still refuses installation. The directory configuration is removed from guest runtime environments to avoid propagating operator capture settings into nested executions; this is not an OS isolation boundary.

Use the saved path and hash from your trusted primary-command output with this operator's inspection, replay, minimization and export modes below. Retain the producing validator revision. Static failures, empty-suite smoke fallback, failures before a complete suite report exists, and archive-limit refusals are not replayable captures. The standalone operator retains its explicit `--capture-capsule` behavior and does not read this automatic-retention setting. Reduction has stricter seed requirements than replay, described below.

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

Add `--bun-bin /trusted/bin/bun` to this command to retain the full three-runtime measurement in a product capsule instead. Complete reference disagreements and failures remain `INCONCLUSIVE` and can be archived, but cannot establish a valid baseline for native fix verification.

The capsule and report destinations must be distinct, new files outside both projects; their parent directories must already exist. A measured failure still returns exit 1 and publishes the capsule; a captured `INCONCLUSIVE` returns exit 2. An incomplete/`ERROR` run is never presented as replayable. If publication fails, the command returns `ERROR` while retaining measured case evidence and a publication diagnostic in its JSON output.

Capsules contain sensitive source, dependency and configuration bytes, potentially including `.env` files and keys. Their contents are not printed to stdout. Files are private (0600), create-only and fsynced. Do not upload them as ordinary public test artifacts.

## Inspect, replay, and verify a fix

Inspect either capsule schema without resolving any executable or executing captured code:

```bash
franken-migration-suite ./migration-capsule.json --inspect-capsule
```

This returns `INTEGRITY_VALID`, captured case identities and the content hash. A valid unpinned checksum is not authenticated provenance: a malicious editor can recompute it. For replay, obtain `CAPSULE_SHA256` from your own trusted capture output or another independently trusted channel, not by trusting an unfamiliar capsule's inspection result.

Replay a two-runtime capsule:

```bash
franken-migration-suite ./migration-capsule.json --replay --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --out ./replay-report.json
```

Replay a three-runtime capsule by explicitly selecting the trusted Bun executable as well:

```bash
franken-migration-suite ./product-capsule.json --replay --execute \
  --expected-sha256 "$PRODUCT_CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --bun-bin /trusted/bin/bun \
  --out ./product-replay-report.json
```

Replay reconstructs the original and candidate snapshots in memory, then uses the same production executor, process supervision, per-case staging and comparison logic as live validation. It never recaptures the later source trees. Recorded executable paths/arguments are evidence, not commands to run: invocations are constructed from local Node discovery and explicit native/Bun selections. Ordinary replay requires matching executable hashes and arguments; byte-identical executable relocation is allowed. Selecting the wrong capsule/runtime mode is an error, never permission to discard Bun evidence or convert schemas.

`REPRODUCED` means newly measured observations equal the captured observations. A faithfully reproduced failure remains `FAIL` in its nested validation; reproduced reference disagreement remains `INCONCLUSIVE`. `DIVERGED` means complete new observations differ. Incomplete execution is `ERROR`, not reproduction. Three-runtime replay retains the full product report and compares every selected case and all three role observations.

Verify an updated candidate runtime explicitly:

```bash
franken-migration-suite ./migration-capsule.json --replay --verify-fix --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --native-bin /trusted/bin/fixed-franken-node \
  --out ./fix-report.json
```

For a product capsule add `--bun-bin /trusted/bin/bun` and use its trusted hash. Fix verification requires a captured `FAIL` with a successful reference execution for every case; product capsules additionally require both references to have agreed. The native executable may change, but every reference runtime identity and observation must remain unchanged. Product verification checks Bun as well as Node: Bun-only drift produces `REFERENCE_DRIFT` even when Node remains unchanged. `FIX_VERIFIED` requires all captured cases to pass, while remaining native failures produce `FIX_NOT_VERIFIED`. A captured `INCONCLUSIVE` cannot authorize fix verification. No source rewrite is installed by replay or fix mode.

Replay refuses input/comparison overrides (`--migrated-project`, `--compare-filesystem`) and cannot be combined with capture or inspection. Replay requires `--execute`, `--expected-sha256` and `--native-bin`, plus `--bun-bin` for product capsules. Offline inspection/export forbids execution/runtime flags.

## Reduce a reproduced failure or reference disagreement

Minimize a two-runtime capsule while retaining every recorded case observation:

```bash
franken-migration-suite ./migration-capsule.json --replay --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --minimize-capsule ./reduced-capsule.json \
  --out ./reduction-report.json
```

For a three-runtime capsule, keep Bun in the reduction:

```bash
franken-migration-suite ./product-capsule.json --replay --execute \
  --expected-sha256 "$PRODUCT_CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --bun-bin /trusted/bin/bun \
  --minimize-capsule ./reduced-product-capsule.json \
  --out ./product-reduction-report.json
```

This is native, execution-backed line-complement reduction. It never edits the source projects or seed capsule. Pair seeds must be complete `FAIL` measurements with successful reference executions and ordinary non-signal candidate exits. Product seeds may be `FAIL` or `INCONCLUSIVE`, but Node and Bun must both have exited successfully for every case and native exits must be ordinary, not signals. Thus reference disagreements can be reduced for diagnosis without pretending they are evidence of a native regression. Reference execution failures, crashing candidates, incomplete runs and passing seeds are refused.

All captured runtime identities, arguments and replay implementation fingerprints must match. Product reduction checks Node, Bun and native before dispatch and around every full-suite attempt. Missing or substituted Bun cannot trigger a pair fallback. Reduction cannot be combined with `--verify-fix`; changing the native runtime is a separate operation.

The initial seed, each accepted candidate and the final retained result require repeated full-suite executions. All original observations must remain identical: passing cases as well as failing cases, every runtime's stdout/stderr byte counts and hashes, termination outcomes, divergence channels, case classifications and captured filesystem effects. The full `ProductCase` set is retained through product reduction; matching Node and native while Bun changes is insufficient. A new syntax error, a missing test or an unrelated failure cannot replace the recorded behavior. Complete rejected candidates are cached by both complete input hashes; incomplete trials are never cached as evidence of rejection or accepted as equivalent.

By default, the reducer selects failing entrypoints, including reference-disagreement cases in product mode. Use repeated `--source-file src/helper.js` arguments to select supporting sources instead. At most 16 canonical project-relative source paths are allowed. They must be ordinary UTF-8 JS/TS files, each no larger than 1 MiB or 4,096 lines. Explicit selections must exist in both trees when the capsule contains distinct original/candidate inputs; each tree is reduced independently. Node and Bun always receive the same current original tree, while native receives the current candidate. Dependencies, configuration, manifests, paths, file modes, links and the test inventory remain unchanged. Newline ranges preserve CRLF, Unicode and unterminated final lines. AST-aware and token-level reduction are not implemented.

Both modes share the source policy, complement-search algorithm, rejection cache, unresolved-run accounting and final-confirmation budget. Defaults are `--max-executions 128`, `--minimize-seconds 120`, and `--confirmations 2`. Execution counts include complete-suite attempts, initial confirmations and final confirmations, not individual child processes. Confirmations may be raised to 8; execution budgets must reserve both initial and final confirmations and cannot exceed 4,096. The time budget is 1–3,600 seconds, with the last 20 percent reserved for final checking. The shared 30-second per-leg cap still applies. Use a sufficient explicit time budget for large runtime binaries or large selected suites; resource limits never authorize skipping final checks.

Search budget exhaustion retains the last confirmed candidate, but never waives fresh final verification. A failed or incomplete final check returns `ERROR` without publishing a reduced capsule. This includes Bun-only drift first observed during final confirmation. `REDUCED` means fewer selected source bytes with preserved observations, not a fixed migration: a reduced native failure still contains `FAIL`, and a reduced reference disagreement still contains `INCONCLUSIVE`. `UNCHANGED` means no reduction was retained. `search_complete=false` identifies budget-limited or unresolved searches; even a completed line search is not proof of a global minimum or deterministic environmental behavior. Statistics include executions, accepted/rejected/unresolved trials, cache hits and the last unresolved diagnostic.

The output retains its ordinary pair or product capsule format, usable with inspection, the corresponding replay mode and offline export. Eligible native failures remain usable for explicit fix verification; reference disagreements remain ineligible. Reduction reports use `franken-node/native-minimization/v1` or `franken-node/product-minimization/v1`. They contain the new content hash, parent capsule hash, reducer fingerprint, selected sources, byte counts, statistics and full final measured evidence. The product report also records `captured_verdict`. The reduced capsule remains sensitive material and is created privately without overwriting an existing path. Publication errors retain completed reduction evidence in JSON output.

## Export a debugging fixture without execution

Restore a pinned capsule of either schema into a new private directory:

```bash
franken-migration-suite ./reduced-capsule.json \
  --export-inputs ./debug-fixture \
  --expected-sha256 "$REDUCED_CAPSULE_SHA256"
```

Use the hash from your trusted capture or reduction result, not a parent capsule's hash. Export works on reduced/unreduced pair and product capsules. No `--execute`, `--native-bin` or `--bun-bin` is accepted, and no recorded command or runtime is resolved. Unlike reexecution, offline export does not require the producing validator/runtime revision to remain installed.

The new directory is mode 0700 and contains `original/`, `candidate/` and `reproducer.json`. Both trees retain captured bytes, ordinary file modes and contained links. Their input hashes are recomputed and checked before the private (0600) completion manifest is written. The manifest records the complete expected observations and relative project roots; product exports keep all three roles. It does not execute them. `EXPORTED` is a successful extraction, not a successful migration or fresh behavioral validation.

The destination must not exist, including as a symlink. Its parent must already exist. Existing files and directories are never merged, replaced or deleted. On an I/O failure a private partial export can remain; export is not an atomic multi-file transaction. Extracted sources may contain secrets or executable project configuration: review and contain them before opening them in tools that automatically execute workspace code.

## Capsule contract and limits

The schemas are `franken-node/native-migration-capsule/v1` for two runtimes and `franken-node/product-migration-capsule/v1` for three runtimes, each with a separate content-hash domain. They are distinct from the standalone Python replay schema. Both record input identities, sorted entry inventories, ordinary permission modes, contained symlink chains, deduplicated hex-encoded file bytes, test-manifest contents and complete per-case observations. An unchanged candidate shares the original snapshot. The product schema retains the full `ProductReport`, including Node, Bun and native identities and observations.

Import validates canonical relative paths, declared directory parents, link containment/cycles, unique entries and blobs, referenced file hashes, reconstructed snapshot hashes, exact test counterparts, comparison scope and consistency between observations and verdicts before staging. Product imports independently reconstruct reference/native outcomes, divergence channels and counters. Missing Bun evidence, contradictory summaries and weakened exclusions are errors. Capsules use compact canonical JSON: do not pretty-print, append whitespace or edit their encoding. Round-trip canonical checks also reject unknown/duplicate data silently ignored by nested report deserializers.

Capsule-specific limits: 128 MiB serialized input, 32 MiB combined expanded snapshot file bytes, 8 MiB entry metadata, 50,000 entries per snapshot and 64 symlink-resolution hops. The shared executor retains its 1,024-case, 4 KiB path and 30-second leg limits. Capture and replay have a 300-second operation budget; minimization uses its separately bounded budget above. Offline schema detection and the selected import/export reader each use bounded reads. Incomplete execution or resource refusal cannot produce a passing/reproduced result.

Capsules bind the replay, capture, supervision, inventory and workspace-comparison source implementations; product capsules additionally bind the product executor and replay implementation. Reexecution requires matching source fingerprints; retain the validator revision. This is not a binding of the full compiled dependency graph. Runtime hashes likewise do not capture dynamically linked libraries. Clocks, environment variables, random values, temporary absolute paths, external modules and network state can still make exact-input reexecution diverge. `environment_reproduced` and `release_certification` remain false.

Implementations live in `crates/franken-node/src/migration/native_replay.rs`, `product_replay.rs`, `native_minimizer.rs` and `product_minimizer.rs` and are consumed directly by this operator. Product replay shares the existing bounded path/blob/link codec and is exposed under `validation_suite::native_replay::failure_capture::product`; its `minimizer` module uses the shared reduction kernel. Automatic capture beyond supported complete primary validation/checked-rewrite failures, AST/token minimization and whole-environment replay remain separate work.

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

Execute only trusted code. Workspace copies are not an OS sandbox: ambient credentials, absolute paths, network access and external services remain available. Sequential filesystem capture and runtime identity rechecks are not atomic snapshots or defenses against every active swap-and-restore race. Runtime byte hashes and captured input hashes establish measured identities, not signed authenticity or full environmental replay. The Rust regression suite includes explicit real Node/Node and Node/Bun/Node orchestration cases, plus deliberate `/bin/true` and `/bin/false` processes for archive/refusal scenarios. None establishes native Franken compatibility.
