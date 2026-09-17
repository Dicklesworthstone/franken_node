# bd-2ew: Automated Rewrite Suggestion Engine

## Decision Rationale

After scanning a project and scoring risks, operators need actionable rewrite suggestions. The suggestion engine maps detected API usage to franken_node equivalents, provides code transformation hints, and generates rollback plan artifacts so operators can safely test changes.

## Scope

1. Map Node.js/Bun API calls to franken_node equivalents
2. Generate rewrite suggestions with before/after examples
3. Produce rollback plan artifacts for each suggestion
4. Prioritize suggestions by risk level and migration impact
5. Provide a Rust module in `crates/franken-node/src/migration/rewrite_suggestion_engine.rs`
   so the suggestion engine is available to crate code and tests, not only
   Python gate scripts.

## Suggestion Categories

| Category | Description | Example |
|----------|-------------|---------|
| `direct-replacement` | 1:1 API mapping exists | `require('fs')` → native fs shim |
| `adapter-needed` | Adapter/wrapper required | `http.createServer` → engine-native server |
| `removal-needed` | API must be removed | `process.binding()` → remove or replace |
| `manual-review` | No automated rewrite possible | Native addon usage |

## Rollback Plan

Each suggestion includes:
- Original code snapshot
- Suggested replacement
- Test commands to verify equivalence
- Rollback command (git restore path) with an argv form so operator tooling does
  not need to parse shell text

Those suggestion templates are separate from the native transaction rollback command described below. Native rollback uses recorded source identities and backups, not a Git restore command.

## Recoverable Native Rewrite Application (Linux)

The primary `run_rewrite` implementation in `crates/franken-node/src/migration/mod.rs` uses `rewrite_transaction.rs` to install an entire planned set of changes rather than writing each file while still discovering the plan.

```bash
# Inspect the proposal without creating a lock, backup, journal or source edit.
franken-node migrate rewrite /path/to/project --json

# Apply through the recoverable native transaction path.
franken-node migrate rewrite /path/to/project --apply --json
```

The transaction writer does not decide transformation semantics; the ESM transformation rules are described below. Ordinary `--apply` does not prove JavaScript behavioral equivalence. Add `--verify` for the checked installation path described below, or use migration validation against preserved original and rewritten inputs before making deployment decisions; see [bd-2st_contract.md](bd-2st_contract.md).

### Complete-plan preflight and installation

On Linux, `--apply` takes a nonblocking advisory project lock and checks for an interrupted transaction **before planning new rewrites**. The lock remains held through planning and installation. Another cooperating writer is refused instead of being allowed to interleave replacements.

No live source is replaced until all proposed source bytes and existing backups have been checked. A stale source, incompatible existing backup, unsupported path or over-limit plan therefore prevents earlier files from being rewritten. The planner refuses more than 1,000 changed files or more than 256 MiB of combined original/replacement bytes; it never evicts earlier rollback entries to make a truncated plan fit.

Original backups remain at `.migrate-backup/<source-path>`. Existing backups with identical bytes may be reused; different bytes are never overwritten. Newly created backups and staged replacement files have mode 0600. Ordinary source permission bits, including executability, are preserved when replacements are installed. Source files with special permission bits, hard links, symlinks or nonregular types are refused. Each original and replacement is bounded to 10 MiB.

All path components are traversed relative to held directory handles with no-follow opens. Source contents and metadata are checked again after staging and before each atomic replacement. Parent directories and installed files are synchronized. Backup directories may be created during preflight even when the transaction is refused; refusal does not imply absolutely no metadata was created.

### Persistent recovery

Before the first source replacement, the writer persists a bounded journal at:

```text
.migrate-backup/.franken-rewrite/pending.json
```

Schema `franken-node/rewrite-transaction/v1` records the session, canonical relative paths, original and replacement content hashes/lengths, and source modes. A private session directory retains replacement inputs. Successful installation moves the journal to that session's `applied.json`; successful recovery moves it to `rolled-back.json`. These records and original backups are retained, not automatically deleted.

If installation returns an error, the writer attempts rollback. If the process exits before completion, the next `--apply` recovers the pending transaction before computing a new plan. Recovery accepts an unchanged original as already restored. It replaces a known installed replacement only with an integrity-checked original backup. **Unrelated source edits, changed permissions, missing files or corrupt backups are not silently overwritten.** Other safely recoverable files are still restored; unresolved conflicts leave `pending.json` in place and prevent a new apply.

A dry run does not recover an interrupted apply. It remains nonmutating and may therefore inspect a partially installed tree. Preserve the journal and backups when resolving a recovery conflict; removing the journal would discard the writer's ability to distinguish incomplete installation from a finished operation.

### Scope and evidence limits

This is **recoverable multi-file installation**, not a filesystem-wide atomic transaction. Other processes can observe intermediate replacements, and advisory locks do not stop arbitrary editors. The final source check and rename are not an atomic compare-and-swap against an uncooperative writer. Directory handles prevent ordinary symlink redirection but do not make privileged concurrent directory renames safe. Journals are private local recovery records, not signed certificates, and same-privilege journal forgery is outside this mechanism's trust boundary.

Tests cover complete application, late backup conflicts, source-mode preservation, plan overflow, symlink/hardlink refusal, interrupted partial/final installation, corrupt recovery data, unrelated edits, and a real child process that exits without running destructors. Process-crash recovery is exercised; sudden storage-device power loss is not simulated. No full-environment capture, autonomous rollout, semantic transformation proof or runtime-equivalence gate is added by this writer itself. Non-Linux builds retain the existing per-file write mechanism.

The public-API regressions live in `crates/franken-node/tests/native_rewrite_transactions.rs`, included by the registered `migrate_cli_e2e` target. They exercise the actual `run_rewrite` implementation rather than a substitute writer:

```bash
rch exec -- cargo test -p frankenengine-node --features test-support \
  --test migrate_cli_e2e rewrite_transactions -- --nocapture
```

The read-only `Native rewrite transactions` workflow additionally compiles the exact transaction module in standalone and nested layouts and compiles the complete primary migration module with its production timeout configuration. These focused builds do not substitute for a full product/engine build.

## Syntax-Aware ESM Specifier Rewriting

The primary ESM transformation uses `migration/module_specifiers.rs` and the existing Tree-sitter JavaScript/JSX grammar. It no longer treats individual source lines as import declarations. No new command or flag is required: dry-run planning, ordinary apply and checked apply all consume the same transformation. Existing file/package-based module-format classification remains in force.

Recognized forms include multiline default/named/namespace imports, side-effect imports, compact declarations without optional spaces, multiple declarations on one line, named/star/namespace re-exports, and literal dynamic `import()` expressions. Literal dynamic imports may use quotes or a template without interpolation; executable imports inside template substitutions are visited. Import attributes, dynamic-import options, comments around tokens, declaration placement and dynamic-import timing are retained.

Only the byte ranges inside recognized module-specifier literals may change. Hashbangs, CRLF/newlines, Unicode, quote style, comments, regexes, ordinary strings, template raw text and JSX text remain unchanged. The rewriter does not hoist declarations, regenerate the AST as formatted source, rename files, add package configuration, or convert an ESM source to a different module format.

Builtin matching uses an exact allowlist for the public unprefixed Node 20/22 baseline. Recognized subpaths such as `fs/promises`, `path/posix`, `stream/web` and `util/types` become explicit `node:` imports. Arbitrary package subpaths such as `fs/custom` and `stream/adapter` remain untouched, as do relative paths, URLs, existing `node:` specifiers and unknown package names. Unprefixed names of prefix-only builtins, such as `test`, are not rewritten into a different module. The same exact normalizer is shared by the existing CommonJS conversion path; that conversion's format/hoisting behavior is otherwise unchanged.

Malformed or unsupported syntax, computed/interpolated imports, escaped specifier literals, and recognized CommonJS calls/export mutations in ESM-classified source require manual review. Refusal returns the entire source unchanged and creates no partial replacement for that file. The grammar does not implement typed TypeScript: such source is explicitly reported for manual migration instead of guessed from lines. Conservative CommonJS detection does not prove lexical binding identity and may require review for a locally defined `require` function.

Planning is bounded to 10 MiB of source, one million visited syntax nodes, 65,536 edits and a two-second parse/traversal budget. The parse callback supports cancellation; AST traversal is iterative rather than recursive. Proposed edits are checked for overlap before the result is constructed in one forward pass. Parser/budget failure is a manual finding, not an empty-success substitute. Existing whole-project transaction limits still apply.

The ESM rewrite changes only specifier spelling, not the product's security policy or capability grants. Ordinary apply may still install independently valid changes in other files while reporting manual-review items; checked apply refuses installation when review items remain. Explicit builtin spelling does not by itself certify compatibility with the selected native runtime.

Regression coverage includes exact byte-preservation tests and actual Node execution before and after transformation. Public `run_rewrite` tests exercise multiline imports, dynamic imports, third-party package exports, idempotence, immutable backups, executable modes and native rollback to the original bytes. JSX tests establish source preservation, not direct Node JSX execution. These tests validate the transformer and writer; they are not native Franken compatibility measurements or a full product build.

## Checked Application Before Installation (Linux)

```bash
franken-node migrate rewrite /path/to/project --apply --verify --json
```

`--verify` opts into execution-backed installation. It requires `--apply` and cannot be combined with `--emit-rollback`; the checked report already contains the planned original/replacement entries, and successful installation preserves the writer's backups and journal. Ordinary dry runs and ordinary `--apply` keep their existing behavior and do not implicitly execute tests.

The checked path holds the cooperative transaction lock from recovery through installation. After recovering any previous pending transaction, it captures the project once. Static validation and the real rewrite planner run on a private copy of that captured input. Static prerequisites must pass and every manual-review item must be resolved before either runtime executes.

The candidate is built only from exact captured file preimages and the planner's complete replacement list. Original inputs run on installed Node; the candidate runs on the invoked native product with the existing native-engine and policy checks. Every discovered test starts from its own fresh workspace. A nonempty, complete passing suite is mandatory, including both successful exits, exact stdout/stderr and persistent filesystem-delta agreement. Matching failures, infrastructure errors, missing observations, missing tests and partial runs never authorize installation. There is no entrypoint-smoke rescue and no reference-success fallback.

After a passing comparison, a new capture of the entire live input must still match the original digest, including unedited dependencies and configuration. Only then does the recoverable transaction writer install the exact measured replacement list. Backup conflicts and stale preimages retain their existing fail-closed behavior. An unchanged proposal still requires successful execution; it does not bypass validation.

Checked JSON uses `franken-node/checked-rewrite/v1`. It retains `static_validation`, `rewrite`, `validation`, and `errors` as they become available. `status` is `APPLIED`, `UNCHANGED`, `REJECTED`, or `ERROR`. The first two return exit 0, measured or prerequisite rejection returns 1, and infrastructure/input/installation errors return 2. Reports on rejection keep `rewrites_applied=0` and retain any completed differential observations. Normal usage errors still use the existing migration error handler. Non-Linux checked apply is refused.

Reports contain the existing rewrite planner's source preimages and replacements; they can disclose private code or embedded credentials. Redirect JSON only to a private destination outside the measured input. Differential observations themselves contain output and file hashes, not raw output streams. `release_certification` is always false.

This is not an operating-system sandbox. Execute only trusted projects: absolute paths, network access and ambient authority remain available subject to the selected runtimes' normal policies. Filesystem comparison excludes `.git` entries and root `.franken-node` state and does not observe transient writes or external effects. The input recheck and installation are not an atomic operation against an uncooperative editor. Recovery of an earlier interrupted transaction may change sources before the new checked proposal is assessed; rejecting a new proposal guarantees that proposal is not installed, not that recovery or arbitrary guest code made no changes.

The implementation lives in `verified_rewrite.rs` and the production suite's `rewrite_candidate.rs` child module. Regression coverage uses actual planner/static-validation code, the actual capture/observer/supervisor, and the actual transaction writer with explicitly identified Node/Node executions. Those tests establish orchestration and refusal behavior, not native Franken compatibility or general semantic equivalence. Native failure-capsule export, autonomous deployment and release certification remain separate work.

## Native Rollback and Recovery-Only Operation (Linux)

The primary command now restores applied native rewrites from their retained transaction identities. It does not invoke Git, a shell, Node, Bun or guest project code.

```bash
# List retained transactions without changing project files or recovering work.
franken-node migrate rollback /path/to/project --json

# Copy an exact transaction_id from history into TRANSACTION_ID, then preview.
franken-node migrate rollback /path/to/project --transaction "$TRANSACTION_ID" --json

# Restore only that transaction after complete source/backup preflight.
franken-node migrate rollback /path/to/project --transaction "$TRANSACTION_ID" --apply --json
```

There is no implicit latest-transaction selection and no force override. Without `--apply`, selecting a transaction remains a preview. Applying requires an explicit ID. History and preview open only existing metadata and acquire the existing cooperative lock; they never create a backup directory, lock file or journal, and they do not perform automatic recovery. A project without native transaction history has an empty history, not a guessed Git-based recovery plan.

### Restoration contract

The selected journal must be valid and bound to its transaction directory. Applied, pending and completed rollback records must agree when multiple records exist. Every original backup is checked against its recorded hash/length, and every source must match either the recorded original or the installed rewrite, including permissions. The whole plan is preflighted before writing restoration intent or changing any source. A conflict in a later file cannot partially restore an earlier file. Missing files, corrupt backups, changed permissions, hard links and symlink redirection are refused rather than overwritten.

Restoration writes the selected journal to the existing `pending.json` location before replacing the first source. It then uses the writer's existing recovery mechanism to restore exact original bytes and modes. Already-original files are left in place. The original `applied.json`, original backups and staged replacements are retained; completion records `rolled-back.json` in the same session. No historical file or unrelated source is deleted.

An interrupted rollback remains recoverable: retry the same transaction with `--apply`, or let the next ordinary rewrite recover the pending work first. A pending initial apply can also be selected explicitly to restore originals **without planning any new rewrite**. A different pending transaction blocks the selected restoration instead of being implicitly recovered. Late errors or new conflicts after preflight may leave a partial restoration; the pending journal and available report details remain for recovery.

Retrying an already completed transaction returns `ALREADY_ROLLED_BACK` without changing or certifying current sources. This is a statement about the retained receipt: it must not undo later user edits or a newer successful migration. History reports `APPLIED`, `APPLY_INTERRUPTED`, `ROLLBACK_PENDING`, or `ROLLED_BACK`; it does not infer chronological latest order from transaction names.

### Rollback reports and bounds

JSON schema is `franken-node/migration-rollback/v1`. Reports include transaction identity, a hash of the validated canonical journal, source/backup hashes, preflight states, conflicts and any pending transaction ID. They omit raw source and backup contents. File states describe preflight observations, not an atomic final-state certificate. Status is `HISTORY`, `READY`, `CONFLICT`, `ROLLED_BACK`, `ALREADY_ROLLED_BACK`, or `ERROR`. Conflict exits 1, input/infrastructure/recovery errors exit 2, and the other outcomes exit 0. Non-Linux rollback is refused.

History is bounded to 1,000 transaction directories, 4,096 directory entries and 16 MiB of cumulative journal reads; a journal is at most 2 MiB. Existing per-file and per-plan rewrite bounds still apply. An exhausted history bound fails explicitly rather than presenting a partial history as complete. An explicitly selected ID does not require scanning all other history.

The implementation is `rewrite_transaction::rollback` in `rewrite_rollback.rs`, reexported as `migration::rollback`. It shares the writer's held-directory/no-follow operations and owner-bound advisory lock. The guard explicitly unlocks when ownership ends so a duplicate descriptor transiently inherited during another thread's process spawn cannot keep a completed operation locked. Tests cover actual descriptor duplication, real process exits at several restoration points, repeated rewrite/restore cycles, original-byte/mode restoration, and preservation of unrelated edits.

Rollback has the same local trust and concurrency limits as the writer: it is not a multi-file atomic filesystem operation, a signed receipt verifier, protection from privileged journal forgery, or an atomic compare-and-swap against arbitrary editors. Power-loss durability is not simulated by process-crash tests. It restores the transaction's source changes, not external services, guest-created files or deployment state.

## Invariants

1. Every suggestion maps to a compatibility registry entry or "untracked".
2. Rollback plans are always generated alongside suggestions.
3. Suggestions are prioritized: critical first, then high, medium, low.
4. Engine deterministically produces identical output for identical input.
5. Time-dependent report fields must be injectable by tests so fixed-timestamp
   Rust verification can prove deterministic output.
6. Unknown API families must fail into `manual-review` suggestions rather than
   disappearing from the report.
7. Linux apply preflights the complete plan and writes a recovery journal before
   its first live source replacement. Recovery never overwrites an unrelated edit.
8. Rollback entries are never truncated to fit a diagnostic retention cap.
9. Checked apply installs only the measured replacement plan after a complete
   nonempty process/filesystem PASS and a fresh captured-input identity check.
10. Native rollback previews are nonmutating; explicit restoration preflights all
    sources and backups, preserves later user edits, and records resumable intent.
11. ESM specifier migration edits only recognized syntax-node ranges; a refused
    source produces no partial replacement, and builtin matching is exact.

## References

- [bd-2a0_contract.md](bd-2a0_contract.md) — Project Scanner
- [bd-33x_contract.md](bd-33x_contract.md) — Risk Scorer
- [bd-2st_contract.md](bd-2st_contract.md) — Migration Validation
