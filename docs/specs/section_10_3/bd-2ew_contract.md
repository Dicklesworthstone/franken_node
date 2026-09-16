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

## Recoverable Native Rewrite Application (Linux)

The primary `run_rewrite` implementation in `crates/franken-node/src/migration/mod.rs` uses `rewrite_transaction.rs` to install an entire planned set of changes rather than writing each file while still discovering the plan.

```bash
# Inspect the proposal without creating a lock, backup, journal or source edit.
franken-node migrate rewrite /path/to/project --json

# Apply through the recoverable native transaction path.
franken-node migrate rewrite /path/to/project --apply --json
```

The command's transformation rules are unchanged. Ordinary `--apply` does not prove JavaScript behavioral equivalence. Add `--verify` for the checked installation path described below, or use migration validation against preserved original and rewritten inputs before making deployment decisions; see [bd-2st_contract.md](bd-2st_contract.md).

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

## References

- [bd-2a0_contract.md](bd-2a0_contract.md) — Project Scanner
- [bd-33x_contract.md](bd-33x_contract.md) — Risk Scorer
- [bd-2st_contract.md](bd-2st_contract.md) — Migration Validation
