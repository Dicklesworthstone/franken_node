# Reviewed candidate installation

`franken-migration-apply` connects the existing captured-input validator to the
native recoverable rewrite transaction. It installs an independently prepared
migration into the original project only after a fresh, complete passing
Node/Bun/Franken comparison. An imported JSON report cannot authorize writes.

## Inspect and approve

Keep original and candidate in separate, non-nested directories. Prepare the
candidate using the same test inventory, golden fixtures, application request,
metadata, dependencies and existing permissions as the original, except for
intended ordinary-file replacements and new regular files under existing
directories. Inspect without executing project code or opening the rewrite writer:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-apply -- inspect /work/original /work/candidate
```

The JSON report includes both captured hashes, the selected tests, and changed
paths with before/after hashes and byte counts. Each change has `kind: "replace"`
or `kind: "create"`. Creations report `before_sha256: null` and
`before_bytes: null`: absence is not an empty file. Their `created_mode` is the
reviewed permission bits as an integer (for example, 416 is octal 0640).
The report does not print source bytes. Review the proposed source diff
independently, including added files and their modes, along with that inventory.
Do not blindly promote a hash from an untrusted report as an independent approval.
Set ORIGINAL_SHA256 and CANDIDATE_SHA256 to the reviewed hashes, then run:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-apply -- apply /work/original /work/candidate \
  --expected-input-sha256 "$ORIGINAL_SHA256" \
  --expected-candidate-input-sha256 "$CANDIDATE_SHA256" \
  --native-bin /installed/franken-node --bun-bin /installed/bun --execute
```

Node must be available in an absolute PATH directory. All selected executables
must be outside both projects. The three executable hashes must differ; that
check does not authenticate their brands. Choose real trusted runtime binaries.

Both hashes and explicit execution consent are mandatory. Wrong, stale or
swapped approvals and unsupported changes fail before writer creation or
runtime discovery. The candidate is reconstructed through the shared
`RewriteCandidate` preparation implementation, and its complete captured hash
must still equal the reviewed candidate hash. It is not a partial diff silently
omitting unsupported changes. Replacement-only library consumers are refused
when a candidate adds files; the installer consumes the complete `changes()`
plan containing both replacements and additions.

The command then holds the native rewrite lock across execution, admission and
installation. It deliberately refuses an unfinished rewrite instead of
implicitly restoring another operation before validating this proposal. Use
explicit `migrate rollback` recovery to resolve pending work first.

First use may create the native writer's private directories and empty lock
file. Those expected initialization writes are not permission to ignore changes
under `.migrate-backup`. Before opening the real writer, the installer stages
the immutable reviewed original into a private temporary tree and runs the
same nonrecovering writer initialization there. The real post-open tree must
match that exact predicted capture. A new strict freshness guard then covers
all its bytes, including initialized metadata, until installation begins.
Unrelated source additions or guest changes to writer metadata are rejected.
The original reviewed hashes and executed snapshots are never rebound to the
post-initialization state. No capture exclusion is added by this accommodation.

## Execution and installation contract

Node and Bun execute the immutable original snapshot; native Franken executes
the immutable candidate, including its added helpers. Every selected test,
application argument, declared stdin/environment/working directory, golden
assertion and persistent workspace delta uses the existing production validator.
Reference failure/disagreement, incomplete observations, timeouts, native failure
or unequal effects cannot be converted to PASS. The captured concurrency
permission remains enforced. Adding an automatically discovered test changes
the inventory and is still rejected; a new helper cannot redefine the oracle.

After complete passing evidence, both on-disk input trees must still match their
pre-execution snapshots, with the original's exact writer initialization covered
by its separate guard. Only immutable captured bytes and reviewed new-file
modes are passed to the native transaction. The proposal is never reread to
redefine the installed bytes. Changes during validation refuse installation;
the command does not conceal ambient guest effects by silently undoing them.

Supported changes are existing regular-file content replacements and new
regular files whose parent directories already exist in the original capture.
New files require ordinary owner-readable modes, no symlink parents, and the
same filesystem as the transaction store. New directories, deleted or renamed
entries, changed existing file modes, changed link targets/kinds, reserved
metadata changes, and altered golden expectations or execution requests remain
rejected. The existing limits remain: at most 1,000 combined replacements and
creations, 10 MiB per before/after file, 256 MiB of logical plan bytes, and the
validator's bounded whole-project capture and execution budgets. This command
does not run a package manager or implement arbitrary structural migration.

Successful installation returns status `APPLIED` and `source_transaction`:

```json
{
  "transaction_id": "txn-EXACT-ID",
  "journal_sha256": "64 lowercase hexadecimal characters",
  "files": 2
}
```

The identity comes directly from this writer's completed journal while the
lock is held, never from guessing the latest history entry. An identical
candidate still requires validation but returns `UNCHANGED` without a new
transaction. A creation-only plan is not unchanged: even adding an empty file
requires a transaction. `REJECTED` and `ERROR` exit nonzero.
`execution_attempted` means the executor was called, not proof that every guest
launched or completed; individual observations record the measured outcomes.

The transaction preserves original backups, modes, all-source preflight,
no-follow descriptor access, write-ahead intent and durability barriers. Each
file replacement or creation is atomic, not the entire multi-file tree.
Interruptions or I/O errors can leave recovery work; retain journals/backups
and inspect them. A lost stdout report after a completed transaction is not an
automatic rollback.

## Successive migrations and transaction-scoped originals

Replacement-only reviewed installs retain `franken-node/rewrite-transaction/v2`
journals. Plans containing new files use `franken-node/rewrite-transaction/v3`.
Each replaced file's exact pre-install bytes are retained privately at:

```
.migrate-backup/.franken-rewrite/TRANSACTION-ID/RECORD-INDEX.before
```

The record index is its zero-based position in that journal, not a caller-chosen
path. The matching `.after` image remains in the same transaction. Both images
are written create-only with mode 0600 and made durable before the pending
journal. All preimages are checked again before any live file is replaced.
Earlier journals, preimages and path-global backups are never overwritten.

This permits original -> candidate one -> candidate two without first undoing
candidate one. Before each application, inspect and independently review the
currently installed original and the next candidate again. Prepare that next
candidate from the current original's full captured tree, including its retained
recovery and rollout metadata; editing an old candidate that lacks the new
history is still an inventory mismatch. These copies contain private history
and must remain private. Use the new role hashes with the same `apply` command;
the three-runtime suite runs again. A previous PASS or installation receipt
cannot authorize the next migration. The second transaction's original is
candidate one's installed content, not the file's first-ever original. An
identical proposal is still validated, but returns `UNCHANGED` without another
transaction.

Restore the explicitly selected transaction using its exact returned identity.
For overlapping migrations, restore candidate two to candidate one, then
candidate one to the original. Trying to restore an earlier transaction while
its files contain a different later image fails the existing full preflight;
unrelated user edits also remain conflicts, not permission to overwrite them.
This is content/mode conflict protection, not a global deployment stack or a
claim of ordering for independent, non-overlapping transactions. A completed
rollback retry never changes newer source work.

Both explicit rollback and interrupted-install recovery use the journal's
schema to select its originals. Missing, corrupt, linked or non-private
transaction preimages are errors: even a correct path-global backup cannot
substitute. Historical v1 journals continue to use immutable
`.migrate-backup/PATH` backups; newer installations can follow them without
modifying their evidence. The original library `apply` and `apply_with_receipt`
APIs retain that v1 first-original contract. They do not silently adopt the new
storage format.

## New-file creation and restoration of absence

A v3 creation record explicitly marks its original as absent. It never treats
an existing empty file as an absent target. Preparation checks the complete plan
before staging recovery images or changing a live source. Creation uses an
atomic no-replace rename, so a pathname appearing after preflight is not
silently overwritten.

Each creation retains a private `.after` image and a second, durable `.new`
image with the reviewed file mode inside the private transaction directory.
Installation moves `.new` to the approved absent pathname. Its continued
presence proves installation did not consume it: a colliding source is then
preserved, even when its bytes and permissions happen to match the proposal.

Rollback previews report `original_absent: true`. A successful rollback restores
absence by moving the unchanged created file into its transaction as
`RECORD-INDEX.retired`, not deleting its bytes. The move cannot overwrite an
existing retained file. An interrupted recovery recognizes the retained image;
a new source appearing after retirement is a conflict, even if byte-identical.
Source and transaction directory changes are synchronized before completion is
recorded. Existing parent directories are never removed.

Modified contents, changed permissions, symlinks and hard links fail the normal
explicit rollback's all-file preflight without restoring earlier files. An
interrupted installation retains the existing startup recovery semantics: it
can restore safe records while preserving conflicts and leaving pending intent
for retry. A later migration can replace an earlier created helper; restore
that later generation first before restoring the earlier file's absence.

Use an updated recovery binary that understands v3 for plans containing new
files; older readers reject this schema. Keep the complete transaction
directories, including retained images, not just the returned JSON summary.
No automatic history conversion, backup deletion, garbage collection, or
fallback to another generation is performed. The same per-operation limits
and non-atomic multi-file recovery contract apply.

## Continue to rollout or restore

Use the exact returned transaction ID, replacing the example placeholder:

```sh
franken-node migrate rollout /work/original --migration-id txn-EXACT-ID \
  --action status --json
franken-node migrate rollout /work/original --migration-id txn-EXACT-ID \
  --action rollback --json
```

The second command restores through the explicitly bound rollout. The
programmatic recovery API accepts the returned ID and journal hash through
`rollback::run_pinned`; it does not select newer work. For rollout, initialize
the installed project's status before producing fresh signed cohort evidence,
following `migration_rollout_source_recovery.md`. The pre-install validation
report is neither signed rollout authorization nor reusable after
installation/state changes. Signed rollout storage and quantified promotion
admission remain separate, unchanged decisions.

Use trusted project code only. Guest processes retain ambient host authority;
the writer lock coordinates cooperating operators, not malicious same-user
processes, arbitrary editors, external services or running applications. This
is not an OS sandbox or a globally atomic snapshot. No fleet traffic is moved,
no live services are stopped, and no external side effects are rolled back.
The report always sets `release_certification: false`; no compatibility-corpus,
production-safety or migration-throughput KPI follows from installing one suite.

## Cancelling reviewed installation

The Linux `apply` command handles Ctrl-C/SIGINT, SIGTERM and SIGHUP as a sticky
cancellation request. No additional flag is required. Signal setup happens
before capture, writer initialization or project execution; a conflicting
existing handler is an error, not permission to overwrite it. The handler only
sets the operation's shared atomic token. Inspection does not register a handler.

Before installation, cancellation stops active owned runtime process groups,
closes their pipes and reaps their leaders through the existing supervisor.
All started case workers are joined. Later runtime legs and cases do not launch
once they observe the request. Completed observations remain in the report;
interrupted product validation is `ERROR`, not a native `FAIL`, passing evidence
or automatic source-restoration authorization. A signal after validation has
finished is checked again before the writer can install its captured plan.

The JSON report adds `cancellation_requested` and `installation_started`:

| Cancellation observation | Result |
|---|---|
| Before the final installation boundary | `status: "CANCELLED"`, `installation_started: false`, no source transaction, exit 130. |
| After entering the journaled writer | Preserve the actual `APPLIED`, `UNCHANGED` or `ERROR` result and any transaction receipt; `installation_started: true`, `cancellation_requested: true`, exit 130. |
| No request observed | Existing success/error status and exit behavior, with `cancellation_requested: false`. |

`installation_started` means the native writer was entered. It is not a claim
that files changed or that installation succeeded. An empty admitted plan may
return `UNCHANGED`. **Exit 130 does not mean that installation did not happen.**
Always inspect the structured status and returned transaction identity. When
stdout is lost or an I/O error leaves the outcome uncertain, inspect retained
journals rather than assuming that a retry is safe or that rollback occurred.

The final successful token check is the commit boundary. After that check,
cooperative signals are deferred through the existing journaled installation,
durability barriers and any failure recovery. There are no new cancellation
returns inside the writer. Repeated signals do not bypass this shield or reset
the token. SIGKILL, process crashes and power loss still require the existing
interrupted-transaction recovery protocol; cooperative cancellation is not an
atomic multi-file transaction or a guarantee against abrupt termination.

Cancellation is checked between capture/preparation phases and between bounded
process-I/O polling rounds. Existing execution and cleanup budgets remain in
force, but cancellation cannot instantly interrupt blocking kernel filesystem
or report-output I/O or synchronous capture work. No hard cancellation-latency
bound is claimed.
A cancelled pre-install operation can leave expected initialized lock metadata;
it does not install the reviewed changes. Guest ambient/external effects are
not undone, and escaped process-group descendants remain outside the cleanup
guarantee. Cancellation does not add an OS sandbox.

Library callers can pass their own per-operation `product_oracle::CancellationToken`
to `RewriteCandidate::validate_product_cancellable`. Tokens are independent by
default; cloned tokens share a one-way request. The library does not install
signal handlers or infer cancellation from a manifest, report or environment.
Existing non-cancellable entrypoints retain their behavior. This integration
covers the reviewed installer, not signal handling for every other migration,
attestation, replay, rollout or fleet command.
