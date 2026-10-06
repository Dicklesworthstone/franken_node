# Reviewed candidate installation

`franken-migration-apply` connects the existing captured-input validator to the
native recoverable rewrite transaction. It installs an independently prepared
migration into the original project only after a fresh, complete passing
Node/Bun/Franken comparison. An imported JSON report cannot authorize writes.

## Inspect and approve

Keep original and candidate in separate, non-nested directories. Prepare the
candidate using the same test inventory, golden fixtures, application request,
metadata, dependencies and permissions as the original, except for intended
ordinary-file content changes. Inspect without executing project code or
opening the rewrite writer:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-apply -- inspect /work/original /work/candidate
```

The JSON report includes both captured hashes, the selected tests, and changed
paths with before/after hashes and byte counts. It does not print source bytes.
Review the proposed source diff independently, along with that inventory. Do
not blindly promote a hash from an untrusted report as an independent approval.
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
runtime discovery. The candidate is reconstructed through the existing
`RewriteCandidate::prepare` implementation, and its complete captured hash must
still equal the reviewed candidate hash. It is not a partial diff silently
omitting unsupported changes.

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
the immutable candidate. Every selected test, application argument, declared
stdin/environment/working directory, golden assertion and persistent workspace
delta uses the existing production validator. Reference failure/disagreement,
incomplete observations, timeouts, native failure or unequal effects cannot be
converted to PASS. The captured concurrency permission remains enforced.

After complete passing evidence, both on-disk input trees must still match their
pre-execution snapshots. Only the immutable captured before/after bytes are
passed to the existing native transaction. The proposal is never reread to
redefine the installed bytes. Changes during validation refuse installation;
the command does not conceal ambient guest effects by silently undoing them.

Supported changes are existing regular-file content replacements. New/deleted
or renamed entries, changed file modes, changed link targets/kinds, reserved
metadata changes, and altered golden expectations or execution requests are
rejected. The existing limits remain: at most 1,000 replacements, 10 MiB per
before/after file, 256 MiB combined replacement bytes, and the validator's
bounded whole-project capture and execution budgets. This command does not
implement package installation or structural migration.

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
transaction. `REJECTED` and `ERROR` exit nonzero. `execution_attempted` means the
executor was called, not proof that every guest launched or completed; the
individual validation observations record the measured outcomes.

The transaction preserves original backups, modes, all-source preflight,
no-follow descriptor access, write-ahead intent and durability barriers. Each
file replacement is atomic, not the entire multi-file tree. Interruptions or
I/O errors can leave recovery work; retain journals/backups and inspect them.
A lost stdout report after a completed transaction is not an automatic rollback.

## Successive migrations and transaction-scoped originals

The reviewed installer uses `apply_versioned_with_receipt` and writes
`franken-node/rewrite-transaction/v2` journals. Each changed file's exact
pre-install bytes are retained privately at:

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
the three-runtime suite runs again. A
previous PASS or installation receipt cannot authorize the next migration.
The second transaction's original is candidate one's installed content, not
the file's first-ever original. An identical proposal is still validated, but
returns `UNCHANGED` without another transaction.

Restore the explicitly selected transaction using its exact returned identity.
For overlapping migrations, restore candidate two to candidate one, then
candidate one to the original. Trying to restore an earlier transaction while
its files contain a different later image fails the existing full preflight;
unrelated user edits also remain conflicts, not permission to overwrite them.
This is content/mode conflict protection, not a global deployment stack or a
claim of ordering for independent, non-overlapping transactions. A completed
rollback retry never changes newer source work.

Both explicit rollback and interrupted-install recovery use the journal's
schema to select its originals. Missing, corrupt, linked or non-private v2
preimages are errors: even a correct path-global backup cannot substitute.
Historical v1 journals continue to use their immutable `.migrate-backup/PATH`
backups; a v2 installation can follow them without modifying their evidence.
The original library `apply` and `apply_with_receipt` APIs retain that v1
first-original contract. They do not silently adopt the new storage format.

Use an updated recovery binary that understands v2 for new reviewed installs;
older readers reject this schema. Keep the complete transaction directories,
not just the returned JSON summary. No automatic history conversion, backup
deletion, garbage collection, or fallback to another generation is performed.
The same per-operation limits and non-atomic multi-file recovery contract apply.

## Continue to rollout or restore

Use the exact returned transaction ID, replacing the example placeholder:

```sh
franken-node migrate rollout /work/original --migration-id txn-EXACT-ID \
  --action status --json
franken-node migrate rollout /work/original --migration-id txn-EXACT-ID \
  --action rollback --json
```

The second command restores through the explicitly bound rollout. The
programmatic recovery API accepts the returned ID
and journal hash through `rollback::run_pinned`; it does not select newer work.
For rollout, initialize the installed project's status before producing fresh
signed cohort evidence, following `migration_rollout_source_recovery.md`.
The pre-install validation report is neither signed rollout authorization nor
reusable after installation/state changes. Signed rollout storage and quantified
promotion admission remain separate, unchanged decisions.

Use trusted project code only. Guest processes retain ambient host authority;
the writer lock coordinates cooperating operators, not malicious same-user
processes, arbitrary editors, external services or running applications. This
is not an OS sandbox or a globally atomic snapshot. No fleet traffic is moved,
no live services are stopped, and no external side effects are rolled back.
The report always sets `release_certification: false`; no compatibility-corpus,
production-safety or migration-throughput KPI follows from installing one suite.
