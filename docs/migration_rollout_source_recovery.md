# Transaction-bound rollout source recovery

Rollout cancellation can now restore the actual files from a native migration
rewrite, rather than merely updating rollout JSON. This is opt-in: select the
exact native `txn-...` identifier as `--migration-id`. An ordinary `mig-...`
rollout remains a metadata-only progression and never guesses a transaction.

## Select, inspect, promote, restore

First inspect the retained native rewrite history:

```sh
franken-node migrate rollback ./project --json
```

Choose the exact applied transaction from that report, then initialize and
inspect its rollout without promoting it:

```sh
franken-node migrate rollout ./project --migration-id txn-CHOSEN-ID --action status --json
```

`txn-CHOSEN-ID` is a placeholder: use the complete ID produced by the native
rewrite. Binding requires an intact, fully applied transaction, all expected
rewritten source files and modes, and valid original backups. It captures the
canonical journal SHA-256 in durable rollout state. Inspection does not restore
sources. Missing, interrupted, conflicting or already-restored transactions
cannot be admitted for a new rollout; inspect/recover them through the explicit
`migrate rollback` command first.

Normal promotion still requires the existing lockstep evidence:

```sh
franken-node migrate rollout ./project --migration-id txn-CHOSEN-ID --action promote --lockstep-report lockstep.json --json
```

Every promotion of a bound rollout also checks that its exact rewrite remains
fully applied. `--force` does not bypass the source-transaction binding and
cannot resurrect an aborted rollout or use promotion as a rollback substitute.
These checks do not upgrade the existing lockstep evidence to full-project or
release certification.

Restore through the rollout:

```sh
franken-node migrate rollout ./project --migration-id txn-CHOSEN-ID --action rollback --json
```

Confidence-triggered automatic rollback in `promote` follows the same source
recovery path. It is not a new background confidence monitor. Restoration
failure is included in the returned promotion error, not silently discarded.

## Recovery protocol

The project-wide rollout lock covers load, decision, restoration and final
state publication. A durable `aborted` / `failed` intent is written before
source restoration begins. Native restoration then acquires the existing
rewrite lock, checks the bound journal hash under that lock, preflights all
sources/backups, and uses the existing per-file write-ahead recovery protocol.
Only a successful restore or the same journal's completed restore receipt
allows rollout status to become `rolled_back`.

Conflicting user edits, changed permissions, missing/corrupt backups, another
pending rewrite or changed journal inventory leave the rollout aborted/failed.
No earlier file is restored when the complete preflight detects a later-file
conflict. Preserve the backups and journals; resolve the reported conflict
explicitly, then repeat rollback with the same migration ID. Promotion remains
blocked throughout recovery, including forced promotion.

If the process exits after native restoration but before rollout completion is
published, the next rollback recognizes the native completed receipt and
finishes the state transition. It does not replace files again. Repeating a
completed rollout rollback also leaves later user edits untouched.

Unix state persistence uses pinned no-follow directory descriptors, exclusive
temporary-file creation, file fsync, atomic rename and directory fsync. Reads
are bounded to 2 MiB and reject linked/nonregular metadata. Native source
restoration is Linux-only; other platforms reject a transaction-bound rollout
rather than pretending that restoration happened.

## Report and authority boundaries

A bound report includes:

```json
"source_rollback": {
  "transaction_id": "txn-CHOSEN-ID",
  "journal_sha256": "64 lowercase hexadecimal characters",
  "restoration_recorded": true
}
```

`restoration_recorded` describes a completed transaction receipt, not a fresh
certification of current source bytes. An unbound cancellation has no
`source_rollback` and explicitly says that no source files were restored.

This restores only files retained in the selected native rewrite transaction,
including their recorded modes. It does not stop running applications, change
fleet traffic, undo database writes, revoke credentials, or reverse external
side effects. Rollout stages remain local control state. Journals and state
pins assume trusted local recovery metadata; they are not publisher signatures
or a sandbox against a privileged actor. The legacy `receipt_signature` field
continues to contain a digest, not a cryptographic signature.
