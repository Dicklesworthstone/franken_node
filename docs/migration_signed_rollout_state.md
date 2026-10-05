# Operator-signed rollout state and transition history

Validation signatures authenticate a validator's measured report. They do not
by themselves authenticate the rollout controller's stored lifecycle state.
Operator-signed storage closes that separate boundary: every persisted state
revision covers the entire history, source-recovery binding, confidence fields,
project, migration identity and predecessor receipt hash with an Ed25519
signature. The existing `RolloutManager` and native recovery implementation
remain responsible for admission, legal transitions and source restoration.

## Provision before initializing a rollout

This is an explicit per-project opt-in. Existing projects without an operator
anchor keep the legacy plain-state format. Install a dedicated public key at:

```
PROJECT/.franken-node/keys/migration-rollout.pub
```

Keep its private seed outside the project and all other captured workspaces,
with owner-only permissions. Use a different key from the migration-validation
signer. The already shipped key generator can create the pair; its output path
selects which independently installed authority is being provisioned:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-attest -- keygen \
  --secret-key /private/operator/rollout.seed \
  --public-key /project/.franken-node/keys/migration-rollout.pub
```

Paths are examples; both files must be new and their parent directories must
already exist. Private-key paths must be absolute, normalized, outside the
project, and have no symlink component. The seed must be a regular 32-byte file,
owned by the executing user, with no group/other permissions and no hard links.
Public-key configuration directories and files cannot be links either.

Select that seed explicitly for operations that write a new rollout revision:

```sh
FRANKEN_NODE_ROLLOUT_SIGNING_KEY=/private/operator/rollout.seed \
  franken-node migrate rollout /project --migration-id txn-CHOSEN-ID \
  --action status --json
```

Initialization writes a signed genesis revision. Normal promotion, confidence
observations, rollback intent and recovery completion go through the same
signed store. An unchanged write does not create another revision. A supplied
private key without the independent public anchor is an error, not permission
to install a key or fall back to unsigned storage.

**Do not retrofit an existing unsigned rollout by dropping a public key beside
it.** Signed mode refuses unsigned existing state rather than claiming that
old history was authenticated. Provision before initializing new rollouts;
retain existing legacy state and recovery journals. There is deliberately no
sign-import or implicit history-adoption command.

## Promote with authenticated state and evidence

Initialize the signed state before measuring the candidate. Generate the
signed validation cohort using `migration_validation_attestation.md`; the
captured candidate includes the new state and receipt files. A promotion uses
both independent authorities: the validator attests observations, while the
operator signs the resulting lifecycle decision.

```sh
FRANKEN_NODE_ROLLOUT_SIGNING_KEY=/private/operator/rollout.seed \
FRANKEN_NODE_ROLLOUT_EXPECTED_HEAD_SHA256="$TRUSTED_PREVIOUS_HEAD" \
  franken-node migrate rollout /project --migration-id txn-CHOSEN-ID \
  --action promote --lockstep-report /private/evidence/cohort.signed.json --json
```

The optional checkpoint must be the exact SHA-256 of the signed state envelope
retained through an independently trusted channel. Do not learn it from a
possibly replayed file and then present that same value as independent proof.
A mismatch fails under the rollout lock before a transition or restoration.
After the initial check, the store tracks its own committed head so a two-write
rollback (intent followed by completion) advances normally. A changed head
between load and write is rejected, even when the replacement is itself signed.

Retain the newly published head hash outside the project after each successful
operation. If an I/O error makes the outcome uncertain, inspect and verify the
actual durable head before deciding what to retry; do not blindly replace the
trusted checkpoint. The checkpoint detects a different revision, not wall-clock
freshness. Without an independent checkpoint, an authentic older history can
still be replayed by an actor controlling local files.

Existing `status --json` returns the usual decoded rollout report. Inspection
of an initialized signed state requires only the public anchor, not the seed:

```sh
franken-node migrate rollout /project --migration-id txn-CHOSEN-ID --action status --json
```

Missing, changed or malformed authority; invalid signatures; unsigned
substitutions; and transplanted project/migration contexts fail closed.
`--force` does not bypass storage authentication or authorize unsigned writes.
Removing the public key does not turn an existing signed envelope into legacy
state. A party that can replace both the trust configuration and state remains
an authority; this is not protection from a compromised host administrator.

## Durable intent, immutable receipts, and retry

The current state pathname remains:

```
.franken-node/state/rollout/MIGRATION-ID.json
```

In opted-in projects it contains the signed envelope, not bare `RolloutState`.
The manager authenticates and unwraps it before interpreting lifecycle fields.
All signed revisions are retained beside it as `.signed-SHA256.json` files.
Each includes the exact predecessor envelope hash. Existing receipts are never
overwritten; a conflict or corrupt partial file blocks publication and remains
available for diagnosis.

Publication holds the existing project-wide lock. It synchronizes the signed
receipt before writing, synchronizing and atomically replacing the current
head, followed by directory synchronization. A crash after receipt retention
but before head replacement can leave an orphan receipt. It is not a committed
transition. The authoritative head stays unchanged, and retry can reuse an
identical retained receipt without overwriting it.

Rollback persists a signed `aborted` / `failed` intent before restoring sources.
Completion becomes `rolled_back` only after the native recovery protocol has
succeeded and the completion revision is signed and durably published. The
native transaction still checks its pinned journal, preflights sources/backups,
preserves conflicts and recognizes already completed restoration.

If the private key is unavailable, a new recovery intent cannot be written and
restoration does not start. **An already durable, authenticated recovery intent
remains authorization to resume that exact restoration.** A retry may therefore
restore files without the private key, but cannot sign or claim completion; it
returns an error and leaves the signed pending intent. Once signing authority
is restored, retry records completion using the native idempotency receipt and
does not overwrite later edits. Key loss must never manufacture an unsigned
successful recovery record.

The unsigned `receipt_signature` field inside historical transition events is
still a legacy state digest. The actual digital signature is on the outer
revision envelope, covering those events and all other state fields. This does
not silently relabel the old field as an Ed25519 signature.

## Independently verify an exported history

The read-only verifier does not need the product engine, private key, source
tree or runtime executables. Copy the selected head and its `.signed-*.json`
predecessors to an audit directory, and supply the public key and expected
project/migration identity independently:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-rollout-verify -- /audit/head.json \
  --receipts-dir /audit \
  --public-key "$TRUSTED_OPERATOR_PUBLIC_KEY" \
  --project /project --migration-id txn-CHOSEN-ID \
  --expected-head-sha256 "$TRUSTED_HEAD"
```

The project argument is the exact canonical path signed at the source; it need
not exist on the verifier host. The tool validates every signature, content
hash and consecutive revision link back to genesis. It rejects missing or
substituted predecessors, wrong keys, different contexts and a wrong checkpoint.
No project code executes and no input file changes. `--include-state` additionally
prints the authenticated state, which can contain private project metadata.

State bytes remain bounded to 2 MiB; an escaped receipt envelope has a separate
bounded read limit. Full-chain verification permits at most 1,024 revisions and
64 MiB of receipt bytes. These are verifier resource limits, not a claim that
local persistence is an indefinitely growing database service.

The verification summary always reports `execution_performed: false` and
`currentness_proven: false`. `externally_pinned` indicates whether a caller's
checkpoint matched. Authenticity and lineage are not proof of honest controller
execution, a globally latest head, an independent timestamp, test independence,
fleet traffic movement or restoration of external side effects. State/key
rollback together cannot be detected without an independently retained trust
root/checkpoint. Key rotation and recovery from loss of the entire signed
history require an explicit external operator procedure; no automatic trust
replacement is provided here.

## Validation scope

The focused recovery workflow imports the production store/controller modules
and tests signed state tampering, authority changes, key admission, project/ID
substitution, checkpoint replay, archive conflicts and actual subprocess exits.
The subprocess tests exercise real native restoration and distinguish durable
intent from signed completion. The offline operator runs separately so another
workflow failure cannot hide its results. These tests do not establish native
JavaScript compatibility or fleet rollout correctness.
