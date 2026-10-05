# Transaction-bound rollout source recovery and measured admission

Rollout cancellation can restore the actual files from a native migration
rewrite, rather than merely updating rollout JSON. This is opt-in: select the
exact native `txn-...` identifier as `--migration-id`. An ordinary `mig-...`
rollout remains a metadata-only progression and never guesses a transaction.

## Select, inspect, measure, promote, restore

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

Default promotion requires an **authenticated captured three-runtime cohort**,
not an unsigned project report or a single-entry `verify lockstep` report.
Provision the independent `.franken-node/keys/migration-validation.pub` anchor
and external dedicated private key as described in
[migration_validation_attestation.md](migration_validation_attestation.md).
Then generate evidence from the live validator after initializing rollout:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-attest -- run ./project \
  --native-bin /absolute/path/to/franken-node --bun-bin /absolute/path/to/bun \
  --signing-key /absolute/private/validator/migration.seed --execute \
  --out /absolute/path/outside-project/cohort-canary.signed.json

franken-node migrate rollout ./project --migration-id txn-CHOSEN-ID \
  --action promote --lockstep-report /absolute/path/outside-project/cohort-canary.signed.json --json
```

Replace executable and report paths with real absolute paths. Node must also
be available through an absolute PATH directory. Run trusted project code only:
`--execute` approves the existing validator's execution authority, not an OS
sandbox. This command measures the current project under all three runtimes;
its passing result is not a promise that an arbitrary installed engine supports
all selected tests. A failed or inconclusive suite remains a failed admission.

The report must be outside the project. Admission authenticates its exact
payload under the independently installed public key before trusting report
fields. It then reuses the producer's full captured-input digest and exact test
inventory, including dependencies, configuration, fixtures, the public trust
anchor and rollout metadata. Writing evidence into that same tree, changing a
dependency, or changing the test selection invalidates the binding. A successful
promotion changes rollout state, so measure again into a **new report path**
before the next promotion. Reusing a previous report does not accumulate
observations. The count remains the current cohort's count.

Every promotion of a bound rollout also checks that its exact rewrite remains
fully applied. `--force` does not bypass the source-transaction binding and
cannot resurrect an aborted rollout or use promotion as a rollback substitute.
It also cannot bypass signature verification of a supplied cohort. Unsigned,
foreign-signer and tampered cohorts are rejected without source restoration.

Restore through the rollout:

```sh
franken-node migrate rollout ./project --migration-id txn-CHOSEN-ID --action rollback --json
```

Operator-health-triggered automatic rollback in `promote` follows the same
source recovery path. Authenticated, complete current-project native failures
can now use it too. The live signer must be invoked with `--attest-regression`
to retain a signed FAIL; it still exits nonzero. Supply that report explicitly
to the rollout decision in a separate command. The controller authenticates
first, then reconstructs every case from the three process/filesystem
observations against the current candidate and exact captured test inventory.
Successful agreeing references are mandatory. The signed-envelope digest is
retained in recovery history; no report-supplied path selects what is restored.

An incomplete, malformed, stale or inconclusive cohort refuses progression
without authorizing restoration. Insufficient successful samples likewise do
not prove a workload regression. A valid signed native FAIL can abort even a
Default-stage rollout; a repeated stage request must not ignore supplied
negative evidence. A valid passing no-op leaves the recorded state unchanged.
`--force` or explicitly disabled automatic recovery refuses the failed
promotion without automatic restoration. This is not a background monitor.
Restoration failures are propagated, not silently discarded.

Legacy unsigned lockstep failures no longer authorize automatic recovery under
default policy. Only the explicit library `min_confidence_score = 0.0` policy
opts into the unquantified trusted-local legacy protocol, including its
unauthenticated regression classification. Direct operator rollback remains
available independently of validation evidence. See the attestation guide for
same-tree and reviewed original/candidate examples and exit-code semantics.

## What the confidence fields mean

`confidence_score` is retained as a separate **operator health ceiling**, not a
measured success probability. It starts at 1.0, meaning no operator health veto
has been applied. A new rollout has no `validation_confidence`. The CLI renders
that distinction explicitly rather than presenting the default ceiling as a
measured confidence claim.

An admitted cohort adds `validation_confidence` to state and JSON reports:

```json
{
  "schema_version": "franken-node/rollout-cohort-confidence/v1",
  "evidence_sha256": "SHA-256 of the complete authenticated envelope",
  "candidate_input_sha256": "64 lowercase hexadecimal characters",
  "total_tests": 40,
  "matched_tests": 40,
  "observed_match_rate": 1.0,
  "wilson_lower_95": 0.912378398802713,
  "wilson_upper_95": 1.0,
  "independent_sampling_verified": false
}
```

The numerical values above illustrate 40/40 matches, not a measured project.
One selected test is one observation; stdout, stderr, filesystem channels and
runtime roles are not additional samples. The product oracle's existing
admission code rechecks every successful process, all three observations,
filesystem scope, the exact inventory and summary counts. Missing cases,
skips, reference disagreement, errors, weaker exclusions, repeated cases and
aliased runtime executable hashes are refused. Extra caller-declared confidence
or sample-count fields are not used to compute the estimate.

The default threshold is 0.90 for **both** the operator health ceiling and the
conditional two-sided 95% Wilson interval's lower endpoint. One all-pass test
has a lower endpoint of approximately 0.20655, not 1.0. Under that calculation,
34/34 is below 0.90 and 35/35 is above it; 72/72 is below 0.95 and 73/73 is above
it. The implementation uses z = 1.959963984540054 and the Wilson score formula
(NIST Dataplot reference: https://www.itl.nist.gov/div898/software/dataplot/refman2/auxillar/wilson.htm).

**Statistical limitation:** this is a conditional binomial model, not proof
that curated deterministic tests are independent or representative. Different
filenames do not establish independent sampling. No production compromise
probability, unseen-code coverage, cohort independence, or 3x migration-quality
claim follows from this interval. `independent_sampling_verified` is always
false. The score is an explicit sample-size-sensitive admission policy, not a
replacement for choosing a meaningful test cohort.

A valid but too-small cohort leaves rollout state and sources unchanged, even
when automatic rollback is enabled. `--force` explicitly waives the admission
threshold while retaining the actual low measured bound in the report; it does
not turn it into 100% confidence. Forced progression without a report clears
both verification and the cohort record. Invalid supplied reports still fail
when forced. Library callers can explicitly set `min_confidence_score = 0.0`
to use legacy single-entry evidence without quantified admission. That path
records no measured cohort; it does not reclassify old checks as samples.

Confidence metadata is included in the existing state digest and is checked
for finite, bounded, mathematically consistent values when loaded. Public
observation updates cannot replace it. Beginning rollback clears the admitted
cohort, because the restored tree is not the tree it measured.

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
restoration and captured-cohort admission are Linux-only; other platforms
refuse unsupported operations instead of pretending that they happened.

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
side effects. Rollout stages remain local control state. Cohort signatures
now authenticate an independently configured validator key; key custody,
local trust configuration and the validator's honesty remain assumptions.
Executable hashes do not prove runtime brands. Journals and state pins are
still trusted local metadata, not a sandbox or an atomic filesystem snapshot
against a privileged actor. The legacy `receipt_signature` field continues to
contain a digest, not a cryptographic signature. Broader fleet transport,
keyed transitions and the charter's migration-quality KPI remain incomplete.
