# Authenticated migration-cohort evidence

`franken-migration-attest` signs the production validator's own freshly executed
Node/Bun/Franken project report. There is no command that signs an imported
report or accepts a caller-declared passing result. A signature authenticates
an authorized validator key, not the correctness or independence of runtimes.

## Provision a dedicated validator authority

Keep the private key outside projects and version control. Initialize the
project normally so `.franken-node/keys` exists. Create an external private
key directory accessible only to its owner. Then generate a new dedicated pair:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-attest -- keygen \
  --secret-key /private/validator/migration.seed \
  --public-key /project/.franken-node/keys/migration-validation.pub
```

Both files must be new absolute paths with existing parents. Neither is
replaced. The raw 32-byte seed is owner-only. If publication of the public key
fails, the newly created private key is retained; never silently retry by
replacing it. Key generation requires a cryptographic OS random source.

Install the public key deliberately before measuring the project. Never copy
an envelope's self-declared public key into the trust file as part of admission.
For an existing validator, independently copy only its reviewed 64-character
lowercase hexadecimal public key to the project anchor. A terminal LF or CRLF
is allowed. Linked configuration directories or public-key files are refused.

## Execute, attest, promote

Initialize rollout status before measurement, as described in
`migration_rollout_source_recovery.md`. Then run:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-attest -- run /project \
  --native-bin /installed/franken-node --bun-bin /installed/bun \
  --signing-key /private/validator/migration.seed \
  --out /private/evidence/cohort-canary.signed.json --execute

franken-node migrate rollout /project --migration-id txn-CHOSEN-ID \
  --action promote --lockstep-report /private/evidence/cohort-canary.signed.json --json
```

All illustrated paths must be replaced with real paths. Node must be on an
absolute PATH entry. The three executable hashes must differ. By default the
complete cohort must pass the existing process/output/filesystem checks before
it can be signed. Explicit `--attest-regression` additionally permits a signed
complete native FAIL as described below; it never converts that result to PASS.
No unsigned-success fallback or automatic key provisioning occurs. An
insufficient sample count may be attested truthfully, but still fails the
rollout confidence gate unless explicitly overridden.

Private key admission, the independent public-key match, execution consent and
output-path checks happen before executing a guest. The key may not reside
inside the captured project, be a symlink or hard link, or have group/other
permissions. Report publication is create-only, outside the project, and uses
a private temporary file, file fsync, no-clobber publication and directory
fsync. The producer rechecks the captured source tree and public key before
signing/publishing. Existing reports are never overwritten.

## Attest an original-to-candidate migration

Use `--migrated-project` to compare Node and Bun on the original tree with
native Franken on an independently prepared candidate. This is not a same-tree
rerun that loses the original behavior. Both trees are captured and their exact
approved snapshots are executed through the existing one-use `ApprovedInputs`
API. No rewrite or installation is performed by the attestation operator.

Provision the validation public key in the **candidate**, and initialize that
candidate's rollout status before reviewing the inputs. Keep the original and
candidate in separate, non-nested directories. Inspect each without execution:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-suite -- /original --list-tests
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-suite -- /candidate --list-tests
```

Review each captured inventory and its input SHA-256 independently. Set
`ORIGINAL_SHA256` and `CANDIDATE_SHA256` to those reviewed 64-character hashes,
then execute:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-attest -- run /original \
  --migrated-project /candidate \
  --expected-input-sha256 "$ORIGINAL_SHA256" \
  --expected-candidate-input-sha256 "$CANDIDATE_SHA256" \
  --native-bin /installed/franken-node --bun-bin /installed/bun \
  --signing-key /private/validator/migration.seed \
  --out /private/evidence/migration-canary.signed.json --execute

franken-node migrate rollout /candidate --migration-id txn-CHOSEN-ID \
  --action promote --lockstep-report /private/evidence/migration-canary.signed.json --json
```

Cross-tree signing requires **both** reviewed hashes, including when the paths
resolve to the same directory. Omitting one, swapping roles, stale captures,
changed test selection, or differing golden expectations refuses execution.
Explicitly reviewed hashes are also supported without `--migrated-project`;
then provide the same hash for both roles. Without hashes, the original
same-tree mode retains explicit `--execute` approval of the current capture.

The candidate's independently installed key authorizes the signer; the
original's key cannot override it. Private seeds, runtime executables and the
signed report must remain outside **both** input trees. The operator verifies
both trees still match the pre-execution hashes before signing and again before
publication. Recapture is a rejection check, never a way to redefine an input
that was already measured. These checks are not a filesystem lock against a
hostile same-user process, nor an atomic snapshot of external effects.

The signed report and the command summary retain separate `input_sha256` and
`candidate_input_sha256` values. Existing rollout admission verifies that the
candidate hash still matches its current project; the original hash is the
signed validator's recorded baseline, not a claim that the original is still
present during promotion. A later rollout transition still requires a new
measurement and newly reviewed candidate hash. Failure never publishes a
passing attestation and never restores or installs either source tree.

## Retain authenticated regression evidence and recover

Add `--attest-regression` to `run` to retain a **complete native FAIL** under the
same signature protocol. This works with either same-tree or reviewed
original/candidate execution; it does not waive `--execute`, paired hash
approvals, original/candidate inventory matching, trust configuration or any
existing execution budget. Use a new output path outside both projects.

For example, after initializing the bound rollout and reviewing both hashes:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-attest -- run /original \
  --migrated-project /candidate \
  --expected-input-sha256 "$ORIGINAL_SHA256" \
  --expected-candidate-input-sha256 "$CANDIDATE_SHA256" \
  --native-bin /installed/franken-node --bun-bin /installed/bun \
  --signing-key /private/validator/migration.seed \
  --out /private/evidence/cohort-regression.signed.json \
  --attest-regression --execute
```

A retained regression prints `verdict: "FAIL"` and `regression_attested: true`
and **exits 1**, even though the signed artifact was published successfully.
Do not interpret file creation as successful validation, use `|| true` to hide
the failure, or chain an expected-failure recovery command with `&&`.
`ERROR`, missing observations, incomplete output, reference failures and
reference disagreement do not produce a signed regression. A normal complete
PASS still follows the unchanged passing-attestation path.

After reviewing the failure, invoke the rollout decision separately:

```sh
franken-node migrate rollout /candidate --migration-id txn-CHOSEN-ID \
  --action promote --lockstep-report /private/evidence/cohort-regression.signed.json --json
```

The default controller authenticates the envelope, captures the current
candidate, requires the exact test inventory and filesystem scope, and
reconstructs each case and the global verdict from all three observations.
Only complete native failures with successful agreeing references can enter
the native recovery path. The promotion command still fails; it records a
durable abort intent and restores only the previously bound transaction.
It does not install, execute or restore any pathname supplied by the report.
The exact signed-envelope digest is retained in recovery history.

A modified input, stale rollout state, changed trust key, invalid signature,
weakened scope, missing case, inconsistent count or an inconclusive result
refuses progression without authorizing source restoration. Insufficient
successful samples also do not authorize rollback. `--force` never turns a
signed FAIL into a promotion and prevents automatic restoration; library
callers can independently disable `auto_rollback_on_failure`. An unbound
rollout records cancellation but explicitly restores no source files.

Conflicts with later user work leave the rollout aborted/failed and retryable;
resolve conflicts explicitly and repeat the rollback action with the same
transaction ID. Completed recovery retries preserve later edits. A supplied
regression is checked even at the Default stage; idempotent stage requests
cannot silently ignore it. Passing no-op requests leave state/history intact.

Unsigned legacy lockstep reports are not negative cohort approvals. Default
policy refuses automatic restoration from them. Library callers selecting
`min_confidence_score = 0.0` explicitly opt into the separately trusted-local,
unquantified legacy protocol, including its unauthenticated recovery evidence.
The normal signed-cohort path does not require that override.

## Wire and trust contract

The versioned JSON envelope contains `schema_version`, `public_key`,
`signature`, and `report_json`. The last field is the exact UTF-8 JSON report
string, not an object reserialized by the verifier. Ed25519 covers the bytes:

```
ASCII("franken-node/migration-validation-attestation/v1") || NUL ||
u64_le(length(report_json_utf8)) || report_json_utf8
```

The envelope is bounded to 16 MiB. Duplicate/unknown/missing envelope fields,
unknown schemas, noncanonical key/signature encodings, weak public keys,
foreign signers and invalid signatures are rejected. Strict Ed25519
verification occurs before any report contents authorize a cohort. Signature
verification does not replace the existing capture, inventory, runtime,
filesystem, numerical-confidence or source-recovery checks.

The trust anchor is local operator-controlled configuration, not remote
identity discovery. A party able to replace that key or steal the secret can
issue new approvals. Guests run with ambient OS authority: this mechanism is
for trusted workloads and is not isolation from hostile same-user processes.
The dedicated key is not passed in guest argv or environment, but filesystem
and process isolation require a separately enforced security boundary.

Signatures authenticate measured-report bytes, not rollout transitions or
traffic routing. Legacy single-entry lockstep reports retain their separately
documented unquantified/trusted-local contract; they are not authenticated by
this cohort feature. The ordinary migration-suite operator remains available
for raw comparison and failure investigation, but raw reports are not signed
cohort approvals. Use a new measurement/report after every rollout transition.
