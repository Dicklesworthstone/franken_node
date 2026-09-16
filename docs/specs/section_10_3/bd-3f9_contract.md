# bd-3f9: Deterministic Migration Failure Replay Tooling

## Decision Rationale

A failure description is not a replay. Operators need the exact original and rewritten inputs, newly measured execution evidence, and a way to test a candidate fix without changing the reference underneath it.

## Target Scope and Delivery Status

The original program targets remain: capture every migration failure, preserve all inputs/environment/runtime state required for deterministic reproduction, retain replay artifacts, and automatically minimize failing cases.

The delivered standalone `scripts/failure_replay.py` now performs **exact-input re-execution** through `scripts/migration_validation_runner.py`. It captures complete bounded workspace inputs, executes both runtimes, restores those same inputs for replay, and compares newly measured observations. It also supports runtime-bound fix verification and offline capsule inspection.

This is not a claim of fully deterministic runtime replay. Ambient environment, clocks, network services, dynamic libraries, and external script dependencies are not captured. Automatic capture from every Rust CLI failure and automated minimization remain outstanding. The native `incident replay` and `franken-node migrate validate` commands are not changed by this work. Do not close the full bead on this narrower delivery.

## Operator Workflow

Capture and measure the original and rewritten projects:

```bash
python3 scripts/failure_replay.py \
  --capture ./original-project \
  --migrated-project ./rewritten-project \
  --compare-filesystem \
  --out ./failure-capsule.json \
  --json
```

Defaults use `node {test}` and `franken-node run --console-only {test}`. Commands can be supplied explicitly as JSON argv arrays using `--baseline-command` and `--migration-command`; each requires one standalone `{test}` argument. The tool does not run package installation, enable degraded runtime fallback, or mint policy authority.

Capture returns 1 when the measured migration fails **and still writes the capsule**; 0 means the measured migration passed. Infrastructure errors, missing runtimes, no tests, incomplete execution, or invalid inputs return 2 and do not produce a replayable capsule. Existing output paths are refused, not overwritten.

Inspect a capsule without invoking or even resolving its runtimes:

```bash
python3 scripts/failure_replay.py --inspect ./failure-capsule.json --json
```

Re-execute trusted captured code, supplying the content hash obtained from an independent trusted channel:

```bash
python3 scripts/failure_replay.py \
  --replay ./failure-capsule.json --execute \
  --expected-sha256 "$CAPSULE_SHA256" \
  --out ./replay-result.json --json
```

Ordinary replay requires matching direct executable bytes, arguments, both validator scripts, and Python executable bytes. Retain the original validator/runtime revisions. A byte-identical executable can relocate; changing an argument or binary is not silently treated as the same run. Commands in the capsule are diagnostic data, never executable instructions. Supply any non-default commands again from your trusted local configuration.

Test an updated candidate runtime against the captured failing case set:

```bash
python3 scripts/failure_replay.py \
  --replay ./failure-capsule.json --execute --verify-fix \
  --expected-sha256 "$CAPSULE_SHA256" \
  --migration-command '["/path/to/fixed/franken-node","run","--console-only","{test}"]' \
  --out ./fix-result.json --json
```

Fix verification permits the migration executable/arguments to change, but not the baseline or validators. The original reference runs must have exited successfully with complete output. Every newly measured reference observation must still match its original observation, and every captured migration case must now pass. If both current runtimes agree only because the reference drifted, the result is `REFERENCE_DRIFT`, not a verified fix. `FIX_VERIFIED` covers these captured cases only; it is not a general compatibility or release certificate.

## Capsule and Observation Contract

Schema: `migration-failure-replay-v1`.

- `snapshots` contains baseline and migration manifests with canonical relative paths, file/directory/link kinds, ordinary permission modes, content hashes, and contained link targets. Identical source roots are captured once. Both trees are captured before any guest execution.
- `blobs` stores deduplicated base64-encoded file bytes addressed by full SHA-256. Dependencies and configuration are included; `.git` is excluded.
- `expected` contains the actual measured case identities, verdicts, divergence channels, per-leg stdout/stderr digests and counts, exit/termination outcomes, and optional persistent filesystem-delta digests. Wall-clock timestamps and elapsed times are not replay-equivalence inputs.
- `runtime_bindings` binds direct executable contents and argument arrays, the replay and validation scripts, and the Python executable. Fingerprints are checked before and after runs. This is not a whole executable-image binding: shared libraries, modules outside the snapshot, and ambient environment remain external.
- `options` records bounded execution/comparison settings. Replay uses these recorded settings; timeout and filesystem capture switches on the CLI configure capture, not a replay-policy override.
- `content_sha256` is a domain-separated hash over canonical capsule contents excluding the hash and derived `replay_id` fields. `replay_id` includes the complete content hash.

Result schema: `migration-replay-result-v1`. It includes newly executed validation evidence, original/current validation verdicts, runtime bindings, mismatched tests, and fix-mode reference-drift details. `environment_reproduced` and `release_certification` remain false.

## Verdicts and Exit Codes

| Mode | Result | Exit | Meaning |
|---|---|---:|---|
| Inspect | `INTEGRITY_VALID` | 0 | Structure and checksums valid; no code executed |
| Replay | `REPRODUCED` | 0 | Newly observed behavior equals the recorded observation; the migration may still be failing |
| Replay | `DIVERGED` | 1 | Complete execution differs from the recorded observation |
| Fix verification | `FIX_VERIFIED` | 0 | Unchanged reference evidence and all captured cases now pass |
| Fix verification | `FIX_NOT_VERIFIED` | 1 | At least one captured case still fails |
| Fix verification | `REFERENCE_DRIFT` | 2 | Reference evidence changed, so a fix cannot be established |
| Any | `ERROR` | 2 | Invalid input, provenance mismatch, unavailable runtime, incomplete run, or other infrastructure failure |

Diagnostic `capture_failure` notes remain supported as non-executable descriptions. They have unique IDs, safe create-only persistence, and no invented `franken-node --replay` command. They cannot be passed off as executable capsules.

## Safety and Resource Boundaries

Capsules can contain `.env` files, private keys, source code and command arguments. Store and share them as sensitive material. Files are created with mode 0600 and fsynced; captures never overwrite existing files or follow an existing output symlink. Summaries do not dump captured file bytes or raw guest output. Inspection is safe from guest-code execution, not a statement that the contents are public.

SHA-256 checksums are not signatures. A malicious editor can recompute an unpinned checksum. Use an independently trusted content hash for artifact identity; do not describe checksum-only inspection as authenticated provenance.

Manifest validation finishes before staging or execution: reject unsafe paths, undeclared/file/link parents, dangling or escaping links, cycles, duplicate paths, unexpected fields, missing/unreferenced blobs, invalid permissions, invalid encodings, and hash mismatches. JSON loading rejects duplicate keys and nonfinite constants. Input files must be bounded regular files, not symlinks or FIFOs.

Bounds: 128 MiB serialized capsule, 64 MiB combined expanded file bytes, 8 MiB manifest metadata, 50,000 entries per workspace, 1,024 measured cases, 4 KiB paths/link targets, bounded link resolution, and 512 MiB per directly fingerprinted executable/validator file. The existing runner provides subprocess deadlines, output caps, per-case workspaces and POSIX process-group cleanup. Capture and execution share a deadline; imported runner capture also retains its own file limits.

Execute only trusted projects. Temporary workspace copies are not an OS sandbox; absolute paths, ambient credentials, network access, detached descendants and concurrent host filesystem mutation need independent containment. Restored input digests are rechecked before execution; sequential source capture and before/after runtime fingerprinting are not atomic snapshots or protection against every active swap-and-restore race.

## Verification

```bash
python3 -m unittest discover -s tests -p test_check_failure_replay.py -v
python3 scripts/failure_replay.py --self-test --json
python3 scripts/check_failure_replay.py --json
```

The regression suite launches real Node processes for capture, replay, candidate changes, file effects, relocation and drift checks. The self-test executes explicit Python commands. These tests validate the orchestration mechanism; they do not establish native Franken compatibility. Tampered expected output is re-executed and produces `DIVERGED`, preventing a self-comparison from masquerading as replay.

## References

- [bd-2st_contract.md](bd-2st_contract.md) — Validation Runner
- [MINIMIZED_FIXTURE_SPEC.md](../../MINIMIZED_FIXTURE_SPEC.md) — Remaining minimization program
