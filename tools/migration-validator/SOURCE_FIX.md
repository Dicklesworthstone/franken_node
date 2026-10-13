# Inspect and verify a repaired migration project

`franken-migration-fix` checks a proposed source repair against a previously captured, independently pinned migration failure. It complements `franken-migration-suite` (capture/replay/reduction), `franken-migration-apply` (reviewed installation), and the attestation operators. It does not install anything or overwrite the seed capsule.

Build through the repository's approved Rust build environment:

```bash
cargo build --manifest-path tools/migration-validator/Cargo.toml --bin franken-migration-fix
```

## Inspect before approving execution

The same read-only command accepts either capsule schema:

```bash
franken-migration-fix ./failure.json ./repaired-project \
  --expected-sha256 "$TRUSTED_CAPSULE_SHA256" \
  --inspect \
  --out ./repair-inspection.json
```

Use the capsule hash from trusted capture output or another authenticated channel. An unfamiliar capsule's self-declared hash is not authentication. Inspection validates the pinned archive and frozen test contract, captures the proposed repair, and reports its `candidate_input_sha256` plus a source-change summary. It does not resolve Node, Bun or native executables, stage workspaces, or run code. Optional report output is the only write.

`INSPECTED` is not `PASS`, `FIX_VERIFIED`, or source approval. Review the actual application and dependency changes independently, then preserve the inspected candidate hash as `REVIEWED_REPAIR_SHA256`. Do not automatically approve whatever a mutable repair directory contains at execution time. The summary contains at most 64 sorted changes, reports truncation explicitly, and is not a substitute for reviewing all changed source.

`--inspect` conflicts with `--execute`, both runtime selections, and `--expected-candidate-input-sha256`. An inspection report uses schema `franken-node/source-fix-inspection/v1`, `oracle: pair|product`, and `execution_performed: false`. It reveals no source bytes or symlink target text; source paths and content hashes are still sensitive metadata.

## Execute the reviewed repair

Both capsule and repair hashes are required by the CLI. A source substitution, mode change or new file after review is rejected before runtime resolution. The source tree is captured once for execution; the operator never fills in a missing approval hash automatically.

### Pair capsule

```bash
franken-migration-fix ./failure.json ./repaired-project \
  --expected-sha256 "$TRUSTED_CAPSULE_SHA256" \
  --expected-candidate-input-sha256 "$REVIEWED_REPAIR_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --execute \
  --out ./source-fix-report.json
```

### Node/Bun/native capsule

```bash
franken-migration-fix ./product-failure.json ./repaired-project \
  --expected-sha256 "$TRUSTED_CAPSULE_SHA256" \
  --expected-candidate-input-sha256 "$REVIEWED_REPAIR_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --bun-bin /trusted/bin/bun \
  --execute \
  --out ./product-source-fix-report.json
```

A product capsule without `--bun-bin` is rejected, never downgraded to a pair comparison. Node is resolved using the existing absolute-PATH-entry rule. Original reference executable identities must match the capsule; recorded paths and arguments are not execution instructions.

These examples assume the built operator is on PATH. Its default build location is `tools/migration-validator/target/debug/`. `--execute` approves both archived reference code and repaired code. Workspace copies are not an OS sandbox; use trusted projects and appropriate external isolation.

## What changes, and what stays fixed

The archived original tree and seed evidence are not changed. Only the in-memory candidate input is replaced by the repair capture. Supporting sources and modules may be added, removed or edited within existing snapshot limits. Comparison continues to use the entire recorded suite, not a selected passing subset.

Selected test entrypoints must retain their archived **candidate** bytes, regular-file kind and permission modes. The complete `.franken-node/migration-tests.json` file is frozen too, including its bytes and permissions. The original reference's harness may have different source spelling after an earlier measured migration; that is not permission to alter the archived candidate's harness during a repair. To fix behavior, change application code behind a stable harness. A broken assertion or test itself requires a newly reviewed capture, not a claim that the old test now passes.

The shared inventory admission also preserves per-test working directories, application arguments, environment overrides, stdin transport and bytes, concurrency, and stdout/stderr/file golden fixture bytes. A repair cannot omit a failing counterpart or substitute expected output. `protected_paths` lists the byte-and-mode-frozen harnesses and manifest; other declared request/oracle bytes remain protected by the shared inventory contract.

This does not identify every transitive test helper, package configuration or implicit input as a frozen oracle. Such supporting changes are included in the repair hash and change summary and must be reviewed independently. Passing proves recorded observations, not correctness on arbitrary inputs or safety of arbitrary dependencies.

Every recorded reference observation must remain unchanged, including persistent workspace effects when captured. For product capsules this applies independently to BOTH Node and Bun. All candidate cases must pass, including previously passing siblings. A reference disagreement, failed reference, or captured PASS is not a usable source-fix seed.

The native executable may also change; `native_runtime_changed` reports this explicitly. A combined source/runtime repair does not prove that source edits alone caused an improvement. The existing validator-identity requirement remains enforced: keep compatible capture/replay builds; inspection does not waive implementation compatibility.

## Results and storage

Execution reports use `franken-node/source-fix-verification/v1`. `seed_content_sha256` identifies the unmodified capsule. `input_sha256`, `captured_candidate_input_sha256`, and `candidate_input_sha256` identify the archived original, archived candidate, and measured repair. `replay` retains the complete pair/product result without discarding any reference. `candidate_input_approved` records a matching caller-supplied repair hash before runtime lookup; it is not a successful validation verdict. `candidate_source_unchanged` records a post-execution recapture matching the measured repair.

Both report forms include `source_changes`: aggregate added/removed/modified path counts, up to 64 details, and a digest over **every** sorted change. Details contain entry kind, mode, byte length, and content/target digest, not raw bytes. Directory additions/removals count as paths too. The digest uses the domain `franken-node/source-fix-changes/v1` followed by NUL, then each compact serialized `SourceChange` preceded by its u64 little-endian encoded byte length. A truncated detail prefix cannot conceal changes from the full digest or candidate input pin.

`FIX_VERIFIED` requires a complete passing comparison, unchanged references and a successful source recheck. `FIX_NOT_VERIFIED` preserves a failing comparison. `REFERENCE_DRIFT` means reference observations changed. `SOURCE_DRIFT` means the captured repair passed but its live tree changed; the nested replay still retains the earlier captured result. `ERROR` covers incomplete measurement, failed rechecks and publication errors. Negative replay results remain negative when the source recheck also fails; `source_recheck_error` records that additional problem.

CLI exit 0 means either **inspection only** (`INSPECTED`, `execution_performed=false`) or complete `FIX_VERIFIED` with both `candidate_input_approved=true` and `candidate_source_unchanged=true`. Exit 1 means `FIX_NOT_VERIFIED`; exit 2 means drift, invalid inputs, incomplete checks or publication failure. Inspect the verdict, not only the exit code. A nested PASS cannot override a top-level failure.

The seed and any output must be outside the repair tree. Report parents must exist; report paths must be new. Files are created with mode 0600. Publication errors preserve completed evidence on stdout and can leave a partial new file. Existing output is never overwritten. Repair roots cannot be symlinks; runtime paths must resolve outside them.

A post-execution recheck is not a filesystem lock or permission to install. Use the separate reviewed-installation workflow for writes or fleet operations. Captures exclude `.git` as specified by the shared snapshot implementation. Ambient environment, clocks, external services and transient effects are not reconstructed. `environment_reproduced` and `release_certification` remain false.

## Library and regression commands

`source_fix::inspect` provides read-only inspection. `source_fix::verify_reviewed` checks both pins before runtime lookup and returns explicit approval metadata. The capture-now `source_fix::verify` API remains available to trusted library callers that already approved execution; its reports have `candidate_input_approved=false`. The CLI uses only the reviewed API for execution.

Run through the approved Rust execution path:

```bash
cargo test --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-fix source_fix::tests -- --test-threads=2
cargo test --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-fix cli_tests -- --test-threads=2
cargo clippy --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-fix --all-targets -- -D warnings
```

The tests include real Node/Node orchestration plus explicitly named `/bin/true`, `/bin/false` and shell observations for role/refusal checks. These are not positive Franken or Bun compatibility evidence. Run the Rust suites and genuine native qualification separately; JavaScript fixture checks alone do not compile or execute the Rust implementation.
