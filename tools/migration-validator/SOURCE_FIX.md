# Verify a repaired migration project

`franken-migration-fix` checks a proposed source repair against a previously captured, independently pinned migration failure. It complements `franken-migration-suite` (capture/replay/reduction), `franken-migration-apply` (reviewed installation), and the attestation operators. It does not install anything or overwrite the seed capsule.

Build the operator through the repository's approved Rust build environment:

```bash
cargo build --manifest-path tools/migration-validator/Cargo.toml --bin franken-migration-fix
```

## Pair capsule

```bash
franken-migration-fix ./failure.json ./repaired-project \
  --expected-sha256 "$TRUSTED_CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --execute \
  --out ./source-fix-report.json
```

## Node/Bun/native capsule

```bash
franken-migration-fix ./product-failure.json ./repaired-project \
  --expected-sha256 "$TRUSTED_CAPSULE_SHA256" \
  --native-bin /trusted/bin/franken-node \
  --bun-bin /trusted/bin/bun \
  --execute \
  --out ./product-source-fix-report.json
```

Use the content hash from trusted capture output or another authenticated channel. Merely reading an unfamiliar capsule's self-declared hash does not authenticate it. A product capsule without `--bun-bin` is rejected, never downgraded to a pair comparison. Node is resolved using the existing absolute-PATH-entry rule. The original reference executable identities must match the capsule; recorded paths and arguments are not execution instructions.

These examples assume the built operator is on PATH. The executable otherwise resides under `tools/migration-validator/target/debug/`. Passing `--execute` approves both the archived reference code and the proposed repaired code. Workspace copies are not an OS sandbox; execute only trusted projects with appropriate external isolation.

## What changes, and what must stay fixed

The repair tree is captured before runtime resolution. The archived original tree is not changed, and the captured candidate is replaced only in the in-memory execution input. Supporting sources and modules may be added, removed, or edited within the existing snapshot limits. The repaired tree must still select exactly the same tests, execution settings and independent oracle data as the original.

The existing shared admission check preserves per-test working directories, application arguments, environment overrides, stdin transport and bytes, concurrency, and stdout/stderr/file golden fixtures. A repair cannot weaken those conditions, omit a failing counterpart, or substitute expected output. Both runtime-comparison modes execute the same production replay/validation code used by ordinary replay.

Every recorded reference observation must remain unchanged, including persistent workspace effects when the capsule measured them. For product capsules this applies independently to BOTH Node and Bun. All repaired-candidate cases must then pass the comparison, including previously passing sibling cases. A reference disagreement or reference failure is not a usable fix-verification seed. Neither is a captured PASS.

The native executable may also be updated. `native_runtime_changed` reports whether its admitted identity/arguments differ from the seed. This is explicit fix verification, not proof that source edits alone caused an improvement when the native runtime also changed.

The validator implementation identity must satisfy the existing replay contract. A capsule produced by an incompatible validator build is rejected; the tool does not silently waive that check. Keep the capture/replay tools from the same compatible build. Inspection and offline export are separate operations and do not establish execution compatibility.

## Results

The JSON schema is `franken-node/source-fix-verification/v1`. Important fields are:

- `seed_content_sha256`: the identity of the UNMODIFIED failure capsule.
- `input_sha256`, `captured_candidate_input_sha256`, `candidate_input_sha256`: archived original, archived candidate, and freshly measured repair identities respectively.
- `replay`: `oracle: pair` or `oracle: product`, with the full existing replay result under `result`; no reference observations are discarded.
- `candidate_source_unchanged`: a post-execution recapture matched the measured repair input hash.

`FIX_VERIFIED` requires complete passing evidence and unchanged references AND a successful unchanged-source recheck. `FIX_NOT_VERIFIED` retains the complete failing comparison. `REFERENCE_DRIFT` means at least one archived reference observation changed. `SOURCE_DRIFT` means the captured repair passed, but the live repair tree changed; its nested replay still preserves the successful measurement of the earlier captured bytes. `ERROR` covers incomplete measurement, failed source rechecks and publication errors. Other negative results remain negative even when a source recheck also fails; `source_recheck_error` preserves that additional failure.

Exit codes are 0 only for a complete `FIX_VERIFIED` result with unchanged source, 1 for `FIX_NOT_VERIFIED`, and 2 for drift, invalid inputs, incomplete checks, or publication failures. Never interpret a nested `PASS` or `FIX_VERIFIED` as success when the top-level result is `SOURCE_DRIFT` or `ERROR`.

The source recheck is not a filesystem lock. It establishes the observed tree identity at that point, not a guarantee against future editing. Use the separate reviewed-installation workflow to install a candidate; source-fix reports themselves do not authorize a write or fleet promotion.

## Storage and limitations

The seed must be outside the repaired tree. The report destination must be new and outside the repair tree (including aliases); its parent must already exist. Reports are created with mode 0600. Publication failure preserves completed evidence on stdout, returns `ERROR`, and can leave an incomplete new output file after an I/O failure. Existing reports are never overwritten. The repair root cannot be a symlink, and each runtime must resolve outside it.

Comparison preserves the capsule's original scope; it does not upgrade a process-only capture to filesystem equivalence. Ambient environment, clocks, external services and transient/external filesystem effects are not reconstructed. `environment_reproduced` and `release_certification` remain false. Passing proves the captured test observations, not arbitrary-program equivalence, native ecosystem qualification, or a release gate.

## Regression commands

Run through the repository's approved Rust execution path:

```bash
cargo test --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-fix source_fix::tests -- --test-threads=2
cargo test --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-fix cli_tests -- --test-threads=2
cargo clippy --manifest-path tools/migration-validator/Cargo.toml \
  --bin franken-migration-fix --all-targets -- -D warnings
```

The source-repair tests execute real Node/Node processes. Deliberately named `/bin/true`, `/bin/false`, and shell observations exercise three-role orchestration and refusal paths, not successful Franken or Bun implementations. Positive native-runtime compatibility must be established separately with the genuine product executable and reference binaries.
