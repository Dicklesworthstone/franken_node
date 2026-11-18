# Claims Registry

All external product claims about franken_node must be registered here with
links to verifier artifacts. Per the [Product Charter §4](PRODUCT_CHARTER.md),
**claims without evidence are not claims**. An entry with `Status: pending`
makes the gap *visible*; that is preferable to leaving the claim entirely
unregistered.

This registry was backfilled on **2026-05-20** during the reality-check bridge
plan. Each entry lists the claim verbatim from the README and the verifier
artifact / verification command that backs (or will back) it. Pending entries
are explicit signals that the claim is real today only at the
*implementation* level — the headline number, signed artifact, or repro
script that an outside auditor would consume has not yet been published.

## Format

Each claim entry uses this structure:

```
### CLAIM-<ID>: <Short Title>
- **Category**: compatibility | security | performance | resilience | migration | operability | verification
- **Source**: README.md L<NN>, AGENTS.md §X, etc.
- **Claim**: <Exact claim text>
- **Evidence artifact**: <path(s) under artifacts/ or docs/specs/>
- **Verification command**: <command an outside auditor can run>
- **Last verified**: <ISO 8601 timestamp>
- **Status**: verified | pending | stale
- **Notes**: optional caveats, links to follow-up beads, etc.
```

## Registered Claims

### CLAIM-001: Targeted Node/Bun compatibility ≥95%

- **Category**: compatibility
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 1); README.md "Comparison" L221+
- **Claim**: franken-node achieves ≥95% pass rate on a targeted compatibility
  corpus measured by the L1 lockstep oracle against Node and Bun.
- **Evidence artifact**: `artifacts/compat/corpus_pass.json` (bound to
  `artifacts/13/compatibility_corpus_results.json`)
- **Verification command**:
  `python3 scripts/check_compatibility_corpus_pass_gate.py --json`
- **Last verified**: 2026-11-18T17:12:00Z (measured triad artifact regenerated
  2026-11-18T17:10:22Z at commit 586f842e2, franken_engine 61685ec62)
- **Status**: pending (measured RED on core band 98.03% < 99.00%: overall
  observed_pct=97.32, required=95.0; 545/560; 16/16 families >= 80.0%;
  ifc_refusals=0; child_process=30/30; tls=40/40)
- **Notes**: Live triad `lockstep-oracle-run` regenerated 2026-11-18T17:10:22Z
  on clean commit `586f842e2` (`franken_engine` `61685ec62`, `--release` binary
  `sha256:84381b79c79bec8ea5a354e63e697eab81e47f9e5c1aa955967ab7f4deb0c556`,
  `node v26.3.0`, `bun 1.4.4`, `result_digest`
  `sha256:13d09f2a39ca3bd267db4485621e6086d7ef9754638f2f944a2d72bcc098b29b`):
  545/560 (`97.32%`), 15 failed, 0 errored, 0 IFC lowering refusals (down from
  97 in `bd-kx70h`). 11 of 16 API families score 100.00% (`buffer`,
  `child_process`, `events`, `fs`, `http`, `os`, `path`, `querystring`,
  `timers`, `tls`, `zlib`), and all 5 remaining families exceed the 80.00%
  per-family floor (`stream` 98.46%, `net` 97.50%, `url` 96.00%, `cluster`
  85.00%, `crypto` 80.00%). Bands measure `edge` 56/56 (`100.00% >= 90.0%`),
  `high-value` 240/250 (`96.00% >= 95.0%`), and `core` 249/254 (`98.03% < 99.0%`).
  `artifacts/compat/corpus_pass.json` remains `RED` and `CLAIM-001` remains
  `pending` until `core` reaches >=99.0% (`bd-28sz`, `bd-bwa93`) and default
  `balanced` profile capability gaps are closed (`bd-reality-20260923-26n9r.12`).

### CLAIM-002: ≥3× migration throughput vs. baseline

- **Category**: migration
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 2)
- **Claim**: franken-node delivers ≥3× migration throughput / confidence vs.
  baseline patterns, measured as time-to-production + confidence score delta.
- **Evidence artifact**:
  `artifacts/migration/throughput_delta.json` +
  `artifacts/migration/throughput_delta_evidence.json` (live, Ed25519-signed,
  census-recomputable)
- **Verification command**:
  `python3 scripts/check_migration_velocity_gate.py --json`; SDK recompute:
  `cargo test -p frankenengine-verifier-sdk --test migration_throughput_recompute`
- **Last verified**: 2026-11-17 (live `target-release` re-measurement at clean commit `dd8d67214`; binary `sha256:1a3fe12895ced80e…` vs live `node v26.3.0` recorded in census)
- **Status**: pending (live gate PASS 22/22 at 3.425x overall, CI95 [2.98x, 3.54x], holdout 3.474x; kept `pending` until producer-distinct crash-recovery verification `bd-reality-20260923-26n9r.37` completes)
- **Notes**: The constructed Feb 2026 report
  (`artifacts/13/migration_velocity_report.json`, fictional
  `cohort-*-001` archetypes, 3.15x) is **not** evidence and the gate rejects
  its ID set (bd-reality-20260820-w0fc6.2). The live gate measures real
  `franken-node migrate audit/rewrite/validate` runs against a frozen cohort
  of checked-in apps plus pinned upstream code, wall-clock vs the checked-in
  manual-baseline codemods (`scripts/migration_baseline/`).
  2026-09-24: an earlier 5.56x ratio came from deleting fsync barriers in
  `rewrite_transaction.rs` (bd-reality-20260923-26n9r.2); restoring serial
  per-file barriers dropped pooled velocity to 1.24x (holdout 0.98x).
  2026-11-17 (`bd-reality-20260923-26n9r.36`): Aether-style two-wave
  group-commit WAL (`PACKED_JOURNAL_VERSION` v6 in
  `crates/franken-node/src/migration/rewrite_transaction.rs`) coalesces staging
  and commit durability barriers without dropping fsyncs. Live `target-release`
  measurement at clean commit `dd8d67214` (binary
  `sha256:1a3fe12895ced80e099f760a0f1242e3a5f4655ea3835fe18f02a4eab166961b`,
  5 fixtures x 5 runs + 1 warmup vs `node v26.3.0` in the same invocation)
  measures pooled median **3.425x** (`34250 bp`, `137ms` baseline vs `40ms`
  tool, bootstrap CI95 `[2.978x, 3.539x]`), holdout `holdout-worker-service`
  **3.474x** (`34737 bp`, `132ms` vs `38ms`), `hardened` **3.618x**, `risky`
  **3.450x**, `rewrite-shell-commonjs` **2.894x**, and `corpus-commander`
  **2.726x**, passing `check_migration_velocity_gate.py` (`22/22`) and
  `migration_throughput_recompute` (`9/9`). Kept `pending` pending independent
  verification in `bd-reality-20260923-26n9r.37`.

### CLAIM-003: ≥10× reduction in successful host compromise vs. baseline

- **Category**: security
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 3); README.md "Why use
  franken-node" L125
- **Claim**: franken-node achieves ≥10× reduction in successful host
  compromise vs. baseline runtimes, measured via adversarial extension
  campaigns on an instrumented test harness.
- **Evidence artifact**: `artifacts/adversarial/compromise_reduction_v2.json`
  (measured), `crates/franken-node/tests/compromise_reduction_baseline_bench.rs`
  (the honest harness), `scripts/check_compromise_reduction_gate.py` (the
  franken-honesty gate)
- **Verification command**:
  `cargo test -p frankenengine-node --features extended-surfaces,test-support
  --test compromise_reduction_baseline_bench
  compromise_reduction_v2_measures_raw_runtime_baseline_against_strict_policy`
  (requires local `node` + `bun`; writes the measured artifact) then
  `python3 scripts/check_compromise_reduction_gate.py`
- **Last verified**: 2026-09-29T00:00:00Z (local measurement snapshot; release gate currently FAIL)
- **Status**: pending (local 2026-09-29 snapshot measured 20.0×, 20/20 contained; `scripts/check_compromise_reduction_gate.py` fails closed with `CURRENT_MEASUREMENT_INPUTS_REQUIRED` / `release_qualified: false` until a fresh signed producer-distinct campaign passes `bd-reality-20260923-26n9r.20` / `.21`)
- **Notes**: Re-measured honestly under bd-reality-20260923-26n9r.3. The
  rewritten harness registers each dependency as **Trusted** (not revoked),
  records a fresh signed revocation frontier so the run reaches execution, and
  runs the entry **file** with a per-case positive control (`FN_CONTROL:<case>`)
  proving guest code ran, plus a genuine host-compromise oracle per vector (a
  file written outside the project root, or bytes delivered to a loopback TCP
  sink the harness owns). Measured 2026-09-29 on a machine with `node` v22.2.0 +
  `bun` 1.4.2: all 20 vectors compromise BOTH raw runtimes (baseline 20/20);
  franken-node strict contains all 20 (franken 0/20) with typed outcomes —
  15 `capability_denied`, 4 `blocked_at_lowering`, 1 `executed_uncompromised` —
  ratio 20.0×, Wilson-95 baseline lower bound 83.9%, franken upper bound 16.1%.
  The gate now REJECTS the pre-2.1.0 tautological artifact (every franken case
  an identical non-zero exit with no typed evidence) and requires each baseline
  runtime to have executed the control and been compromised. CI runs the gate
  (Python) but the bench's baseline leg needs `node`+`bun`, absent on the rch
  workers, so the bench fail-closes to `status: baseline_unavailable` there and
  the committed artifact is the local measurement snapshot.

### CLAIM-004: 100% deterministic replay for high-severity incidents

- **Category**: resilience
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 5); README.md L114
- **Claim**: Every high-severity incident has a full replay bundle
  (`.fnbundle`) such that any operator can replay it byte-for-byte.
- **Evidence artifact**:
  `crates/franken-node/tests/replay_bundle_integrity_conformance.rs`,
  `crates/franken-node/tests/incident_bundle_integrity_conformance.rs`,
  per-incident bundles under `.franken-node/state/incidents/<id>/`
- **Verification command**:
  `franken-node incident bundle --id INC-<n> --verify` then
  `franken-node incident replay --bundle INC-<n>.fnbundle --trusted-public-key <key>`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill —
  conformance harness is real and passes; production data flow is not yet
  externally certified)
- **Status**: verified (conformance level); pending (production audit)
- **Notes**: `tools::replay_bundle` does fsync-backed atomic-rename
  durability; replay is fail-closed without `--trusted-public-key`. The
  conformance harness asserts bit-exact round-trip.

### CLAIM-005: Trust-card primitives are built-in, not external tooling

- **Category**: security
- **Source**: README.md L225 "Comparison" table
- **Claim**: Per-extension trust cards are built into the runtime; Node, Bun,
  and Deno require external tooling.
- **Evidence artifact**: `crates/franken-node/src/supply_chain/trust_card.rs`
  (~6,800 LoC); `trust-card-v1.0` schema; `tests/conformance/` trust-card
  conformance harnesses
- **Verification command**:
  `franken-node trust scan <project> && franken-node trust list --json && franken-node trust card <id>`
- **Last verified**: 2026-05-20T22:00:00Z (manual e2e verified during
  bridge-plan smoke test on `/tmp/franken_smoke_v6/test-app`; `npm:lodash`
  card created, listed, and inspected successfully)
- **Status**: verified
- **Notes**: HMAC-signed snapshots with high-water file; loaded under
  `SnapshotSourceContext::{TrustedFile, UntrustedNetwork}`. Camouflage
  assessment + reputation trend tracking present.

### CLAIM-006: Revocation-aware execution gates fail closed

- **Category**: security
- **Source**: README.md L226 "Comparison" table; L130 "Why use" table; L1158+
- **Claim**: Risky and dangerous actions consult fresh trust state before
  executing; `now >= expires_at` fail-closed at the boundary so clock skew
  never produces a false "fresh" answer.
- **Evidence artifact**: `crates/franken-node/src/security/revocation_freshness.rs`
  (`registry_revocation_freshness_denial`);
  `crates/franken-node/src/supply_chain/trust_card_registry_store.rs`
  (`record_revocation_frontier`); `crates/franken-node/tests/remotecap_cli_e2e.rs`
  (frontier-gated issuance tests)
- **Verification command**:
  `cargo test -p frankenengine-node --features test-support --test remotecap_cli_e2e --test revocation_freshness_regressions`
- **Last verified**: 2026-09-24 (live, release build of 57d978f0e)
- **Status**: verified live for `run` preflight, the execution-time recheck
  and `remotecap issue`; pending (signed external attestation)
- **Notes**: Until 2026-09-23 the gate was dead on default installs: it read
  the mtime of a legacy `.json` snapshot that `init` never writes, and file
  mtimes cannot witness freshness anyway (opening the fsqlite store rewrites
  it). The frontier is now data: `registry_meta.revocation_frontier_epoch_secs`,
  written only by `trust sync --force` with zero network errors. Live run on
  2026-09-24:
  - fresh frontier: strict passes;
  - 498 s later: strict blocked with `revocation_stale`
    ("age 498s > max 300s"), while balanced (3600 s) and legacy-risky pass;
  - a resync with a network error did not advance the frontier;
  - a clean resync restored strict.
  `remotecap issue` had gated on the mtime of its own authoritative
  revoked-token file (passing before the first revoke, then denying every
  issue 5 minutes after one); it now requires a frontier within 300 s.
  Owner decision (2026-09-24): only strict refuses a stale or missing
  frontier; balanced admits with a preflight warning, so the default profile
  keeps working offline.

### CLAIM-007: Counterfactual policy simulation

- **Category**: resilience
- **Source**: README.md "Why use" L131
- **Claim**: `incident counterfactual --policy strict` re-executes the same
  trace under a different policy profile and emits a reproducible diff of
  decisions, blocked actions, and evidence.
- **Evidence artifact**: `crates/franken-node/src/replay/time_travel_engine.rs`,
  `crates/franken-node/src/tools/counterfactual_replay.rs`,
  `crates/franken-node/tests/incident_replay_counterfactual_cli_e2e.rs`
- **Verification command**:
  `franken-node incident counterfactual --bundle <b> --trusted-public-key <k> --policy strict --json`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: verified (CLI present; e2e test present); pending (signed
  cross-policy diff artifact)
- **Notes**: Schema pinned to
  `franken-node/incident-counterfactual-report/v2`. v2 adds an `executor`
  discriminator (`synthetic` | `production`) — bound into the
  `counterfactual_digest` preimage — so consumers can tell whether the diff came
  from the sandboxed risk-score model or the runtime's real policy engine
  (bd-5r99w.4).

### CLAIM-008: Compatibility lockstep oracle across Node, Bun, franken-engine

- **Category**: compatibility
- **Source**: README.md L132 "Why use"; docs/L1_LOCKSTEP_RUNNER.md
- **Claim**: N-version execution across Node, Bun, and franken-engine with
  signed divergence receipts when behavior diverges.
- **Evidence artifact**: `crates/franken-node/src/runtime/lockstep_harness.rs`,
  `crates/franken-node/src/api/compat_gate.rs`,
  `crates/franken-node/tests/compat_lockstep_oracle_conformance.rs` (see `.github/workflows/lockstep-runner-release-gate.yml`)
- **Verification command**:
  `franken-node verify lockstep <project> --runtimes node,bun,franken-node --emit-fixtures`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: pending — handler is implemented but lockstep requires `node`
  and `bun` binaries on PATH at the verifier's machine; a published signed
  divergence-receipt corpus has not been emitted.

### CLAIM-009: Signed extension registry with Ed25519 + provenance

- **Category**: security
- **Source**: README.md L233 "Comparison"; L1008 "Trust-Native Primitives"
- **Claim**: `registry publish` requires `--version` and `--signing-key`
  (Ed25519); admission enforces signature + provenance + `minimum_assurance_level`.
- **Evidence artifact**: `crates/franken-node/src/registry/`,
  `crates/franken-node/src/extensions/artifact_contract.rs`,
  `crates/franken-node/tests/registry_cli_wire_conformance.rs`
- **Verification command**:
  `franken-node registry publish ./dist --version 1.0.0 --signing-key <k> --json && franken-node registry verify npm:@example/plugin`
- **Last verified**: 2026-05-20T22:00:00Z (CLI panic fixed in bridge plan;
  `registry publish --help` now functional)
- **Status**: verified
- **Notes**: Pre-bridge-plan, `registry publish` panicked with
  `clap` argument-name collision (`version` conflicted with auto `--version`).
  Fixed via `#[command(disable_version_flag = true)]` in `cli.rs:1588`. A new
  integration test
  (`tests/cli_arg_validation.rs::cli_structure_passes_clap_debug_assertions`)
  exercises `Cli::command().debug_assert()` and would have caught this
  regression.

### CLAIM-010: Threshold k-of-n Ed25519 verification with cached keys

- **Category**: security
- **Source**: README.md L1010 "Trust-Native Primitives"; L1175+ "How threshold
  signatures work"
- **Claim**: k-of-n quorum verification with domain-separated, length-prefixed
  preimage; constant-time decode + verify per signer; cached signer-set
  pre-decode for repeated verifications of the same quorum.
- **Evidence artifact**: `crates/franken-node/src/security/threshold_sig.rs`,
  `crates/franken-node/benches/threshold_sig_verify_bench.rs`,
  `tests/security/threshold_signature_verification.rs`
- **Verification command**:
  `cargo bench -p frankenengine-node --bench threshold_sig_verify_bench`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: verified
- **Notes**: 2,584-line module; CrimsonCrane audit on 2026-04-19 found zero
  defects (see memory `security_audit_threshold_sig_2026_04_19.md`).

### CLAIM-011: Verifier SDK runs outside the producing runtime

- **Category**: verification
- **Source**: README.md L120 "TL/DR"; L2792 "Verifier SDK"
- **Claim**: `frankenengine-verifier-sdk` (at `sdk/verifier/`) re-implements
  the verification side of the protocol so an auditor does not need to depend
  on the main `frankenengine-node` crate.
- **Evidence artifact**: `sdk/verifier/src/lib.rs`;
  `sdk/verifier/src/incident_bundle.rs` (independent verification of CLI
  `.fnbundle` output under a verifier-supplied Ed25519 anchor);
  `sdk/verifier/tests/cli_incident_bundle.rs` (a real CLI-produced bundle,
  RFC 8032 TEST 1 anchor, tamper/reseal/foreign-signer negatives);
  `tests/conformance/verifier_sdk_capsule_replay.rs`;
  `tests/conformance/verifier_session_monotonic.rs`
- **Verification command**: `cargo test -p frankenengine-verifier-sdk`;
  `python3 scripts/check_verifier_sdk_independence.py` (stages sparse standalone
  tree in `TemporaryDirectory` without root `Cargo.toml` or `crates/` and runs
  offline `cargo metadata` graph exclusion); standalone CI proof
  `.github/workflows/verifier-sdk-standalone.yml` (sparse checkout of
  `sdk/verifier/` + committed evidence only; `cargo tree` must not reach any
  franken-node crate; stable toolchain)
- **Last verified**: 2026-11-12 (standalone sparse tree without the workspace:
  full SDK suite + TOML/cargo-metadata graph gate green, zero franken-node or
  franken-engine crates in the dependency graph)
- **Status**: verified
- **Notes**: `sdk/verifier/Cargo.toml` no longer inherits workspace fields, so
  it builds from its own directory. Before 7e97be752 the SDK could not parse CLI incident bundles
  (`missing field artifact_path`): the SDK `bundle` module verifies a
  different, SDK-native format whose built-in "signature" check was an
  unkeyed digest; schema `vsdk-replay-bundle-v2.0` removed that field
  (bd-reality-20260923-26n9r.7), leaving `integrity_hash` for integrity and
  the detached Ed25519 `verify_signed_bundle` for authenticity.

### CLAIM-012: `#![forbid(unsafe_code)]` in lib.rs and main.rs

- **Category**: security
- **Source**: README.md L141, L2315; AGENTS.md §"Toolchain"
- **Claim**: No `unsafe` blocks anywhere in the `frankenengine-node` crate.
- **Evidence artifact**: `crates/franken-node/src/lib.rs:1`,
  `crates/franken-node/src/main.rs:1`
- **Verification command**:
  `grep '#!\[forbid(unsafe_code)\]' crates/franken-node/src/{lib,main}.rs`
- **Last verified**: 2026-05-20T22:30:00Z (build-break bridge-plan fix
  removed redundant `unsafe impl Send/Sync` blocks that another agent had
  introduced into `crypto/schemes.rs`, restoring conformance to this
  invariant)
- **Status**: verified
- **Notes**: The auto-derived `Send + Sync` on the wrapper structs is
  sufficient (their inner `ed25519_dalek::SigningKey` / `VerifyingKey` are
  themselves `Send + Sync` in dalek 2.x).

### CLAIM-013: Constant-time comparisons on every signature/hash/MAC

- **Category**: security
- **Source**: README.md L1612 "Threat Model" (timing side-channel row);
  L2316
- **Claim**: `security::constant_time::{ct_eq, ct_eq_bytes}` (backed by
  `subtle`) wraps every signature, hash, MAC, content-hash, trace-id, and
  action-id comparison.
- **Evidence artifact**: `crates/franken-node/src/security/constant_time.rs`
- **Verification command**:
  `cargo fuzz run fuzz_constant_time_comparison` (50-target fuzz suite under
  `fuzz/fuzz_targets/`)
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: verified
- **Notes**: Memory file documents 50+ files hardened to use `ct_eq` across
  120+ sessions.

### CLAIM-014: Saturating arithmetic on every counter / sequence / epoch

- **Category**: security
- **Source**: README.md L2318-2320 "Security Posture"
- **Claim**: All counter, sequence, epoch, and timestamp arithmetic uses
  `saturating_add` / `saturating_sub` to defeat overflow-based bypass.
- **Evidence artifact**: `crates/franken-node/src/` (2,502
  `saturating_add`/`saturating_sub` uses across 325 files, counted
  2026-09-24)
- **Verification command**:
  `rg -n '(?<![a-zA-Z_])([+\-]=\s*1|\\.\\s*[\\w]+\\s*[+\\-]\\s*1)' crates/franken-node/src/` (regression: any naked `+= 1` on a counter is a candidate finding)
- **Last verified**: 2026-09-24 (usage count only)
- **Status**: pending
- **Notes**: Downgraded from "verified". The earlier evidence was "60+ files
  modified per memory record", and no gate checks "every" counter: the
  verification command lists candidates, but nothing fails on a naked
  `+= 1`. Saturating arithmetic is widespread, but "all" is not
  demonstrated.

### CLAIM-015: ~23,000 `#[test]` cases across the workspace

- **Category**: verification
- **Source**: README.md L2348
- **Claim**: Roughly 23,000 `#[test]` cases across inline `#[cfg(test)]`
  modules and the workspace test trees.
- **Evidence artifact**: 26,532 `#[test]` attributes on 2026-09-25, of which
  22,139 are inline in `crates/franken-node/src/`
- **Verification command**:
  `rg -c '^\\s*#\\[test\\]' crates/franken-node/src/ tests/ crates/franken-node/tests/ sdk/verifier/ | awk -F: '{s+=$2} END {print s}'`
- **Last verified**: 2026-09-25 (registered count)
- **Status**: verified as a **registered** count only. Executed count is not
  measured: the inline tests compile only on the dedicated inline lane
  (`--cfg franken_node_inline_tests`), and no CI job runs the full suite
  (bd-reality-20260923-26n9r.9). A registered test is not evidence that it
  runs or passes.

### CLAIM-016: 146 registered cargo-fuzz harnesses

- **Category**: verification
- **Source**: README.md "Fuzzing and Differential Testing"
- **Claim**: cargo-fuzz harnesses target parsers, deserializers, signature
  verifiers, lifecycle inputs, canonical encoders, transcript readers.
- **Evidence artifact**: `fuzz/Cargo.toml` (146 `[[bin]]` targets, 146
  sources under `fuzz/fuzz_targets/`)
- **Verification command**: `rg -c '^\[\[bin\]\]' fuzz/Cargo.toml`
- **Last verified**: 2026-09-23 (count only)
- **Status**: verified (registration count); pending (compilation). The last
  full compile census (2026-05-29) found 45 targets not compiling, and
  `verification-target-compile-gate.yml` has never run (PR-only trigger, 0
  PRs). `fuzz/regression/` holds 5 inputs (bd-fuzz-regression-corpus-f28ac).

### CLAIM-017: 51 CI workflow files

- **Category**: verification
- **Source**: README.md L928, L2335-2341
- **Claim**: Gate-oriented CI with claim gates (ATC, BPET, DGIS, VEF),
  conformance gates, closer-discipline, mutants, coverage, security-golden-
  artifacts, etc.
- **Evidence artifact**: `.github/workflows/*.yml` (51 files)
- **Verification command**: `ls .github/workflows/*.yml | wc -l`
- **Last verified**: 2026-09-23
- **Status**: verified (files exist); **not evidence of enforcement**. The
  2026-09-23 audit found 82% of 1,924 main runs failing over 7 days, no green
  cargo test of the crate ever, and 10 PR-only gates that never ran because
  the repository has had no PRs (bd-reality-20260923-26n9r.9).

### CLAIM-018: 13 Criterion benchmarks

- **Category**: performance
- **Source**: README.md L2647-2657 (listed 8 by name)
- **Claim**: Benchmark suite covering Cuckoo revocation, BLAKE3, replay-bundle
  gzip, trust-card canonical, proof-verifier gate, anti-entropy insert,
  threshold-sig verify, `perf_wins`, plus 3 additional benches the README
  doesn't enumerate.
- **Evidence artifact**: `crates/franken-node/Cargo.toml` (13 `[[bench]]`
  targets as of 2026-09-23); `cargo bench -p frankenengine-node`
- **Verification command**:
  `cargo bench -p frankenengine-node --benches --no-run`
- **Last verified**: 2026-09-25 (13 `[[bench]]` targets registered)
- **Status**: verified as registered targets; no CI job compiles or runs
  them, so no benchmark result is claimed here.
- **Notes**: README under-counts; the 3 extras (`crypto_scheme_bench`,
  `evidence_ledger_performance`, `replay_bundle_gzip_bench` already in list,
  one more) should be added to the README's `[[bench]]` enumeration.

### CLAIM-019: Dual-Oracle close-condition gate (L1 + L2 + release policy)

- **Category**: verification
- **Source**: docs/DUAL_ORACLE_CLOSE_CONDITION.md; README.md L2614
- **Claim**: Program completion requires three simultaneous GREEN signals:
  L1 Product Oracle, L2 Engine-Boundary Oracle, Release Policy Linkage. No
  partial success; no waivers.
- **Evidence artifact**:
  `artifacts/oracle/l1_product_verdict.json` (target),
  `artifacts/oracle/l2_engine_verdict.json` (target),
  `artifacts/oracle/release_policy_verdict.json` (target)
- **Verification command**: `franken-node doctor close-condition --json`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: pending
- **Notes**: CLI handler `handle_doctor_close_condition` is wired. The
  verdict artifacts are checked in under `artifacts/oracle/`: L1 product
  RED (2026-07-12, compatibility corpus below 95%), L2 engine GREEN and
  release policy GREEN (both 2026-05-21, not re-derived since), so the
  committed `close_condition_receipt.json` is RED. Tracked by Track-3
  bridge-plan item `[T3-ORACLES]`.

### CLAIM-020: First-run bootstrap is friction-minimized

- **Category**: operability
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 4: "Install-to-safe-
  workload friction")
- **Claim**: An operator can go from `curl | bash` install through to a
  policy-governed workload with an automation-first, deterministic-gates
  path.
- **Evidence artifact**:
  `crates/franken-node/src/main.rs::Command::Init` handler;
  `crates/franken-node/src/config.rs::Config::resolve_with_bootstrap` (new
  in bridge plan: auto-synthesizes `trust.registry_signing_key` and
  `security.authorized_api_keys` so `init` succeeds with zero operator input);
  `crates/franken-node/tests/cli_arg_validation.rs`
- **Verification command**:
  `mkdir /tmp/fnode-fresh && cd /tmp/fnode-fresh && franken-node init --profile balanced --out-dir . --json | jq .bootstrap_synthesis`
- **Last verified**: 2026-05-20T22:30:00Z (manually verified during bridge
  plan smoke test; before the bridge plan, this command failed with
  `trust.registry_signing_key must be configured` on every empty directory)
- **Status**: pending
- **Notes**: The verification command covers `init` only, not the claimed
  `curl | bash` → policy-governed workload path. On 2026-09-23 that path was
  broken at several points:
  - The default installer ships v0.1.0 (1,136 commits stale), which cannot run
    guest JS.
  - `--method source` never clones frankentui.
  - A fresh source build could not `run hello.js` without a sidecar engine
    binary (fixed in 1ee827258).
  - `trust scan --deep --audit` needed two undocumented environment variables
    (fixed in 96f8f0188: `init` provisions a RemoteCap key and a scoped
    trust-scan token, and the receipt signing key is provisioned too).

  The README smoke workflow now exercises `run` (check 9). This claim moves
  back to verified only when a clean-container installer e2e passes
  (bd-reality-20260923-26n9r.11, bd-34d5).

### CLAIM-021: ≥3 IBD capabilities adopted by production users

- **Category**: operability
- **Source**: docs/PRODUCT_CHARTER.md §5–6; bd-reality-20260820-w0fc6.8
- **Claim**: At least three independent production operators exercise at least
  three of the ten impossible-by-default capabilities, evidenced by signed
  receipts whose audience is not a franken-node test fixture.
- **Evidence artifact**: `artifacts/adoption/ibd_production_use.json`
- **Verification command**:
  `python3 scripts/check_impossible_adoption.py --json`
- **Last verified**: 2026-08-21T00:00:00Z
- **Status**: pending
- **Notes**: Honest default is `production_operator_count=0`, `verdict=pending`.
  `bd-2hrg` closed the IBD index document, not production adoption. Do not
  mark this claim verified while count<3.

### CLAIM-022: ≥2 independent external replications across core claims

- **Category**: verification
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 6); docs/specs/section_13/bd-whxp_contract.md
- **Claim**: At least two independent external organizations reproduce the
  compromise-reduction (`≥10×`), migration-velocity (`≥3×`), and replay-coverage
  (`100%`) claims from published artifacts without conflict of interest.
- **Evidence artifact**: `artifacts/13/independent_replication_report.json`
- **Verification command**:
  `python3 scripts/check_independent_replications_gate.py --json`
- **Last verified**: 2026-11-11T00:00:00Z
- **Status**: pending (`independent_replications_passing=0` of required `2`;
  `scripts/check_independent_replications_gate.py` rejects RFC 2606/6761
  `example.org` placeholder URIs in `artifacts/13/independent_replication_report.json`)
- **Notes**: Tracked by `bd-whxp` and `bd-reality-20260923-26n9r.16`. Remains
  `pending` until two real independent external replication campaigns publish
  non-placeholder signed evidence URIs and pass the gate.

### CLAIM-023: API latency within 10% of Node.js (HC-003) and cold-start budgets

- **Category**: performance
- **Source**: docs/headline_claims.toml `HC-003`; docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md L187-189, L1062; perf/budgets.toml
- **Claim**: franken_node API latency is within 10% of Node.js for equivalent
  workloads (`HC-003`, `ratio_ci95[1] <= 1.10`) and meets `perf/budgets.toml`
  cold-start budgets (`ci_dev <= 200 ms`).
- **Evidence artifact**: `artifacts/perf/runtime_vs_node.json` (Ed25519-signed
  30-run + 5-warmup randomized interleaved triad report); `perf/budgets.toml`
- **Verification command**:
  `python3 scripts/bench_runtime_vs_node.py --bin target/release/franken-node --require-bun --runs 30 --warmup 5 --json`
- **Last verified**: 2026-11-18T10:54:47Z (release binary `sha256:e27676b859fc13ccb66562dc1014c13f07b56df03a42c57eebd7e1cb113fb8c6`, `franken_node` `de5420dce`, `franken_engine` `61685ec62`, `node v26.3.0`, `bun 1.4.4`)
- **Status**: pending (measured RED on HC-003: `verdict=FAIL`, `ratio_ceiling=1.10` untouched; `ci_dev <= 200.0 ms` cold-start budget `PASS` at `hello` `p50=179.063 ms`, `p99=221.428 ms`, `rss_p50=57402 KiB`)
- **Notes**: Measured in a single randomized interleaved invocation across all
  6 workloads (`hello`, `json_roundtrip`, `compute_loop`, `fs_read`,
  `require_pkg`, `loopback_http`, all 6 passing byte-identical stdout equality
  across `node`, `bun`, and `franken-node`): `hello` 4.71× node (`179.1 ms` vs
  `38.0 ms`, `bun` `27.5 ms`), `loopback_http` 3.51× (`214.0 ms` vs `60.9 ms`),
  `require_pkg` 4.95× (`227.6 ms` vs `45.9 ms`), `compute_loop` 12.56×
  (`702.7 ms` vs `56.0 ms`), `json_roundtrip` 14.09× (`1125.3 ms` vs `79.9 ms`),
  `fs_read` 16.98× (`806.2 ms` vs `47.5 ms`), with exact binomial
  order-statistic 95% CIs on `p50`/`p95`/`p99` and `os.wait4` `ru_maxrss` KiB.
  Tracked by `bd-reality-20260923-26n9r.10` / `.36` / `.37`.

## Update Cadence

- Every README "Why use franken-node" or "Comparison" claim added should land
  with a corresponding entry here.
- Pending entries should be revisited monthly; if no progress has been made
  toward emitting the evidence artifact, the bead tracking the gap should be
  re-prioritized.
- Stale entries (claim verified on date X, but underlying code has moved
  since) should be flagged and re-verified.
