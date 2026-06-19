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
- **Evidence artifact**: `artifacts/compat/corpus_pass.json` (target path; not
  yet emitted)
- **Verification command**:
  `franken-node verify lockstep <corpus> --runtimes node,bun,franken-node --emit-fixtures`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill — no signed
  artifact yet)
- **Status**: pending
- **Notes**: `compat-corpus-pass-gate.yml` workflow exists; the workflow's
  artifact emission step has not produced a checked-in baseline. Tracked by
  the Track-3 bridge-plan item `[T3-CORPUS]`.

### CLAIM-002: ≥3× migration throughput vs. baseline

- **Category**: migration
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 2)
- **Claim**: franken-node delivers ≥3× migration throughput / confidence vs.
  baseline patterns, measured as time-to-production + confidence score delta.
- **Evidence artifact**: `artifacts/migration/throughput_delta.json` (target
  path; not yet emitted)
- **Verification command**: TBD — needs a published comparison-corpus runner
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: pending
- **Notes**: `migration-velocity-gate.yml` workflow exists; baseline/treatment
  numbers have not been published. The four-stage migrate pipeline (audit,
  rewrite, validate, rollout) is implemented and runs end-to-end on real
  Node/Bun projects, so the throughput claim is plausible but not yet
  *measured-and-signed*.

### CLAIM-003: ≥10× reduction in successful host compromise vs. baseline

- **Category**: security
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 3); README.md "Why use
  franken-node" L125
- **Claim**: franken-node achieves ≥10× reduction in successful host
  compromise vs. baseline runtimes, measured via adversarial extension
  campaigns on an instrumented test harness.
- **Evidence artifact**: `artifacts/security/compromise_reduction.json`
  (target path; not yet emitted)
- **Verification command**:
  `cargo test -p frankenengine-node --test 'adversarial_*' --release` then
  aggregate via the harness in
  `tests/security/exfiltration_sentinel_scenarios.rs`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: pending
- **Notes**: Adversarial test suites that back this claim are real and pass
  today (see `tests/security/`: `adversarial_trust_card_forgery`,
  `adversarial_supply_chain_poisoning`, `bpet_adversarial_evolution_suite`,
  `dgis_quarantine_containment`, `dgis_adversarial_suite`, etc.). What is
  missing is a published baseline/treatment study with a single number
  ("10×") attached to a signed artifact.

### CLAIM-004: 100% deterministic replay for high-severity incidents

- **Category**: resilience
- **Source**: docs/PRODUCT_CHARTER.md §5 (table row 5); README.md L114
- **Claim**: Every high-severity incident has a full replay bundle
  (`.fnbundle`) such that any operator can replay it byte-for-byte.
- **Evidence artifact**:
  `tests/conformance/replay_bundle_integrity_conformance.rs`,
  `tests/conformance/incident_bundle_integrity_conformance.rs`,
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
- **Evidence artifact**: `crates/franken-node/src/security/revocation_freshness.rs`;
  `crates/franken-node/src/security/revocation_freshness_gate.rs`
- **Verification command**:
  `cargo test -p frankenengine-node revocation_freshness`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: verified (implementation + tests); pending (signed external
  attestation)
- **Notes**: Recent commit `6695a5c6 fix(close_condition): switch verify to
  verify_strict (Ed25519 malleability)` confirms active hardening on the
  fail-closed path.

### CLAIM-007: Counterfactual policy simulation

- **Category**: resilience
- **Source**: README.md "Why use" L131
- **Claim**: `incident counterfactual --policy strict` re-executes the same
  trace under a different policy profile and emits a reproducible diff of
  decisions, blocked actions, and evidence.
- **Evidence artifact**: `crates/franken-node/src/replay/time_travel_engine.rs`,
  `crates/franken-node/src/tools/counterfactual_replay.rs`,
  `tests/incident_replay_counterfactual_cli_e2e.rs`
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
  `tests/conformance/lockstep_*` (see `.github/workflows/lockstep-runner-release-gate.yml`)
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
  `tests/registry_cli_wire_conformance.rs`
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
- **Evidence artifact**: `sdk/verifier/src/lib.rs` (266 `#[test]` cases);
  `tests/conformance/verifier_sdk_capsule_replay.rs`;
  `tests/conformance/verifier_session_monotonic.rs`
- **Verification command**: `cargo test -p frankenengine-verifier-sdk`
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: verified

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
- **Evidence artifact**: 60+ files modified per memory record; codebase-wide
  grep `rg -n 'saturating_(add|sub)' crates/franken-node/src/`
- **Verification command**:
  `rg -n '(?<![a-zA-Z_])([+\-]=\s*1|\\.\\s*[\\w]+\\s*[+\\-]\\s*1)' crates/franken-node/src/` (regression: any naked `+= 1` on a counter is a candidate finding)
- **Last verified**: 2026-05-20T00:00:00Z (registry backfill)
- **Status**: verified

### CLAIM-015: ~23,000 `#[test]` cases across the workspace

- **Category**: verification
- **Source**: README.md L2348
- **Claim**: Roughly 23,000 `#[test]` cases across inline `#[cfg(test)]`
  modules and the workspace test trees.
- **Evidence artifact**: 24,255 actual count (under-count in README):
  20,854 in `src/` + 1,538 in `tests/` + 1,597 in `crates/franken-node/tests/` +
  266 in `sdk/verifier/`
- **Verification command**:
  `rg -c '^\\s*#\\[test\\]' crates/franken-node/src/ tests/ crates/franken-node/tests/ sdk/verifier/ | awk -F: '{s+=$2} END {print s}'`
- **Last verified**: 2026-05-20T17:00:00Z (counted during reality-check)
- **Status**: verified

### CLAIM-016: 50 cargo-fuzz harnesses

- **Category**: verification
- **Source**: README.md L2555 ("43 cargo-fuzz harnesses" — under-counted)
- **Claim**: cargo-fuzz harnesses target parsers, deserializers, signature
  verifiers, lifecycle inputs, canonical encoders, transcript readers.
- **Evidence artifact**: `ls fuzz/fuzz_targets/` (actual count 50; README
  said 43)
- **Verification command**: `ls fuzz/fuzz_targets/ | wc -l`
- **Last verified**: 2026-05-20T17:00:00Z
- **Status**: verified

### CLAIM-017: 29 CI gate workflows

- **Category**: verification
- **Source**: README.md L928, L2335-2341
- **Claim**: Gate-oriented CI with claim gates (ATC, BPET, DGIS, VEF),
  conformance gates, closer-discipline, mutants, coverage, security-golden-
  artifacts, etc.
- **Evidence artifact**: `.github/workflows/*.yml` (29 files)
- **Verification command**: `ls .github/workflows/ | wc -l`
- **Last verified**: 2026-05-20T17:00:00Z
- **Status**: verified

### CLAIM-018: 11 Criterion benchmarks

- **Category**: performance
- **Source**: README.md L2647-2657 (listed 8 by name)
- **Claim**: Benchmark suite covering Cuckoo revocation, BLAKE3, replay-bundle
  gzip, trust-card canonical, proof-verifier gate, anti-entropy insert,
  threshold-sig verify, `perf_wins`, plus 3 additional benches the README
  doesn't enumerate.
- **Evidence artifact**: `crates/franken-node/benches/` (11 `.rs` files);
  `cargo bench -p frankenengine-node`
- **Verification command**:
  `cargo bench -p frankenengine-node --benches --no-run`
- **Last verified**: 2026-05-20T17:00:00Z
- **Status**: verified
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
- **Notes**: CLI handler `handle_doctor_close_condition` is wired in
  `main.rs:6218+`. The three verdict artifacts at the documented paths are
  not yet checked in. Tracked by Track-3 bridge-plan item `[T3-ORACLES]`.

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
- **Status**: verified
- **Notes**: README's "Quick Example" Day-0 workflow now works end-to-end
  through `init → trust scan → trust list → trust card`.

## Update Cadence

- Every README "Why use franken-node" or "Comparison" claim added should land
  with a corresponding entry here.
- Pending entries should be revisited monthly; if no progress has been made
  toward emitting the evidence artifact, the bead tracking the gap should be
  re-prioritized.
- Stale entries (claim verified on date X, but underlying code has moved
  since) should be flagged and re-verified.
