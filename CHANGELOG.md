# Changelog

All notable changes to **franken_node** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-vector test data has its own log in [`vectors/CHANGELOG.md`](vectors/CHANGELOG.md).

Scope: this file tracks the `frankenengine-node` Rust crate (binary
`franken-node`) and its companion crates `franken-security-macros` and
`frankenengine-verifier-sdk`. Task references use the project's local Beads
tracker (`br-…` / `bd-…` IDs stored under `.beads/`); commits referenced by
shorthash are reachable with `git show <hash>`.

## [Unreleased]

This window covers work landed on `main` between the previous changelog cut
(2026-04-25) and 2026-05-16: roughly 1,500+ commits across security
hardening, validation infrastructure, operator tooling, and CI gate work.

### Added

#### Operator tooling and CLI

- `franken-node doctor workspace-pressure`: new doctor subcommand that reads
  disk, memory, build-fleet, and RCH-queue signals and routes them through a
  policy decision (balanced / conservative / permissive thresholds), emitting
  recommended operator actions in JSON or human form. Implementation lives in
  `crates/franken-node/src/ops/doctor.rs` and is documented in
  `BD_P9MPD5_IMPLEMENTATION.md` (bd-p9mpd.5).
- `franken-node ops resource-governor`: advisory subcommand that takes a
  process snapshot plus requested/active proof classes, RCH queue depth, and
  target-dir usage, and answers whether validation should run, defer, or
  deduplicate (target-dir lease planner, validation capacity-market bids).
- `franken-node ops validation-readiness`, `ops validation-closeout`,
  `ops config-audit`, and `ops metrics`: full operator surface for the
  validation broker / proof-cache lifecycle, with Prometheus-shaped metrics
  output (`ops/validation_broker.rs`, `ops/evidence_index.rs`).
- `franken-node proofs queue status` and `franken-node proofs workers restart`:
  operator entry points into the proof pipeline. The `restart` form fails
  closed without `--operator-id`, `--operator-role`, `--reason`, and
  `--confirm` (`cli.rs::ProofWorkersCommand`).
- `franken-node safe-mode {enter,status,exit}`: operator-driven lifecycle
  state machine backed by `runtime::safe_mode::SafeModeController`. Entry
  requires `--reason`, `--operator-id`, and `--trust-state-hash`; exit
  requires `--confirm` plus per-condition flags
  (`trust-state-consistent`, `no-unresolved-incidents`,
  `evidence-ledger-intact`).
- `franken-node doctor close-condition` and `doctor evidence-readiness`: new
  doctor leaves that emit dual-oracle close-condition receipts and report on
  evidence readiness from broker snapshots.
- `franken-node debug {explain,evidence,trace}`: operator-facing surfaces for
  walking a signed decision-receipt through verification, inspecting verifier
  evidence artifacts, and tracing policy evaluation steps.
- `franken-node fleet agent`: long-running fleet-agent loop with `--zone`,
  `--poll-interval-secs`, `--max-cycles`, and `--once` flags for embedded
  control-plane workers.
- Cleanup executor with audit receipts (bd-p9mpd.7): age- and extension-aware
  cleanup driven through `ops/cleanup_executor.rs` and durable
  `storage/cleanup_receipts.rs`, with dry-run/execute modes and full
  store→search→retrieve→delete lifecycle. See `BD_P9MPD7_IMPLEMENTATION.md`.
- Flight-recorder hygiene tracking (bd-iwa3z): `FlightRecorderTargetDir`
  wraps a `FlightRecorderTargetDirHygiene` (status enum
  `clean/stale/dirty/mixed/unknown`) plus a `FlightRecorderSyncRootHygiene`
  (status enum `clean/modified/untracked/conflicted/unknown`), and
  surfaces artifact-count, stale-artifact-count, and size analysis
  through the validation broker (`ops/validation_broker.rs`).
  See `BD_IWA3Z_IMPLEMENTATION.md`.

#### Validation infrastructure

- Cross-repo drift validation epic (bd-7vk3p): six-part series adding a
  cross-repo drift snapshot contract (bd-7vk3p.1), preflight classifier
  (bd-7vk3p.2), drift handoff renderer (bd-7vk3p.3), fixture hardening
  (bd-7vk3p.4), cross-repo readiness blockers (bd-7vk3p.5), and reproof
  watchlist (bd-7vk3p.6). Backed by
  `scripts/check_cross_repo_validation_drift.py` and reflected in validation
  broker readiness gates.
- Proof-lane readiness epic (bd-wc27p): proof-lane readiness classifier,
  capsule binding (constant-time), surfaced readiness state, frozen goldens,
  reroute policy, and SLO model with a reliability ledger. RCH worker
  reliability scoring (`crates/franken-node/src/ops`), fresh-heartbeat proof
  ambiguity model, swarm performance evidence, and operator handoff
  summaries shipped under the same epic.
- Validation broker / proof cache machinery: `validation_broker`,
  `validation_planner`, `validation_proof_cache`,
  `validation_proof_coalescer`, `validation_proof_debt_ledger`,
  `validation_readiness`, `validation_closeout`, `evidence_index`,
  `swarm_handoff_evidence`, `operator_transcripts`, `swarm_bead_templates`,
  `closed_bead_compliance`, and `cli_arg_validation` are all wired as
  first-class `[[test]]` targets in `crates/franken-node/Cargo.toml`.
- Operator what-if simulator, agent command-budget ledger, build-graph
  watcher (bd-38hez series), operator transcript goldens for RCH validation
  recovery.

#### Runtime / control-plane surfaces

- BPET evolution risk scorer + integration tests
  (`security/bpet`, `tests/evolution_risk_scorer_integration.rs`,
  `tests/conformance/bpet_feature_extraction.rs`,
  `tests/security/bpet_adversarial_evolution_suite.rs`).
- DGIS adversarial topology surfaces: deterministic `ContagionGraph` and
  contagion simulator (bd-1q38.1), fragility model, SPOF detection,
  immunization planner (bd-cclm.1, bd-3tw7), DGIS↔ATC and BPET↔ATC fusion
  bridges (`security/dgis`, `dgis/`, `federation/`).
- Trust-card camouflage-hint validation wired into `supply_chain::trust_card`
  with a dedicated verification gate (bd-35m7).
- Cancellation protocol conformance harness, fleet-decision contract
  conformance harness, security challenge–response conformance harness,
  migration protocol conformance harness, supply-chain attestation manifest
  golden, VEF execution-receipt binary-format golden
  (`tests/cancellation_protocol_conformance.rs`,
  `tests/fleet_decision_contract_harness.rs`,
  `tests/challenge_flow_timing_attack_resistance.rs`,
  `tests/migration_report_conformance.rs`,
  `tests/supply_chain_golden_artifacts.rs`,
  `tests/vef_receipt_schema_conformance.rs`).
- Authentication-failure visibility surface for incident response, including
  bounded per-source-IP cardinality in `AuthFailureLimiter`
  (`crates/franken-node/tests/auth_failure_limiter_loom.rs`,
  `tests/auth_failure_limiter_per_source_isolation.rs`).
- Mock-free end-to-end pipelines for transparency inclusion, migration,
  revocation registry, incident bundle lifecycle, trust-card lifecycle,
  control-epoch lifecycle, quarantine-registry lifecycle, evidence-ledger
  lifecycle, fork-detection lifecycle, marker-stream lifecycle, audience
  token chain, MMR proofs, evidence-replay gate, divergence gate, key-role
  separation registry, control-lane scheduler, cancellation protocol,
  epoch-transition barrier, and provenance gate
  (`crates/franken-node/tests/e2e_*.rs`, 19 files).

#### CI and gates

- `.github/workflows/closer-discipline-gate.yml`: blocks merges with thin
  or fabricated bead close-reasons, backed by
  `scripts/check_close_reason_quality.py`.
- `.github/workflows/coverage-report.yml`: aggregated test coverage report.
- `.github/workflows/compat-corpus-pass-gate.yml`: compatibility corpus
  threshold gate.
- `.github/workflows/execution-normalization-gate.yml`: deterministic
  execution / proof-normalization gate.
- `.github/workflows/lockstep-runner-release-gate.yml`: lockstep runner
  release readiness.
- `.github/workflows/mutants-gate.yml`: mutation-testing gate via
  `cargo-mutants`.
- Closer-discipline gate hooks added across 19+ `scripts/check_*.py`
  validators, plus the frankensqlite / policy / profile / tiered-trust
  checker scaffolds.

#### Specs and documentation

- `docs/specs/dgis_immunization_planner.md`,
  `docs/specs/dgis_quarantine_orchestration.md`,
  `docs/specs/validation_proof_explanation_bundle.md` (new validator
  contract).
- `docs/validation/proof-lane-readiness-blocker-runbook.md`: operator
  diagnostic playbook.
- `docs/security/bpet_adversarial_playbook.md`: BPET adversary kinds,
  detection signatures, parametric ramp curves, and detector-threshold
  tuning.
- `beads_compliance_audit/closer_discipline_memo.md` (2026-05-12)
  documents the false-closed bead anti-pattern and three-fix roadmap
  (checklist, pre-commit guard, CI gate).
- BD implementation memos at repo root:
  `BD_IWA3Z_IMPLEMENTATION.md` (flight-recorder hygiene),
  `BD_P9MPD5_IMPLEMENTATION.md` (workspace-pressure doctor),
  `BD_P9MPD7_IMPLEMENTATION.md` (cleanup executor + receipts),
  `BD_SH95A_IMPLEMENTATION.md` (RCH fixture-replay E2E patterns).

### Changed

- Replaced the fleet-quarantine mock transport with real file-based
  persistence (`FileFleetTransport` in
  `crates/franken-node/src/control_plane/fleet_transport.rs`).
- Replaced replay-bundle in-memory fixtures with real file-I/O round-trips
  in end-to-end tests.
- Replaced mocks with real dependencies in trust / OSV integration tests.
- Switched `BTreeMap` control-lane assignment storage to a fixed-size array
  for predictable allocation and cache behavior (bd-17nu4).
- Standardized `lock_utils` adoption across timing-sensitive test harnesses
  (ATC extractors, sybil proofs, degraded mode, sandbox policy, obligation
  tracker, conformance gates, virtual transport; bd-qkjac.1).
- Bead closer discipline (bd-8vo8v) enforced repo-wide: a close_reason must
  be ≥ 80 chars and cite at least one of a commit SHA, PR, or file:line;
  `bug`/`feature` types must also cite a passing test. The 2026-05-11
  compliance audit recalibrated 737 of 2,944 closed beads and found 18
  genuinely false-closed (2.4% of the recalibration sample); a separate
  scan of all 3,627 closed beads in scope found 1,354 (37%) with
  thin or empty reasons. See `beads_compliance_audit/closer_discipline_memo.md`.
- Mass UBS-criticals closure (bd-dwb9i): ~19 commits hardening
  supply-chain, trust-card, DGIS, BPET, connector, federation, policy, and
  transport modules against unbounded growth, overflow, and type confusion.
- Engine dispatcher consumes the new `CapabilityProfile` getter API rather
  than direct field access.
- Proof-pipeline operator surface (bd-rm6ex): new `ops/proof_pipeline.rs`
  module plus `api/proof_pipeline_routes.rs` expose proof creation,
  batching, and transport telemetry with policy-visible lane assignment
  and fallback logic. The CLI surface lives under
  `franken-node proofs {queue status, workers restart}`.
- Dropped vendored `transplant/` (pi_agent_rust snapshot) and surrounding
  drift-detect infrastructure once cross-repo drift validation
  (bd-7vk3p) shipped.
- Decision receipts now sign and verify through the shared
  `crypto::Ed25519Scheme` raw trait path. This deliberately preserves the
  existing `ed25519-v1` canonical preimage and signature bytes instead of
  double-wrapping receipts with the new domain-framed trait path (bd-dwx4l).

### Fixed

- Preserved `TempDir` lifetime across the fleet-quarantine test scope so
  state is not cleaned up underneath the assertion phase.
- Corrected JSON syntax in the decision-receipt golden fixture and
  improved `usize` to `u64` conversion in VEF schema-conformance tests.
- Hardened report generation against `chrono::Duration` conversion failure.
- Closed a nonce-replay timing window in `control_plane::audience_token` by
  pulling fast-path comparison through `security::constant_time::ct_eq`.
- Parser-bomb DoS bounds for evidence/attestation reads enforced through
  `bounded_read{,_to_string}` size checks (`lib.rs`).
- Fail-closed expiry semantics: invalid or unparsable timestamps are now
  treated as expired in validation readiness paths.
- Trust-scan hash computation: replaced overflow-prone subtraction with
  `wrapping_sub` for cyclic clock-drift handling.
- `time_travel_engine` f64 ratio checks: added `is_finite` guards and
  saturation around arithmetic that could overflow at extreme replay
  windows.
- VEF receipt canonical hash schema migration from v2 to v3: dropped a
  legacy domain+length prefix that produced cross-version mismatch on
  replay.
- Bounded claim byte capacity before computing the binding hash, closing a
  DoS gap on adversarial claims.
- Sanitized `signing_key` Debug output in `QuarantineController` to prevent
  accidental key disclosure in error logs; redacted `TaskClass` and other
  sensitive Debug fields.
- Atomic write paths now `fsync` the containing directory after rename for
  decision receipts and fleet transport state, preventing torn writes on
  crash.
- Activation executor now fails closed at the executor boundary
  (bd-2gh.1); connector lifecycle conformance proofs wired into the suite.

### Security

- **Constant-time comparison sweep.** ~65 commits applied
  `security::constant_time::ct_eq{,_bytes}` (backed by the `subtle` crate)
  across signature, hash, MAC, content-hash, trace-id, and action-id
  comparisons. Notable sites: `audience_token`, `decision_receipt`,
  `verifier-sdk` content hash, replay-context chain hash, quarantine
  validation, explanation-bundle digest.
- **Saturating arithmetic.** ~79 commits replaced raw `+`/`+=` on
  counters, sequences, and epochs with `saturating_add`/`saturating_sub`.
  Notable sites: registry GC counter, crash-loop test counters, test
  result counters, session-auth `seq` pinning at `u64::MAX`, atomic reset
  of `SESSION_NONCE_COUNTER` near saturation, time_travel_engine f64
  guards.
- **Bounded vector growth.** `push_bounded` (defined in
  `crates/franken-node/src/lib.rs`) replaced raw `Vec::push` in
  capacity-critical contexts across supply-chain, connector, api,
  runtime, policy, vef, security, tools, and control-plane modules
  (bd-32vc6 and adjacent beads). Zero-capacity paths now clear rather
  than panic.
- **Domain-separated, length-prefixed hashing.** Migrated capability
  artifacts, vef-receipts, replay capsules, and trust-card snapshots to
  length-prefixed canonical forms with `b"<module>_<function>_vN:"`
  domain prefixes (bd-11ek9.1, bd-32vc6).
- **Checker hardening initiative.** ~197 `harden …` commits strengthened
  validation gates across signed-extension registry, extension manifest,
  hardening-state, witness ref, correctness envelope, high-assurance,
  integrity sweep, ecosystem API, vef perf budget, bounded masking, DGIS
  barrier, BPET economic, key-role separation, VEF evidence capsule,
  policy-change workflow, fork detection, audience token, deterministic
  seed, device profile, counterfactual, control epoch, ZK attestation,
  session auth, trust-object id, verifier SDK, migration pipeline,
  migration artifacts, universal verifier SDK, verifier economy,
  rollback bundle, zone segmentation, trajectory camouflage, durability
  mode, repro bundle, category shift, counterfactual lab, durability
  violation, control evidence, proof-carrying decode, transport fault,
  idempotency, region tree, cancellable task, and adversarial suite.
- **Audit follow-up waves** (bd-2jns, bd-ye4m, etc.): 9-of-14 then 14-of-14
  TRUE_FALSE_CLOSED implementations from the 2026-05-11 audit landed
  through audit-followup waves 3 through 7, each wave covering an
  additional sub-task (fixtures, integration tests, wiring, verification
  gates) for deferred large false-closures.
- **Authentication-failure source-IP bounding.** `AuthFailureLimiter` now
  caps source-IP cardinality to defeat memory-DoS via unbounded source
  tracking.
- **Timestamp monotonicity** added to decision-receipt construction.
- **`is_finite` guards** added to f64 equality assertions in security
  tests, preventing NaN/Inf bypasses.
- `#![forbid(unsafe_code)]` is enforced in both `lib.rs` and `main.rs`;
  no `unsafe` blocks exist in the primary crate.

### Performance

- Eliminated per-result metadata clones in cleanup-receipt search.
- Eliminated per-event `format!` allocations in validation loops.
- Cached canonical schema field lookup to avoid per-result allocations in
  the serializer hot path.
- Reduced root-publish lock registry contention in the control-plane.
- Indexed the obligation reserve hot path in the connector.
- Made shared evidence-ledger count accessors cheap.
- Switched MMR proofs to use raw hashes internally.
- Replaced a hot-path stderr logger in the evidence ledger.
- Replay-bundle Gzip benchmark suite, threshold-signature verify
  benchmark, anti-entropy insert benchmark, proof-verifier gate
  benchmark, Cuckoo revocation benchmark, BLAKE3 performance benchmark,
  trust-card canonical benchmark, and a consolidated `perf_wins`
  benchmark are all wired under `[[bench]]` in
  `crates/franken-node/Cargo.toml`.
- ~15 dedicated `perf(threshold-sig)` commits and ~12 `perf(replay-bundle)`
  commits sharpened the two highest-volume verification surfaces.
- **Replay-bundle streaming JSON-size measurement** (bd-98xo5.6.1, T6.1):
  promoted `canonical_json_len` from internal helper to a public streaming
  byte-counter that skips the intermediate `Vec<u8>` allocation
  `serde_json::to_vec(value)?.len()` would have produced. Round-1
  perf-bench measurements
  (`tests/artifacts/perf/20260520T214003Z_franken_node_perf/criterion_raw/replay_bundle_gzip.txt`)
  report a 1.83-2.07× speedup over the `to_vec`-based variant at every
  event-count (10/100/1000), held across the bench's `streaming_counter`
  benchmark which now invokes production code directly rather than a
  divergent local reimplementation. Regression-guarded by
  `canonical_json_len_streams_rather_than_materialising_a_vec` (bd-98xo5.6.2,
  T6.2) which inspects the internal `write_calls` counter via
  `canonical_json_streaming_stats` and fails loud if a future patch reverts
  the function to the buffered shape.

### Testing

- ~23,000 `#[test]` cases across inline `#[cfg(test)]` modules and
  workspace-root suites (`tests/integration`, `tests/conformance`,
  `tests/contract`, `tests/e2e`, `tests/golden`, `tests/security`,
  `tests/perf`).
- Proptest- and fuzz-style invariants for `ct_eq`, `bounded_read`, and
  `saturating_add` (`tests/encoding_proptest.rs`,
  `tests/claims_proptest.rs`, `tests/conformance_proptest.rs`,
  `tests/replay_bundle_adversarial_fuzz.rs`,
  `tests/fleet_quarantine_serde_fuzz_harness.rs`,
  `tests/spec_derived_fuzz_seeds.rs`,
  `tests/sdk_verifier_public_api_fuzz_harness.rs`,
  `tests/traceparent_parser_fuzz_harness.rs`).
- Loom-based concurrency interleaving tests for the
  `AuthFailureLimiter`, operator process-start initialization, evidence
  ledger append ordering, and remote-cap replay token set.
- Metamorphic suites for storage, control-lane policy, control-epoch,
  trust card, replay window, replay bundle event reorder, time-travel,
  artifact signing, decision-receipt round trip, activation pipeline,
  epoch-key derivation, threshold-signature quorum, evidence-ledger
  chain order, canonical serializer, and observability witness.
- Adversarial trust-card forgery and supply-chain poisoning suites
  (`tests/adversarial_trust_card_forgery.rs`,
  `tests/adversarial_supply_chain_poisoning.rs`).
- Connector lifecycle stress, interop suite revocation, public-API E2E,
  method-contract artifact conformance, and protocol harness tests
  (`tests/connector_*.rs`,
  `tests/conformance/connector_lifecycle_transitions.rs`).
- RCH fixture-replay E2E covering 8 failure modes (remote success, SSH
  timeout E104, missing toolchain, filesystem pressure, local fallback
  refusal, cargo contention deferral, source-only blocking, product
  compile failure) in `tests/e2e_rch_validation_fixture_replay.rs`
  (bd-sh95a, `BD_SH95A_IMPLEMENTATION.md`).

### Tooling and CI

- Closer-discipline gate (`.github/workflows/closer-discipline-gate.yml`)
  blocks merges with thin/empty close_reasons. Companion script
  `scripts/check_close_reason_quality.py` doubles as a pre-commit guard
  (`scripts/check_close_reason_quality.py --staged --warn-only`).
- All new validators follow the standardized check-script contract:
  `--json` / `--self-test` / `--no-write` / `--skip-cargo` flags,
  structured exit codes, and JSON artifact output. The
  `scripts/check_*.py` catalog now exceeds 460 scripts.
- New gates pair with new specs: each adds a `docs/specs/<gate>.md`
  contract and a `scripts/check_<gate>.py` validator.

### Documentation

- The README's command reference and Configuration sections have been
  updated to reflect new CLI leaves (`safe-mode`, `proofs`, `debug`,
  `doctor workspace-pressure`, `doctor close-condition`,
  `doctor evidence-readiness`, `ops resource-governor`,
  `ops validation-readiness`, `ops validation-closeout`,
  `ops config-audit`, `ops metrics`, `fleet agent`,
  `verify {module,corpus,transparency-log,recovery-runbook}`,
  `trust-card {show,export,list,compare,diff}`).
- Product charter (`docs/PRODUCT_CHARTER.md`) and architecture overview
  (`docs/ARCHITECTURE_OVERVIEW.md`) are the authoritative scope and shape
  documents; the README now points at them rather than restating policy.

[Unreleased]: https://github.com/Dicklesworthstone/franken_node/commits/main
