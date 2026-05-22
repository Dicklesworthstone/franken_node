# DEFINE — franken_node workspace-wide perf profile

Run-id: `20260520T214003Z_franken_node_perf`
Requestor: Jeffrey Emanuel
Decision being supported: Identify the ranked hotspot list that
`extreme-software-optimization` will score (Impact × Confidence / Effort
≥ 2.0). No optimization happens in this skill.

The franken_node workspace is the **product layer** over the
`franken_engine` substrate. It is a CLI + library, **synchronous** Rust
(`async fn` count = 0 in `crates/franken-node/src/`), `#![forbid(unsafe_code)]`,
edition 2024, no workspace-wide `[profile.*]` override.

This run profiles all ten committed Criterion benches plus targeted
microbenches that exercise the hot paths the codebase reality-check
flagged: `vef::*`, `observability::evidence_ledger`,
`control_plane::fleet_transport`, `dgis::contagion_simulator /
fragility_model / spof_detection`, `replay::time_travel_engine`,
`encoding::canonical_serializer`, `crypto::schemes`,
`security::threshold_sig`, `security::constant_time`, and the
tree-sitter-driven `migration` audit.

## Scenarios

Each scenario gets its own DEFINE row. They are the units of comparison
across rounds — a hotspot may live across more than one scenario, and
the per-scenario p95 is what budgets clamp.

| # | Scenario (Criterion bench / harness)                | Surface under test                                         | Scale axis                  | Workload notes |
|--:|------------------------------------------------------|-------------------------------------------------------------|------------------------------|----------------|
| 1 | `crypto_scheme_bench::ed25519_*_raw/{64,512,4096}`   | `crypto::Ed25519Scheme` sign/verify                         | payload size                | dalek baseline + wrapper |
| 2 | `threshold_sig_verify_bench::{current,preparsed}/{8,32}` | `security::threshold_sig::verify_threshold`             | signer count                | current path vs preparsed-key proxy |
| 3 | `trust_card_canonical_bench`                         | `supply_chain::trust_card` canonical serialization          | card complexity             | HMAC-signed snapshot perf |
| 4 | `replay_bundle_gzip_bench`                           | `tools::replay_bundle` + flate2 gzip chunking               | timeline size / compression | bundle export hot path |
| 5 | `cuckoo_revocation_bench`                            | `security::revocation_freshness` cuckoo filter              | insert/lookup volume        | OSV refresh path |
| 6 | `proof_verifier_gate_bench`                          | `vef::proof_verifier` proof gate                            | proof complexity            | VEF proof admission cost |
| 7 | `anti_entropy_insert_bench` (feat: `advanced-features`) | `runtime::anti_entropy` insert + merkle reconcile        | record count                | reconciliation cycle |
| 8 | `blake3_performance_bench` (feat: `blake3`)          | optional BLAKE3 vs SHA-256                                  | input size                  | compare hash backends |
| 9 | `perf_wins`                                          | five claimed wins (SignaturePreimage, transparency, lane scheduler TaskId, frankensqlite, trace digest) | mixed | regression guard |
| 10| `evidence_ledger_performance` (file present, not registered in Cargo) | `observability::evidence_ledger` append + len/snapshot | append rate | discoverable hot path |

## Metric

For every scenario:

- **wall-time**: p50, p95, p99 per iteration in microseconds (Criterion);
  p99.9/p99.99 are *conservative worst-observed* (default sample_size ≤ 100).
- **throughput**: derived `ops/sec = 1 / mean_seconds` reported in
  `BASELINE.md`.
- **peak RSS** of the bench process via `/usr/bin/time -v`.
- **CPU flame attribution**: which symbol owns the wall-time, via samply
  (or perf where samply is unavailable).
- **alloc rate**: only collected for scenarios where DHAT can attach
  cheaply (perf_wins, replay_bundle_gzip, trust_card_canonical).

## Budget

Workspace has no per-scenario p95 budget in `BUDGETS.md`. The committed
artifact `artifacts/performance_budgets/bd-ncwlf_hot_path_budget_evidence.json`
defines **smoke-budget work-unit ceilings** (not wall-clock budgets) for
four hot paths:

| Hot path                                              | post-fix p95 (work units) | regression guard |
|-------------------------------------------------------|--------------------------:|------------------|
| `ops.telemetry_bridge.persistence_batch`              | 4.0                       | ≤ +10% vs before-fix p95 |
| `control_plane.fleet_transport.read_snapshot`        | 5.0                       | ≤ +10% vs before-fix p95 |
| `observability.evidence_ledger.len_snapshot`         | 3.0                       | ≤ +10% vs before-fix p95 |
| `storage.frankensqlite_adapter.write_event`          | 6.0                       | ≤ +10% vs before-fix p95 |

For this run the budget is **the current p95 of each Criterion bench**
multiplied by 0.5 as a target for the optimization round, per the
"pick current p95 × 0.5" fallback in the skill. The number per scenario
is recorded in `BASELINE.md` once measured.

## Golden output

This is a *profiling* skill — no code change ships from here. Behavioral
golden checks aren't required for the profile run itself. But the
hand-off to `extreme-software-optimization` must include:

- `golden_checksums.txt`: sha256 of the **bench binaries** themselves
  under the new `release-perf` profile, so the next skill can confirm
  it's profiling the same binary it changes.
- A frozen Cargo.lock SHA at run start (recorded in `fingerprint.json`).

## Scope boundary

Out of scope this run:

- **`fastapi_rust`** (HTTP API surface) — has its own perf gates under
  `tests/perf/remote_bulkhead_under_load.rs`; runs there.
- **Async/Tokio paths** — none in the primary crate; not relevant.
- **Cross-filesystem matrix** — single-host run on `/data` (ext4 over
  NVMe, see fingerprint).
- **Cold-cache numbers** — every scenario runs warm; cold-cache I/O
  belongs to a separate scenario (`replay_bundle_export_cold` is a
  candidate for round 2 once we know whether disk dominates).
- **Network egress paths** — no live HTTP in benches.
- **`migrate audit` tree-sitter end-to-end on a real npm app** — runs
  in `migrate_cli_e2e`; not parameterizable as a microbench in this round.
  Listed for round 2.

## Variance envelope

Per the skill default:

- ≤ 10 % p95 drift vs the prior same-host run → noise, ignore.
- > 10 % → investigate (rebuild, re-measure on the same host).
- > 20 %, or three consecutive > 10 % → escalate; treat the host as
  contaminated and find a quieter run window.

## Stakeholder / requester

Jeffrey Emanuel asked for "exhaustively apply ALL phases end to end of
the /profiling-software-performance skill." The decision that hangs on
this profile is: where should the codebase invest next round of
optimization? The hotspot table answers that question.
