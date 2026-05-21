# Performance History — franken_node profiling skill

A living index across rounds. Each row is one round-id directory. New
rounds append; never overwrite.

## Round index

| Round | Date          | Run-id                                    | Scope                                                | Δ vs prior |
|------:|---------------|-------------------------------------------|------------------------------------------------------|------------|
| 1     | 2026-05-20    | `20260520T214003Z_franken_node_perf`      | All 10 Criterion benches; full DEFINE→HAND OFF; baselines + perf + samply + heaptrack for top-3 candidates | n/a (first profile) |
| 2     | 2026-05-20    | `20260520T231041Z_franken_node_perf_r2`   | Round-1 deferred items: evidence_ledger (now registered as `[[bench]]`), dgis::contagion_simulator integration test, vef::proof_generator test, fleet_transport static read | confirmed 2 round-1 candidates as non-hotspots; raised 2 new candidates |

## Unified cross-round hotspot ranking (current)

| Final rank | Location                                                                                  | Source round | Status |
|----------:|---------------------------------------------------------------------------------------------|-------------:|--------|
| 1         | `trust_card_canonical::canonicalize_value_current` recursive `Value::clone()` — Θ(W^N × N), 3.59 s on complex_4x12 | R1           | confirmed; head of queue for `extreme-software-optimization` |
| 2         | `crypto::Ed25519Scheme::{sign_raw,verify_raw}` rebuilds keys per call — flat +22 µs / +6 µs | R1           | confirmed; highest ROI fix (preparsed-handle pattern) |
| 3         | `security::threshold_sig::verify_threshold` re-parses VerifyingKey per call — 10 % win available | R1           | already proven on bench; promote to real callers |
| 4         | `cuckoo_revocation` insert cliff between N=10 k and N=50 k                                  | R1           | policy decision, no code change |
| 5         | `dgis::contagion_graph` String NodeId BTreeMap operations — ~17 % of contagion-test cycles | **R2**       | new finding; clean contained win once production frequency is measured |
| 6         | `replay_bundle_event_size::vec_len` vs `streaming_counter` (1.86×)                          | R1           | one-call-site replacement |
| 7         | `fleet_transport::canonicalize_json_value` `format!()` of unused-on-happy-path `path` string | **R2**       | reframed: NOT the same hotspot as trust_card; minor allocation hygiene only |
| —         | `observability::evidence_ledger::append`                                                    | R2 (reject)  | 16.62 µs / append — not a hotspot at current scale; remove from R1 deferred list |
| —         | `dgis::contagion_simulator::step()`                                                         | R2 (reject)  | 0.45 % cycles on integration-test workload — round-1 static-read hypothesis was wrong; do NOT optimise |

## Round-3 candidates (measurement gaps remain)

- `vef::proof_generator::compute_proof_bytes` scaling sweep — **resolved
  as non-hotspot** by bd-98xo5.8.2 on 2026-05-21; see decision row below.
- `vef::receipt_chain::verify_integrity` chain-length sweep — **resolved
  as non-hotspot** by bd-98xo5.8.2 on 2026-05-21; see decision row below.
- `migration` tree-sitter parsing on real npm corpora.
- `contagion_simulator::step` on a *large* graph (10k nodes, 100 steps) to confirm or reject at scale.

## Non-hotspot decisions (bd-98xo5 epic)

Surfaces investigated and explicitly classified as "fast enough at current
scale" — these are NOT eligible for further optimisation work until the
documented reopen condition fires. Re-running the cited bench under a fresh
perf round is the gate to re-classify.

| Surface | Date / source run | Per-call cost | Reopen if | Tracking bead |
|---------|-------------------|---------------|-----------|---------------|
| `vef::proof_generator::compute_proof_bytes` + `vef::receipt_chain::verify_integrity` | 2026-05-21 / `20260520T231041Z_franken_node_perf_r2` (proof_generator.perf.flat.txt) | R2 profile: `proof_generator_timeout_race` 1000-loop test finishes in 30 ms total (≈ 30 µs per invocation incl. fixture setup); user-code symbols ≥ 0.3 % flat share = **0** (kernel page-table init dominates at 10.50 %); 926 allocs / 1000 invocations ≈ 1 alloc per call. Per source-level prediction in `crates/franken-node/benches/vef_proof_chain_bench.rs:20-30` (shipped at bd-98xo5.8.1 commit `3471198b`): generate/N=4096 ≈ 1 ms, verify/N=4096 ≈ 10 ms — three orders of magnitude below the rank-1 hotspot (`trust_card_canonical complex_4x12` at 3591 ms) and same order as the already-promoted rank-3 hotspot (`threshold_sig_verify_threshold/32` at 1.78 ms). | Production sustains > 1 000 proof windows / sec across the fleet, OR a real perf round on `vef_proof_chain_bench` measures N=4096 verify above 30 ms (3× the predicted ceiling) | bd-98xo5.8.2 (closed 2026-05-21) |

## Δ per scenario across rounds

Round 2 did not re-baseline any round-1 scenario; the iteration protocol
requires that to happen *after* `extreme-software-optimization` ships a
change. The Δ column below is reserved for future rounds.

| Scenario                              | R1 p95       | R2 p95 | Δ    |
|---------------------------------------|-------------:|-------:|------|
| trust_card_canonical `current/medium_3x8` | 33.23 ms |   —    | —    |
| trust_card_canonical `current/complex_4x12` | 3 591 ms |   —    | —    |
| ed25519_scheme_sign_raw/64            |    45.69 µs  |   —    | —    |
| threshold_sig_verify current/32       |     1.78 ms  |   —    | —    |
| cuckoo_filter_insert/50k              |    24.78 ms  |   —    | —    |
| evidence_ledger append (large entry)  |       —      | 16.62 µs| (new) |

## Build / fingerprint provenance

Round 1 and round 2 used the **same host** (AMD EPYC 7282, ext4/NVMe,
Linux 6.17.0-22-generic), **same toolchain** (rustc 1.97-nightly
2026-04-30), **same `release-perf` build profile** (re-added in round 2
after concurrent agents reverted it), and **same kernel tuning**
(`perf_event_paranoid=1`, `kptr_restrict=0`, `nmi_watchdog=0`,
`perf_event_mlock_kb=32768`). Cross-round comparisons are valid; see
each round's `fingerprint.json` for the exact diff.
