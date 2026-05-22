# Hypothesis ledger — `20260520T214003Z_franken_node_perf`

Every candidate explanation for the observed hotspots, marked
`supports` / `rejects` / `revisit` with evidence. Pre-flame predictions
are credited where they panned out, called out where they didn't.

## Pre-flame predictions (from static read in Phase 4)

| Hypothesis (pre-flame)                                                              | Verdict   | Evidence |
|-------------------------------------------------------------------------------------|-----------|----------|
| **#1 evidence_ledger replay-detection hash scan dominates append throughput**      | revisit   | Bench file exists but is **not registered** as `[[bench]]` in `crates/franken-node/Cargo.toml` → ran 0 measurements. Cannot confirm or reject this round. Round-2 work. |
| **#2 canonical_serializer recursive `Vec` allocation for nested object key sort**  | **supports (partial)** | Heaptrack: 21 505 042 allocs in 63 s for `trust_card_canonical/current/medium_3x8`; 87 % of those go through `hashbrown::raw::fallible_with_capacity` (the IndexMap backing serde_json::Value::Object). BUT — the dominant cost is **not** the key-sort allocation hypothesised; it's the *deep `Value::clone()` of the entire subtree* at every recursion level. The bench's "optimized" variant addresses the key-sort allocation and saves only 4-6 %, leaving the subtree-clone untouched. |
| **#3 fleet_transport `canonicalize_json_value` `format!()` allocates path strings** | revisit   | Bench coverage of fleet_transport is in `tests/perf/control_plane_overhead_gate.rs`, not a Criterion bench. Not measured this round. Plausible — the structural pattern (recursive `format!("{path}.{key}")`) is identical to the trust-card finding. |

## Observed-from-profile findings

| Hypothesis (post-flame)                                                  | Verdict   | Evidence |
|---------------------------------------------------------------------------|-----------|----------|
| **Allocator dominates trust_card_canonical**                              | **supports** | perf `_int_malloc 7.62 % + free 2.82 % + malloc 1.17 % + libc_malloc2 1.51 % + unlink_chunk 1.42 % + malloc_consolidate 3.63 % + drop_in_place::Bucket 1.66 % + drop_in_place::Core 0.74 % + memmove 0.71 % ≈ 21.3 %`, plus `IndexMap::clone 4.29 %` directly. Excluding bench scaffolding the actual workload is ~26 % heap ops. |
| **`Ed25519Scheme::sign_raw` wrapper overhead is a flat 22 µs/call**       | **supports** | Criterion deltas at three payload sizes are 21.83 µs, 20.62 µs, 21.90 µs — flat to within ±1 µs across 64-byte to 4096-byte payloads. Confirms it's a per-call setup cost, not payload-scaled. Source confirms `SigningKey::from_bytes(secret_key)` runs every call at `crates/franken-node/src/crypto/schemes.rs:240`. |
| **`Ed25519Scheme::verify_raw` wrapper overhead is a flat 6 µs/call**       | **supports** | Criterion deltas 6.05, 5.74, 5.87 µs — same pattern. Confirms `VerifyingKey::from_bytes` per-call cost at `crates/franken-node/src/crypto/schemes.rs:252`. |
| **threshold_sig is dominated by Ed25519 verify, not user-code overhead**  | **supports** | perf: curve25519 field math (FieldElement51 Mul, pow2k, LookupTable, EdwardsPoint Add, FieldElement2625x4 AVX2) totals ≈ 50 % of cycles; `frankenengine_node::security::threshold_sig::verify_threshold` itself is **0.63 %**. The 10 % preparsed-keys win is essentially the entire user-code lever. |
| **cuckoo_revocation insertion has a load-factor cliff between 10 k and 50 k** | **supports** | `insert/10 k = 1.667 ms` (cuckoo) vs `2.469 ms` (BTree) — cuckoo wins by 1.48×. `insert/50 k = 24.78 ms` (cuckoo) vs `13.47 ms` (BTree) — BTree wins by 1.84×. The slope changes sign between 10 k and 50 k, classic eviction-chain symptom. |
| **`replay_bundle_event_size::streaming_counter` is faster than `vec_len`** | **supports** | 1.85× across all three sizes (small/medium/large). Bench already documents the win — implementation already uses streaming, so this is a regression-guard finding, not a new lever. |
| **bench scaffolding adds 25-30 % overhead at the top of every flame**      | **supports** | `__ieee754_exp_fma + rayon::iter::plumbing::bridge_producer_consumer + rayon_core registry steal` collectively claim 25-30 % of cycles in *every* perf profile (trust_card_canonical 36 %, threshold_sig 32 %, crypto_scheme 34 %). This is Criterion's bootstrap-resampling estimator computing CIs in parallel via rayon's work-stealing. Must be excluded from user-code reasoning. |
| **`replay_bundle_gzip/no_compression_fallback` is real I/O**               | rejects   | 635 picoseconds at all event sizes ⇒ measuring a trivial branch (compression feature off in this build), not gzip work. Re-enable with `--features compression` for round 2 if compression behavior is the question. |
| **trust_card "optimized" path on the bench is the production fix**         | rejects   | Saves only 4-6 % because BTreeSet → Vec+sort is not the dominant cost. The 95 % of time spent in subtree clone is still there. Production fix must be structural (sort+stream, not clone). |

## Hypotheses raised this round, deferred to round 2

| Candidate                                                                   | Why deferred |
|------------------------------------------------------------------------------|--------------|
| `observability::evidence_ledger` append/replay-detection throughput          | bench file not registered as `[[bench]]`; static read flags `Sha256::new()` per call + O(N) ct_eq scan as candidates |
| `dgis::contagion_simulator::step()` per-tick rebuild of `build_in_edges(graph)` + `BTreeSet::clone()` | no dedicated bench; static read flags `crates/franken-node/src/dgis/contagion_simulator.rs:247-250` |
| `control_plane::fleet_transport` recursive `format!()` in path construction | bench lives under `tests/perf/control_plane_overhead_gate.rs` (work-unit gate, not wall-time bench); needs a Criterion harness |
| `vef::proof_generator` per-proof Sha256 rebuild + `format!("sha256:{}", hex::encode(...))` | covered by existing `proof_verifier_gate_bench` (single case only); needs scale sweep |
| `migration` tree-sitter parsing on real JS/TS corpora                       | only `migrate_cli_e2e` end-to-end test exists; needs a corpus-driven microbench |
| **batched verification** with `ed25519_dalek::verify_batch` for threshold_sig | structural change beyond profile-time scope; flag for the optimisation skill |

## Confirmation summary

- **`trust_card_canonical` deep-clone** is the surprise headline of the
  round. Confirmed by three independent signals: wall-time scaling
  (Θ(W^N × N)), heaptrack alloc count (21.5 M allocs / 63 s), and perf
  flat profile (≈ 26 % cycles in heap ops). All three triangulate on
  the same root cause.
- **`Ed25519Scheme` wrapper overhead** confirmed by per-payload-size
  delta being flat (within ±1 µs across a 64× payload size range).
  Triangulation: bench deltas, source inspection, and the absence of
  the wrapper symbol in flat-profile (the work is absorbed into
  dalek's setup code).
- **threshold_sig** is *not* a user-code lever — confirmed by 0.6 %
  cycles in `verify_threshold` and 50 % in dalek field math. The +10 %
  preparsed-keys path is the single available win; anything larger
  needs `verify_batch`.
