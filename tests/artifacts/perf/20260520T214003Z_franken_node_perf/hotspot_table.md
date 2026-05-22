# Hotspot table — `20260520T214003Z_franken_node_perf`

Ranked by **(impact share × confidence) / effort estimate**. Every row
cites an artifact in the same directory.

| Rank | Location                                                                                    | Metric                              | Value          | Category    | Evidence |
|-----:|---------------------------------------------------------------------------------------------|-------------------------------------|---------------:|-------------|----------|
| 1    | `trust_card_canonical_bench::canonicalize_value_current` — recursive `Value::clone()`        | wall-time at `current/complex_4x12` | **3 591 ms**   | CPU+alloc   | `criterion_raw/trust_card_canonical.txt`; heaptrack `peak_heap = 430 MiB`, **21 505 042 allocs / 63.8 s** (337 022 alloc/s); perf `_int_malloc 7.62 % + IndexMap::clone 4.29 % + free 2.82 % + memmove 0.71 % + drop_in_place 2.40 % ≈ 18-26 % cycles in heap` |
| 2    | `crypto::Ed25519Scheme::{sign_raw,verify_raw}` — re-derives `SigningKey`/`VerifyingKey` per call | wall-time delta vs direct dalek     | **+22 µs/call sign, +6 µs/call verify** (1.91× sign at 64 B) | CPU        | `criterion_raw/crypto_scheme.txt`: `ed25519_dalek_direct/64 = 23.86 µs` vs `ed25519_scheme_sign_raw/64 = 45.69 µs`; source confirms at `crates/franken-node/src/crypto/schemes.rs:232-243` — `SigningKey::from_bytes(secret_key)` and `VerifyingKey::from_bytes` rebuilt every call |
| 3    | `security::threshold_sig::verify_threshold` — re-hex-decodes + reparses each `VerifyingKey` per signer per call | wall-time @ 32 signers              | **1.78 ms (current) → 1.61 ms (preparsed)** | CPU         | `criterion_raw/threshold_sig_verify.txt`; perf shows curve25519 field math 50 %, user code 0.6 %; the **+10 % preparsed-keys win** is the cheap fix |
| 4    | `cuckoo_filter_insert` — eviction storm crossing the load-factor cliff between 10 k and 50 k entries | wall-time at 50 k inserts           | **24.78 ms** (vs BTree **13.47 ms** — 1.84× slower) | algorithmic | `criterion_raw/cuckoo_revocation.txt`; cuckoo wins lookup at every N, loses insert past ≈ 30 k |
| 5    | `replay_bundle_event_size::vec_len` — `Vec::len()` after `to_vec()` vs `streaming_counter` | wall-time at large_1000             | **622 µs vs 335 µs** (1.86× slower) | CPU+alloc   | `criterion_raw/replay_bundle_gzip.txt`; bench already documents the win — implementation should standardise on `streaming_counter` |
| 6    | `vef::proof_verifier_gate` (single case `verification_gate_batch_allow`)                    | wall-time                           | 465 µs        | CPU         | `criterion_raw/proof_verifier_gate.txt`; needs scale sweep to derive a budget |
| 7    | `observability::evidence_ledger` append path                                                 | (not measured this round)           | —              | —           | bench file present but **not registered** in `crates/franken-node/Cargo.toml` `[[bench]]` — round-2 work |
| 8    | `dgis::contagion_simulator::step()` — recomputes `build_in_edges(graph)` and clones the infected `BTreeSet` per tick | (not measured this round)          | —              | —           | static read flagged `crates/franken-node/src/dgis/contagion_simulator.rs:247-250`; no dedicated bench exists yet |

## Notes

**The bench scaffolding shows up at 25-30 % in every profile.** Criterion's
`__ieee754_exp_fma` + `rayon::iter::plumbing::bridge_producer_consumer`
+ `rayon_core::registry::WorkerThread::find_work` consistently
land at 25-30 % of samples across all three perf profiles. This is
**Criterion's bootstrap-resampling estimator** computing CIs in
parallel via rayon — not the function under test. Exclude that band
when reasoning about user-code costs.

**Rank 1 is dominant.** Heaptrack shows 21.5 M allocs in 63 s for a
**medium**-sized trust card; the workload is bottlenecked on the
allocator. The on-disk "optimized" bench variant (Vec+sort instead of
BTreeSet) saves only ~4-6 % because it leaves the dominant
`val.clone()` deep-copy of the entire IndexMap subtree at every
recursion level untouched. Real fix is structural — canonicalise
without cloning the inner `Value`s, e.g. iterate over a sorted view of
keys and stream the result through a writer.

**Rank 2 has the highest ROI.** A flat 22 µs / sign × every signed
artifact in the system is a real production cost. Direct fix: cache or
accept a pre-built `SigningKey` / `VerifyingKey`, matching the
threshold-sig pattern at rank 3. Estimated effort: 1-2 days of
trait-surface change; impact at most signing call sites is unequivocal.

**Rank 3 is already proven.** The bench shows the preparsed-keys win;
the codebase needs to plumb it through to production `verify_threshold`
sites. The remaining ~90 % of cost is dalek field math — irreducible
without algorithmic change (e.g. batched verification across signers,
which dalek supports via `verify_batch`).

**Rank 4 is a policy choice, not a code change.** Cuckoo's insert cost
crosses BTree past ~30 k entries. If the revocation frontier routinely
exceeds 30 k, switch to BTree for insert-heavy workloads. If most ops
are lookups, keep cuckoo. No code change needed — only a measurement
of real-world N and a decision.

**Rank 5 is a one-character fix.** Replace `Vec::len()` after `to_vec()`
with `ByteCounter` streaming. The pattern is already in the bench;
just propagate it.

**Ranks 6-8 are gaps in this round's coverage.** Round 2 priorities.

## Baseline Reuse Ledger

Caches present in the codebase that this round did not measure
directly:

| Cache                                         | Supported | Hit metric exposed? | Round-2 work |
|-----------------------------------------------|-----------|---------------------|--------------|
| `threshold_sig::PreparsedThresholdConfig`      | yes (bench-only proxy) | no                  | wire into `verify_threshold` real callers |
| `crypto::Ed25519Scheme` signing-key cache      | **no**    | n/a                 | introduce |
| `vef::proof_verifier_gate` precomputed gates   | unknown   | n/a                 | measure |
| `observability::evidence_ledger` replay-key prefilter | yes | yes (`prefilter_hits`, `prefilter_collisions` per docs) | dedicated bench |
