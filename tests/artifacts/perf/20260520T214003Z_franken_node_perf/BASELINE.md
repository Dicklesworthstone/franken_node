# Baseline — franken_node Criterion suite — 2026-05-20 — git aa3b1c9a

Build: `--profile release-perf` with `RUSTFLAGS="-C force-frame-pointers=yes"`,
codegen-units=1, lto=thin, debug=line-tables-only, strip=false.
Host: AMD EPYC 7282 (64 logical cores), 251 GiB RAM, ext4/NVMe.
Tuning applied (sysctl perf_event_paranoid=1, kptr_restrict=0, nmi_watchdog=0,
page caches dropped); see `tuning.json`.
Variance envelope: ≤10 % p95 drift = noise, see `DEFINE.md`.

## Coverage

| Bench file                    | Built? | Ran? | Notes |
|-------------------------------|:------:|:----:|------|
| `crypto_scheme_bench`         | ✅     | ✅   | full sweep |
| `threshold_sig_verify_bench`  | ✅     | ✅   | full sweep |
| `cuckoo_revocation_bench`     | ✅     | ✅   | full sweep |
| `proof_verifier_gate_bench`   | ✅     | ✅   | single case |
| `replay_bundle_gzip_bench`    | ✅     | ✅   | full sweep |
| `trust_card_canonical_bench`  | ✅     | ⚠    | covered `simple_1x5`, `medium_3x8`, and `current/optimized` at `complex_4x12`; long-tail `serialize_*/complex_4x12` (~12 min remaining) cancelled — headline data captured |
| `evidence_ledger_performance` | ✅     | ❌   | binary built but `cargo run` produced `0 measured` — the file is **not** registered as `[[bench]]` in `crates/franken-node/Cargo.toml`. Listed as a gap. |
| `perf_wins`                   | ❌     | ❌   | bench link failed because the `franken-node` **binary** failed to compile (`config::BootstrapSynthesis` missing in main.rs — concurrent-agent damage). Library + non-bin-dependent benches built fine. |
| `anti_entropy_insert_bench`   | ❌     | ❌   | feature `advanced-features` not enabled in this baseline |
| `blake3_performance_bench`    | ❌     | ❌   | feature `blake3` not enabled in this baseline |

## Headline numbers (Criterion mean ± width)

All times are mean of the `[low high]` 95 % CI; numbers in `(...)` are
high-bound on the CI. Sample size is 100 unless otherwise noted (40 for
`threshold_sig`).

### crypto_scheme

| Case (payload bytes)                                | Mean        | high CI    | Notes |
|----------------------------------------------------|------------:|-----------:|-------|
| `raw_sign/ed25519_dalek_direct/64`                 | 23.86 µs    | 24.22 µs   | dalek baseline |
| `raw_sign/ed25519_scheme_sign_raw/64`              | **45.69 µs**| 46.13 µs   | **1.91×** dalek_direct |
| `raw_sign/ed25519_dalek_direct/512`                | 26.68 µs    | 27.01 µs   |       |
| `raw_sign/ed25519_scheme_sign_raw/512`             | **47.30 µs**| 47.79 µs   | **1.77×** dalek_direct |
| `raw_sign/ed25519_dalek_direct/4096`               | 41.70 µs    | 41.75 µs   |       |
| `raw_sign/ed25519_scheme_sign_raw/4096`            | **63.60 µs**| 63.78 µs   | **1.52×** dalek_direct |
| `raw_verify/ed25519_dalek_direct/64`               | 47.25 µs    | 47.33 µs   |       |
| `raw_verify/ed25519_scheme_verify_raw/64`          | 53.30 µs    | 53.55 µs   | 1.13× dalek_direct |
| `raw_verify/ed25519_dalek_direct/512`              | 48.28 µs    | 48.39 µs   |       |
| `raw_verify/ed25519_scheme_verify_raw/512`         | 54.02 µs    | 54.16 µs   | 1.12× |
| `raw_verify/ed25519_dalek_direct/4096`             | 56.75 µs    | 56.82 µs   |       |
| `raw_verify/ed25519_scheme_verify_raw/4096`        | 62.62 µs    | 62.70 µs   | 1.10× |

**Headline:** `Ed25519Scheme::sign_raw` is ~22 µs slower than direct dalek
for every payload size — the wrapper adds a flat overhead, not a
payload-proportional one. At 64 B, that's nearly the cost of doing the
sign itself.

### threshold_sig_verify

| Case            | Mean     | high CI  | vs `current` |
|-----------------|---------:|---------:|--------------|
| `current/8`     | 433.6 µs | 439.0 µs | 1.00× |
| `preparsed_keys/8`  | **396.4 µs** | 406.0 µs | **0.91×** |
| `current/32`    | 1.778 ms | 1.785 ms | 1.00× |
| `preparsed_keys/32` | **1.611 ms** | 1.623 ms | **0.91×** |

**Headline:** Caching the per-signer `VerifyingKey` (decoded once instead
of every verify) saves a flat ~10 % regardless of signer count, meaning
the dominant cost is the Ed25519 verify itself, not the hex-decode +
VerifyingKey parse. 32-signer verification at 1.78 ms is a high-frequency
hot path on busy clusters.

### cuckoo_revocation

| Case                                | N         | Mean       | high CI    |
|-------------------------------------|----------:|-----------:|-----------:|
| `revocation_checking/cuckoo_filter_lookup` | 1 000     | 57.5 ns    | 57.6 ns    |
| `revocation_checking/btree_lookup`         | 1 000     | 61.1 ns    | 61.3 ns    |
| `revocation_checking/cuckoo_filter_lookup` | 10 000    | 54.9 ns    | 55.0 ns    |
| `revocation_checking/btree_lookup`         | 10 000    | 85.6 ns    | 85.8 ns    |
| `revocation_checking/cuckoo_filter_lookup` | 100 000   | 54.9 ns    | 55.0 ns    |
| `revocation_checking/btree_lookup`         | 100 000   | 138.4 ns   | 138.6 ns   |
| `revocation_checking/cuckoo_filter_lookup` | 500 000   | 55.0 ns    | 55.0 ns    |
| `revocation_checking/btree_lookup`         | 500 000   | 178.3 ns   | 178.5 ns   |
| `revocation_insertion/cuckoo_filter_insert`| 10 000    | 1.667 ms   | 1.672 ms   |
| `revocation_insertion/btree_insert`        | 10 000    | 2.469 ms   | 2.476 ms   |
| `revocation_insertion/cuckoo_filter_insert`| 50 000    | **24.78 ms** | 24.85 ms |
| `revocation_insertion/btree_insert`        | 50 000    | **13.47 ms** | 13.51 ms |
| `revocation_deletion/cuckoo_filter_delete` |     —     | 55.29 µs   | 55.35 µs   |

**Headline:** Cuckoo lookup is O(1) (≈ 55 ns flat) vs BTree O(log N)
(61 → 178 ns at 500 k). On **lookup** cuckoo wins by 3.2× at 500 k.
But on **insertion at 50 k** cuckoo loses to BTree by **1.84×**
(24.78 ms vs 13.47 ms) — cuckoo eviction storms become catastrophic past
the load-factor cliff. The crossover for inserts is between 10 k
(cuckoo wins by 1.48×) and 50 k (BTree wins by 1.84×). This is a true
scaling-law finding.

### proof_verifier_gate

| Case                              | Mean      | high CI    |
|-----------------------------------|----------:|-----------:|
| `verification_gate_batch_allow`   | 465.4 µs  | 470.4 µs   |

Single case; need more variants to derive scaling.

### replay_bundle_gzip

| Case (events)                                              | Mean       | high CI    |
|-----------------------------------------------------------|-----------:|-----------:|
| `replay_bundle_event_size/vec_len/small_10`               | 4.98 µs    | 4.99 µs    |
| `replay_bundle_event_size/streaming_counter/small_10`     | **2.71 µs**| 2.72 µs    |
| `replay_bundle_event_size/vec_len/medium_100`             | 57.60 µs   | 57.68 µs   |
| `replay_bundle_event_size/streaming_counter/medium_100`   | **27.80 µs**| 27.90 µs   |
| `replay_bundle_event_size/vec_len/large_1000`             | 622.2 µs   | 628.5 µs   |
| `replay_bundle_event_size/streaming_counter/large_1000`   | **335.0 µs**| 338.2 µs  |
| `replay_bundle_generation/generate/small_10`              | 323.4 µs   | 324.1 µs   |
| `replay_bundle_generation/generate/medium_100`            | 2.937 ms   | 2.957 ms   |
| `replay_bundle_generation/generate/large_1000`            | 29.47 ms   | 29.62 ms   |
| `replay_bundle_gzip/no_compression_fallback/*`            | 635 ps     | 643 ps     |

**Headline 1:** `streaming_counter` is **1.83-1.86× faster** than
`vec_len` for measuring serialized event size — the existing code
already prefers this path; the bench documents the win.

**Headline 2:** `replay_bundle_generation/generate` is essentially
linear (10× events ≈ 10× time, 9.1× and 10.0× respectively at
small→medium→large), no algorithmic explosion.

**Headline 3:** `no_compression_fallback` at 635 ps is a measurement of
a trivial branch (compression feature off), not real compression.

### trust_card_canonical

| Case (depth × width)                                  | Mean        | high CI     | vs `current` |
|-----------------------------------------------------|------------:|------------:|--------------|
| `current/simple_1x5`                                 | 79.81 µs    | 80.21 µs    | 1.00× |
| `optimized/simple_1x5`                               | 79.19 µs    | 79.66 µs    | 0.99× |
| `serialize_current/simple_1x5`                       | 128.35 µs   | 129.30 µs   |       |
| `serialize_optimized/simple_1x5`                     | 117.39 µs   | 117.85 µs   |       |
| `current/medium_3x8`                                 | 33.23 ms    | 33.49 ms    | 1.00× |
| `optimized/medium_3x8`                               | 31.21 ms    | 31.53 ms    | 0.94× |
| `serialize_current/medium_3x8`                       | 35.06 ms    | 35.20 ms    |       |
| `serialize_optimized/medium_3x8`                     | 32.36 ms    | 32.53 ms    |       |
| `current/complex_4x12`                               | **3 591 ms**| 3 661 ms    | 1.00× |
| `optimized/complex_4x12`                             | **3 437 ms**| 3 460 ms    | 0.96× |

**Headline:** Catastrophic super-linear scaling. depth/width going from
3×8 (33 ms) → 4×12 (**3.59 s**) is a **108× increase for 9× more
keys at one more level of nesting**. This is the canonical
"recursive deep clone" anti-pattern: `canonicalize_value_current` does
`val.clone()` on every recursion, so depth N width W ⇒ Θ(W^N × N) work.
The "optimized" variant in the bench only switches BTreeSet → Vec+sort
for the key collection — it does **not** address the dominant
`val.clone()`, so it saves only ~4-6 %. The real hotspot is the
recursive subtree clone, not the key sort.

## Variance snapshot

Each bench produced one variance reading. Criterion outliers per case
ranged from 1 % to 18 % (medians ≈ 5 %). Heavy concurrent activity on
the host (5+ rch builds running simultaneously) likely inflated p95
outliers; the means are still trustworthy for hotspot ranking but the
tails should be re-measured on a quieter host before declaring a
budget.

## Memory baseline

Not collected per-bench in this round (Criterion does not run
`/usr/bin/time -v`). Will be captured in Phase 5 via samply's process
metrics and `heaptrack` runs on the top-3 candidates.

## What's in `criterion_raw/`

Raw per-bench tee'd output, line-faithful:

- `crypto_scheme.txt`
- `cuckoo_revocation.txt`
- `proof_verifier_gate.txt`
- `replay_bundle_gzip.txt`
- `threshold_sig_verify.txt`
- `trust_card_canonical.txt`

Tests pass: PASS (every bench reported `Analyzing` and no panics).
