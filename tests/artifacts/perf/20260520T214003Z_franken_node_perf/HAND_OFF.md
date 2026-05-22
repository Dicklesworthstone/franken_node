# Hand-off — `extreme-software-optimization`

> Profile complete: `franken_node` workspace — run-id `20260520T214003Z_franken_node_perf`

## Top-3 hotspots (ranked)

| # | Location                                                                                  | Metric (baseline)                               | Category   |
|---|-------------------------------------------------------------------------------------------|------------------------------------------------:|------------|
| 1 | `trust_card_canonical_bench::canonicalize_value_current` — recursive `Value::clone()`     | **3 591 ms** at `current/complex_4x12`; 21.5 M allocs / 63 s; 430 MiB peak heap; 26 % cycles in heap ops | CPU+alloc |
| 2 | `crypto::Ed25519Scheme::{sign_raw,verify_raw}` — re-derives keys per call                 | **+22 µs / sign, +6 µs / verify** flat overhead vs direct dalek (1.91× sign at 64 B) | CPU |
| 3 | `security::threshold_sig::verify_threshold` — re-hex-decodes + reparses VerifyingKey per signer per call | **1.78 ms → 1.61 ms** (−10 %) at 32 signers when preparsed | CPU |

Full ranked table with evidence: `hotspot_table.md`. Five additional
rows (cuckoo insert cliff, `Vec::len` vs streaming counter,
proof_verifier_gate single-point, evidence_ledger gap, dgis static
read) are documented there.

## Supported hypotheses

- **Allocator dominates trust_card_canonical.** Triangulated by
  wall-time Θ(W^N × N), heaptrack 21.5 M allocs in 63 s, and perf flat
  profile with ≈ 26 % cycles in heap ops. The bench's "optimized"
  variant only saves 4-6 % because it does not touch the dominant
  recursive `Value::clone()` of the subtree.
- **Ed25519Scheme wrapper rebuilds keys per call.** Flat +22 µs / sign
  and +6 µs / verify across 64-byte to 4096-byte payloads confirms a
  per-call setup cost. Source at
  `crates/franken-node/src/crypto/schemes.rs:240,252`.
- **threshold_sig is bottlenecked on dalek field math, not user code.**
  50 % of cycles in `curve25519_dalek::backend::serial::u64::field::*`
  and `backend::vector::avx2::*`; user code `verify_threshold` is
  0.63 %. The 10 % preparsed-keys win is the only available
  user-level lever.

## Rejected hypotheses

- "trust_card optimized path on the bench is the production fix" — saves
  4-6 % only; the dominant subtree-clone is untouched.
- "replay_bundle_gzip/no_compression_fallback is real I/O" — 635 ps at
  every size is a trivial-branch measurement under `compression`
  feature off.

## Deferred / round-2

- `observability::evidence_ledger` append + replay-detection — bench
  file exists but is not registered as `[[bench]]` in
  `crates/franken-node/Cargo.toml`. Static read identifies
  `is_replay_attack_ct_bytes()` (L1237–1260) as a likely hotspot.
- `dgis::contagion_simulator::step()` per-tick `build_in_edges` rebuild
  + `BTreeSet::clone` (`crates/franken-node/src/dgis/contagion_simulator.rs:247-250`).
- `control_plane::fleet_transport` recursive `format!()` for path
  construction in `canonicalize_json_value` — same structural pattern
  as trust_card hotspot, no Criterion harness yet.
- `vef::proof_generator` per-proof Sha256 rebuild +
  `format!("sha256:{}", hex::encode(...))`.
- batched verification with `ed25519_dalek::verify_batch` for
  threshold_sig (structural API change).

## Scoring inputs for `extreme-software-optimization`

The next skill scores **Impact × Confidence / Effort ≥ 2.0**. Suggested
starting values:

| Rank | Impact | Confidence | Effort | Score | Notes |
|------|-------:|-----------:|-------:|------:|------|
| 1 (trust_card deep-clone) | 5  | 5 | 4 | 6.3 | Restructure recursive canonicalisation to sorted-view + streamed write. Largest absolute win but invasive change. **Apples-to-apples gate:** prove byte-identical canonical output via existing trust-card golden tests under `tests/golden/`. |
| 2 (Ed25519Scheme key cache) | 5 | 5 | 2 | **12.5** | Introduce preparsed-handle pattern mirroring `PreparsedThresholdConfig`. **Highest ROI.** Trait surface stays; only callers that opt in lose the per-call rebuild. |
| 3 (threshold_sig preparsed) | 3 | 5 | 1 | **15.0** | Already implemented in the bench as a proxy; promote to real `verify_threshold` callers. Lowest effort. |
| 4 (cuckoo insert cliff) | 2 | 5 | 1 | 10.0 | Pure policy decision; measure production N and switch backend if needed. No code change. |
| 5 (`vec_len` → streaming_counter) | 1 | 5 | 1 | 5.0 | Single-call-site replacement; bench already proves it. |

(Impact 1–5; Confidence 1–5; Effort 1–5 where 5 = hardest. Score =
Impact × Confidence / Effort.)

## Golden / equivalence proofs the next skill must preserve

- **Trust card canonical output is byte-identical** before and after
  any change. Verified by `tests/golden/` snapshots under
  `crates/franken-node/tests/` (trust card export goldens) and the
  HMAC-signed `card_hash`/`registry_signature` fields in
  `supply_chain::trust_card::TrustCard` — any change in the canonical
  encoder breaks every existing trust card on disk.
- **Ed25519 signature bytes are bit-for-bit identical**. Verified by
  the existing test at `crates/franken-node/src/crypto/schemes.rs:356-369`
  (`Ed25519Scheme::sign_raw` ⟶ direct dalek round-trip).
- **threshold_sig quorum decisions are unchanged** under
  preparsed-key caching. Verified by the bench's parity check
  (`current` and `preparsed_keys` paths verify the same artifact and
  must return identical pass/fail).
- **No new `unsafe` code.** `#![forbid(unsafe_code)]` is in both
  `lib.rs` and `main.rs`; any optimization that needs `unsafe` is
  outside scope.

## Variance envelope for re-baseline

Same-host re-run after a change must land within **±10 %** of these
p95s on the corresponding bench. >20 % drift or three consecutive
>10 % drifts means the host was contaminated — retry after a quiet
window. The host had 5+ concurrent rch builds during this baseline
(see `fingerprint.json` notes); a quieter host should tighten the CI
bounds.

## Re-baseline command

```bash
# Re-add the release-perf profile (concurrent agents may have removed it)
# at workspace root Cargo.toml — see fingerprint.json build_profile fields.

RUSTFLAGS="-C force-frame-pointers=yes" \
    rch exec -- cargo build --profile release-perf -p frankenengine-node --benches

# Then run the same scenario the change targets, e.g.:
./target/release-perf/deps/trust_card_canonical_bench-<hash> --bench \
    --sample-size 30 --measurement-time 3 --warm-up-time 1 \
    "current/medium_3x8"
```

## Artifact inventory (this directory)

```
20260520T214003Z_franken_node_perf/
├── DEFINE.md                            # 10 scenarios + budgets + scope
├── INSTRUMENTATION.md                   # what's there, what's missing, plan for next skill
├── BASELINE.md                          # p50/p95/p99 across all 7 ran benches
├── HAND_OFF.md                          # THIS FILE
├── fingerprint.json                     # host + toolchain + build profile
├── tuning.json                          # kernel knobs applied + revert block
├── golden_checksums.txt                 # sha256 of each bench binary
├── hotspot_table.md                     # ranked 8-row table, evidence-cited
├── scaling_law.md                       # 5 scale axes with verdicts
├── hypothesis.md                        # pre-flame + post-flame ledger
├── criterion_raw/
│   ├── crypto_scheme.txt
│   ├── cuckoo_revocation.txt
│   ├── proof_verifier_gate.txt
│   ├── replay_bundle_gzip.txt
│   ├── threshold_sig_verify.txt
│   └── trust_card_canonical.txt
└── profiles/
    ├── trust_card_canonical.samply.json        # 3.0 MB samply (Firefox Profiler format)
    ├── trust_card_canonical.perf.data          # 224 MB perf record, 28 272 samples
    ├── trust_card_canonical.perf.flat.txt      # extracted flat top-symbols
    ├── trust_card_canonical.heaptrack.zst      # 20 MB heaptrack alloc trace
    ├── trust_card_canonical.heaptrack.report.txt
    ├── threshold_sig_verify_32.samply.json     # 2.1 MB samply
    ├── threshold_sig_verify_32.perf.data       # 145 MB perf, 18 170 samples
    ├── threshold_sig_verify_32.perf.flat.txt
    ├── crypto_scheme_sign64.perf.data          # 131 MB perf, 16 389 samples
    └── crypto_scheme_sign64.perf.flat.txt
```

## Summary statement (verbatim for the user)

```
Profile complete: franken_node workspace — run-id 20260520T214003Z_franken_node_perf

Baseline (Criterion suite, release-perf):
  trust_card_canonical current/complex_4x12 = 3 591 ms  (no prior budget; recommend ≤ 1 800 ms after Rank-1 fix)
  ed25519_scheme_sign_raw/64                = 45.69 µs  (vs dalek_direct 23.86 µs; gap is the budget target)
  threshold_sig_verify current/32           = 1.78 ms   (preparsed_keys at 1.61 ms is the achievable budget)

Top 3 hotspots:
  1. trust_card_canonical::canonicalize_value_current — recursive Value::clone() — CPU+alloc
     (3.59 s wall, 21.5 M allocs/63 s, 26 % cycles in heap ops)
  2. crypto::Ed25519Scheme::{sign_raw,verify_raw} — re-derives keys per call — CPU
     (+22 µs/sign, +6 µs/verify flat regardless of payload size)
  3. security::threshold_sig::verify_threshold — re-parses VerifyingKey per signer per call — CPU
     (10 % win available via preparsed keys)

Supported hypotheses:
  - Allocator dominates trust_card_canonical (triangulated by wall-time + heaptrack + perf)
  - Ed25519Scheme wrapper rebuilds keys per call (flat +22 µs / +6 µs)
  - threshold_sig bottlenecked on dalek field math, not user code (50 % vs 0.6 %)

Rejected hypotheses:
  - trust_card "optimized" path on the bench is the production fix (saves only 4-6 %)
  - replay_bundle_gzip/no_compression_fallback measures real compression (635 ps = trivial branch)

Ready for extreme-software-optimization to score
(Impact × Confidence / Effort ≥ 2.0). Suggested starting scores:
  Rank 3 (threshold_sig preparsed)       — 15.0  (lowest-effort win, do first)
  Rank 2 (Ed25519Scheme key cache)        — 12.5
  Rank 4 (cuckoo insert cliff policy)     — 10.0  (zero code change)
  Rank 1 (trust_card deep-clone)          —  6.3  (highest absolute win but invasive)
  Rank 5 (vec_len → streaming_counter)    —  5.0

Artifacts: tests/artifacts/perf/20260520T214003Z_franken_node_perf/
```
