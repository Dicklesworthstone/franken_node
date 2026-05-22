# Phase 4 — Instrumentation review

This phase doesn't *add* instrumentation (the skill stops at hand-off).
It catalogs **what's already in the source**, what's missing, and what
the next skill should add before the next round.

## What's already there

- **Event-style `tracing`** in 24 source files. Examples in
  `observability::evidence_ledger`:
  ```rust
  tracing::info!(event_code = event_codes::LEDGER_CAPACITY_WARN, …)
  tracing::warn!(event_code = event_codes::LEDGER_CAPACITY_WARN, …)
  tracing::debug!(event_code = event_codes::LEDGER_APPEND, …)
  ```
  Every log carries a stable `event_code` field (the `EVD-LEDGER-*`,
  `FN-AE-*`, `PRF-*`, … families documented in README.md). Good for
  SIEM, **not** good for perf attribution — there is no time captured,
  no duration, no histogram.

- **`PerformanceBudgetGuard`** at
  `crates/franken-node/src/policy/perf_budget_guard.rs` (2 338 LOC) and
  `crates/franken-node/src/connector/perf_budget_guard.rs` (2 345 LOC).
  These are *consumers* of measurements (gates that pass / block based
  on submitted `p95_us` / `p99_us` / `cold_start_ms` numbers), not
  collectors. They define the contract for what a future perf collector
  must emit.

- **Smoke-budget contract** in
  `crates/franken-node/tests/hot_path_perf_budget_contract.rs` +
  `artifacts/performance_budgets/bd-ncwlf_hot_path_budget_evidence.json`.
  Documents 4 hot paths (`telemetry_bridge.persistence_batch`,
  `fleet_transport.read_snapshot`, `evidence_ledger.len_snapshot`,
  `frankensqlite_adapter.write_event`) with before/after work-unit
  counts. Encodes intent, not wall-time.

## What's missing for proper attribution

- **No `#[tracing::instrument]` spans** anywhere in `src/` (count = 0).
  Without spans you can't roll up `cumulative_us × count` per call
  site.
- **No HDR histograms** (`hdrhistogram` not referenced in `src/`).
- **No `perf.profile.*` structured-log contract** in `src/`. The
  contract from the skill (`perf.profile.run_start`,
  `perf.profile.span_summary`, `perf.profile.hypothesis_evaluated`) is
  not implemented.
- **No sentinel `_profile_*` no-op functions** for flame-graph
  attribution. The pipeline stages in `replay::time_travel_engine` and
  `tools::replay_bundle` are inlined by LLVM at opt-level=3 with
  `lto=thin`, so the flame will not show them as distinct bars.

## What the next skill should add (Phase-1 work for round 2)

Add these **behind an env flag** (`FRANKEN_NODE_PROFILE=1`) so production
pays nothing:

1. **Sentinel frames** in the four highest-leverage hot paths:
   ```rust
   #[inline(never)]
   fn _profile_evidence_ledger_validate_append() { std::hint::black_box(()); }
   #[inline(never)]
   fn _profile_canonical_serializer_recurse() { std::hint::black_box(()); }
   #[inline(never)]
   fn _profile_trust_card_canonicalize() { std::hint::black_box(()); }
   #[inline(never)]
   fn _profile_threshold_sig_verify() { std::hint::black_box(()); }
   ```
2. **HDR histograms** on the four budget-tracked hot paths (one
   `Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)` per hot path,
   flushed periodically as `perf.profile.span_summary` events with
   `cumulative_us, count, p50_us, p95_us`).
3. **`#[tracing::instrument(skip_all, fields(...))]`** on `compute_digest`,
   `canonicalize_schema_value`, `verify_threshold`, `EvidenceLedger::append`,
   `WorkflowTrace::compute_digest_bytes` — at minimum.
4. **Structured `perf.profile.run_start` / `run_complete`** wrappers in
   each bench main so flamegraph captures land in the same JSONL stream
   as the histograms.

## Why this round didn't add them

The skill explicitly says: *"This skill stops at the hotspot table —
hand to extreme-software-optimization."* The instrumentation list above
is part of the hand-off package; the next skill applies it under "one
lever per commit" discipline.

## Static-read hot-path hypotheses (pre-flame)

Three concrete code-level patterns observed while waiting for the
release-perf build (from the deep-read agent's report; quoted below
verbatim):

> 1. **EVIDENCE_LEDGER `validate_append()` — Replay detection hash scan.**
>    `is_replay_attack_ct_bytes()` (L1237–1260) dominates under high
>    append throughput due to O(N) constant-time scan over the VecDeque
>    of seen signatures, compounded by `replay_key_hash()` recreating
>    `Sha256` for prefilter on every call. Two Sha256 inits per append
>    (prefilter + optional ct_scan) + up to 8 192 ct_eq comparisons if
>    prefilter collision occurs.
>
> 2. **CANONICAL_SERIALIZER `write_canonical_value()` — Nested object
>    allocation.** Hot path `serialize_value()` (L484) →
>    `canonicalize_schema_value()` (L756) → recursive
>    `write_canonical_value()` (L855) allocates `Vec<_>` for every
>    nested object's entries (L900–901) for sorting, even for
>    single-level payloads; no pre-allocation or reuse of sort buffer.
>
> 3. **FLEET_TRANSPORT `canonicalize_json_value()` — Recursive String
>    formatting.** `format!()` macro called once per array element and
>    object key during canonicalization recursion (L159, L170);
>    allocation cost compounds with deep nesting, and no opportunity
>    for path interning or reuse.

The trust_card_canonical bench (3.59 s on `complex_4x12`) is the
**empirical confirmation** of hypothesis #2: with depth 4 width 12, the
recursive `val.clone()` inside `canonicalize_value_current` deep-copies
the entire subtree at every level, producing Θ(W^N × N) work. The
"optimized" path in the bench only addresses the BTreeSet → Vec+sort
key collection (~4-6 % saved); it leaves the dominant subtree-clone
untouched.

## Modules that already optimise allocations (do not over-correct)

- **`security::threshold_sig::SigningMessage`** — stack buffer
  (384 bytes) for common case, heap fallback for oversized
  identifiers; `Vec::with_capacity()` with correct hint.
- **`connector::canonical_serializer`** — `Vec::with_capacity` using
  `min_object_capacity` from schema definition (this is the *bench*
  optimized path, not the *runtime* default path used by trust cards).
- **`security::constant_time::ct_eq_bytes`** — length-first short-
  circuit before constant-time comparison (correct DoS posture, no
  perf cost).
- **`replay_bundle_gzip_bench`** documents that `ByteCounter` streaming
  is 1.85× faster than `Vec::len` after `to_vec` — implementation
  already prefers the streaming form.

These are reference patterns for the optimization round, not targets.
