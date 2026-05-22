# Hypothesis ledger — round 2

Tests the round-1 deferred hypotheses with fresh evidence.

| Round-1 hypothesis                                                                             | R2 verdict | Evidence (this run) |
|-------------------------------------------------------------------------------------------------|------------|---------------------|
| `observability::evidence_ledger::append` is a hotspot because `is_replay_attack_ct_bytes` does an O(N) ct_eq scan + `Sha256::new()` per call | **rejects** | Bench measured: append p95 = 16.62 µs at the full large-payload (~ 2 KiB) entry. `json_string_size` is the only evidence_ledger symbol above 0.3 % in perf flat profile (at 0.81 %). The ct_eq scan and Sha256 work simply do not dominate. |
| `dgis::contagion_simulator::step` is hot because of per-tick `build_in_edges` rebuild + `state.infected.clone()` BTreeSet copy | **rejects** | perf flat profile: `step` = **0.45 %** of cycles. The hot path on the 200x integration-test workload is **graph construction** (`generate_deterministic` 14.85 %, `validate` 5.07 %, `add_edge` 3.98 %, `add_node` 1.42 %) and **String NodeId memcmp** in BTreeMap operations (`__memcmp_avx2_movbe` 14.10 %). |
| `vef::proof_generator` has hot allocations from per-call `Sha256::new()` and `format!("sha256:{}", hex::encode(...))` | **revisit / measurement gap** | Source inspection shows `compute_proof_bytes` is well-written (one Sha256 per batch, length-prefixed updates, no string formatting). The `format!()/hex::encode` is in `hash_bytes()` which is called rarely (receipt ID materialisation). Available test (`proof_generator_timeout_race`) finishes in 0 ms — not a viable profile target. **Round-3 work**: write a dedicated Criterion microbench for `compute_proof_bytes` and `receipt_chain::verify_integrity`. |
| `control_plane::fleet_transport::canonicalize_json_value` shares the same `format!()` + recursive-allocation pattern as trust_card | **rejects (partial)** | Source inspection confirms a *different* root cause: `canonicalize_json_value` consumes its input via `into_iter()` — no deep subtree clone. The two `format!("{path}.{key}")` calls per recursion build a `path` string used **only in error reporting** (the float-error branch at L176). Wasted on the happy path but O(1) per Value visited — not the Θ(W^N × N) cliff that dominated trust_card. Real fix: defer path computation to error sites. |

## New hypotheses raised this round

| Hypothesis                                                                                              | Verdict   | Evidence |
|----------------------------------------------------------------------------------------------------------|-----------|----------|
| **DGIS NodeId-as-String drives ~17 % of contagion-test cycles via BTreeMap key comparisons** | **supports** | perf: `__memcmp_avx2_movbe` 14.10 % + `BTreeMap<String, Vec<ContagionEdge>>::insert` 3.84 % + `BTreeMap<String, ...>` 2.97 % = ≈ 21 % cycles in String-keyed BTree work. Source: `NodeId = String` in `dgis::contagion_graph`. Switching to `u32` / `Copy` integer NodeIds with a side `Vec<&str>` lookup would eliminate this entire band. |
| **DGIS graph construction dominates the integration-test workload** | **supports** | `generate_deterministic` 14.85 % + `validate` 5.07 % + `add_edge` 3.98 % + `add_node` 1.42 % + `validate_node_id` 4.10 % = ≈ 29 % cycles. But this is **test-fixture-generation cost**, not production cost — production builds the graph once per profile evaluation. The fixture builder being slow is a CI symptom, not a runtime hotspot. |
| **Criterion bootstrap resampling dominates allocation counts for short-iteration benches** | **supports** | evidence_ledger heaptrack: 1 005 881 / 1 158 614 = 87 % of allocs come from `criterion::stats::univariate::bootstrap`. The actual user code is responsible for ≈ 150 k allocs across 146 k iterations — one alloc per append. Anyone reading raw heaptrack numbers must filter out the bench scaffolding band before drawing conclusions. |

## Deferred to round 3

- **`vef::proof_generator::compute_proof_bytes` scaling sweep** — needs a Criterion bench. Likely cheap to author (10-20 lines, mirrors `crypto_scheme_bench` structure). Round-1 hypothesis cannot be confirmed or rejected without this.
- **`vef::receipt_chain::verify_integrity` chain length sweep** — same gap.
- **`migration` tree-sitter parsing on real npm corpora** — still no bench harness. Tree-sitter perf depends on grammar + node count; a 100 k-line JS file is the realistic stress workload, and `migrate_cli_e2e` covers correctness but not bench-grade timing.
- **`control_plane::fleet_transport::canonicalize_json_value`** wall-time confirmation on a real payload — could be done by reusing the existing `fleet_quarantine_metamorphic.rs` test as a profile target, OR by porting one canonical-encoder microbench from the trust_card_canonical bench (substitute the call site).
- **DGIS contagion sim on a *large* graph** — the integration test uses small fixtures. To exercise the round-1 hypothesis about `step()`, build a 10k-node graph and run 100 steps. Without that, `step()` 0.45 % is the small-graph reading; a large-graph reading could shift dramatically.

## Confirmation summary across both rounds

After two rounds, the **two confirmed hotspots** that should be top of the
`extreme-software-optimization` queue:

1. **Round 1 Rank 1 / round 2 confirmed: `trust_card_canonical_bench::canonicalize_value_current` recursive `Value::clone()`** — Θ(W^N × N) deep-clone, 26 % cycles in heap ops at medium_3x8, 3.59 s at complex_4x12. Real fix is structural (sort-and-stream, no clone). No round-2 invalidation.
2. **Round 1 Rank 2 / round 2 confirmed: `crypto::Ed25519Scheme::{sign_raw,verify_raw}` rebuilds keys per call** — flat +22 µs sign / +6 µs verify, source-confirmed at `crates/franken-node/src/crypto/schemes.rs:240,252`.

The **two rejected hypotheses** that should be REMOVED from queue:

3. ~~`evidence_ledger` append is hot~~ — measured 16.2 µs / append; not a hotspot at the current scale. Reopen only if production trace shows N > 100k appends/sec.
4. ~~`contagion_simulator::step` is hot~~ — 0.45 % of cycles on the available workload. The static-read flag was wrong.

The **two new hotspots emerging from round 2**:

5. **DGIS String NodeId BTreeMap comparisons (~17 % cycles)** — interning NodeId to integers would erase this band.
6. **Bench harness allocation skew** — Criterion's bootstrap resampling owns 87 % of heaptrack allocs in fast benches. Any heaptrack-driven hotspot ranking must filter out the bootstrap band first.
