# Hotspot table — round 2 (deferred coverage)

This table covers **only the new findings from round 2**. The round-1
ranking (`tests/artifacts/perf/20260520T214003Z_franken_node_perf/hotspot_table.md`)
remains the canonical ranking for the four scenarios it measured. The
unified cross-round ranking is in `tests/artifacts/perf/HISTORY.md`.

| Rank | Location                                                                          | Metric                              | Value          | Category    | Evidence |
|-----:|-----------------------------------------------------------------------------------|-------------------------------------|---------------:|-------------|----------|
| R2-A | `dgis::contagion_graph` — String NodeIds drive BTreeMap operations and memcmp     | % cycles on dgis_contagion 200x loop | **≈ 17 %**     | CPU         | `profiles/dgis_contagion.perf.flat.txt`: `__memcmp_avx2_movbe 14.10 % + BTreeMap<String,Vec<Edge>>::insert 3.84 % + BTreeMap String ops 2.97 %`. Source: `NodeId = String` |
| R2-B | `dgis::contagion_graph::generate_deterministic` + `validate` + `add_edge` — fixture-generation cost | % cycles                         | **≈ 30 %**     | CPU         | `profiles/dgis_contagion.perf.flat.txt`: 14.85 + 5.07 + 4.10 + 3.98 + 1.42. **Caveat:** this is test-fixture cost, not production runtime cost (production builds the graph once). |
| R2-C | `fleet_transport::canonicalize_json_value` — recursive `format!()` for unused-on-happy-path `path` string | (not measured directly)              | small constant per Value | CPU+alloc | source inspection of `crates/franken-node/src/control_plane/fleet_transport.rs:154-180`. Two `format!()` per Value visited build a `path` string used only in the float-error branch (L176). |
| —    | `observability::evidence_ledger::append` (large payload, 256 cap, 16 MiB max)     | p95 / append                        | 16.62 µs       | (no hotspot — within budget) | `criterion_raw/evidence_ledger.txt`. `json_string_size 0.81 %` only evidence_ledger symbol > 0.3 %. **Round-1 deferred hypothesis rejected.** |
| —    | `dgis::contagion_simulator::step`                                                  | % cycles on dgis_contagion 200x loop | **0.45 %**     | (no hotspot — round-1 hypothesis rejected) | `profiles/dgis_contagion.perf.flat.txt`. Caveat: small fixtures only; large-graph behaviour not measured. |
| —    | `vef::proof_generator::compute_proof_bytes`                                        | (measurement gap)                   | —              | (deferred to R3 — needs Criterion bench) | source review confirms it's well-written; test exec too fast for perf sampling. |
| —    | `migration` tree-sitter parsing on real corpus                                    | (measurement gap)                   | —              | (deferred to R3) | no bench harness exists. |

## Categorical conclusions

**Confirmed hotspot, ready to optimise:**
- R2-A — DGIS String NodeId interning is a clean, contained win. Hypothesis matches: every BTreeMap<String, ...> lookup/insert costs O(|s|) memcmp; switching to a `u32` NodeId with a side `Vec<&str>` table would erase this band. Real-world impact depends on how often production builds and traverses contagion graphs.

**Confirmed non-hotspot, can be removed from the queue:**
- evidence_ledger append (16.2 µs/large-entry, well under any reasonable budget for an audit log).
- dgis::contagion_simulator::step (0.45 % of cycles on the available workload).

**Reframed (not the pattern we thought):**
- fleet_transport::canonicalize_json_value — small constant-factor allocation hygiene issue (unused-on-happy-path `format!()` for `path`), not the trust_card-style deep-clone cliff. Lower priority than the round-1 hypothesis implied.

**Caveat hotspot:**
- R2-B — DGIS graph construction at ~30 % of cycles is real, but in CI fixture-generation, not production. Reopen only if production runs ever build a fresh contagion graph per request.

## Round-2 effort scoring suggestions

| Item | Impact | Confidence | Effort | Score | Notes |
|------|-------:|-----------:|-------:|------:|------|
| **R2-A**: intern DGIS NodeId to `u32` with `Vec<&str>` lookup | 3 | 4 | 3 | **4.0** | Touches `dgis::contagion_graph` + every caller. Confidence is 4 not 5 because the production graph-traversal frequency isn't measured. |
| Reframed fleet_transport `format!()` path strings → defer to error site | 1 | 5 | 1 | 5.0 | Trivial fix once attempted; tiny absolute impact. Pair with the trust_card fix in one PR if scope allows. |
| Round-3 work — author Criterion benches for vef::proof_generator + receipt_chain | — | — | 2 | — | Profiling investment, not optimisation. Required before vef can be scored. |
