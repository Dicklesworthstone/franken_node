# DGIS contagion step hot-path optimization

Run id: `20260522T1940Z_r38_dgis_step_cod5`
Tracking bead: `bd-98xo5.17`
Pass id: `r38-cod5-1450-next`

## Change

`contagion_simulator::step` now consumes graph-owned interned node order and a
cached reverse-adjacency view instead of rebuilding `in_edges` on every step.
`InfectionState` also keeps a graph-interner fingerprint, so the matching fast
path borrows infected/exposure maps instead of cloning them before each loop.

## Verification

```text
rch exec -- cargo check -p frankenengine-node --no-default-features --features advanced-features --lib
rch exec -- cargo test -p frankenengine-node --no-default-features --features advanced-features --test dgis_contagion_simulator simulator_step_fast_path_uses_cached_in_edges_after_edge_mutation
rch exec -- cargo bench -p frankenengine-node --no-default-features --features advanced-features --bench dgis_large_graph_bench -- dgis_large_graph
```

The targeted security regression passed: 1 test passed, 0 failed, 24 filtered
out. The broader `cargo test -p frankenengine-node --no-default-features
--features advanced-features contagion` command remains blocked by unrelated
compile errors in `tests/conformance/bd_w0jq_degraded_mode_audit_conformance.rs`.

## Criterion

Compared with the bd-98xo5.10 baseline in
`tests/artifacts/perf/20260522T1841Z_dgis_large_graph_cod5/REPORT.md`.

| Case | Baseline mean | Optimized mean / interval | Change |
|------|--------------:|---------------------------:|-------:|
| `requested_1000n_actual_1000n_999e_100s` | 42.003 ms | 14.109 ms `[13.371, 14.877]` | 2.98x faster |
| `requested_10000n_actual_1024n_101e_100s` | 22.258 ms | 5.3175 ms `[5.1507, 5.4896]` | 4.19x faster |
| `requested_50000n_actual_1024n_42e_50s` | 10.016 ms | 3.2998 ms `[3.2295, 3.3690]` | 3.04x faster |
| `requested_1024n_actual_1024n_10476e_100s` | 173.98 ms | 22.411 ms `[21.707, 23.113]` | 7.76x faster |

Decision: accepted. The bead's large-graph hot path moved from repeated
reverse-edge construction plus state cloning to one cached graph view and
borrowed interned state when the graph node index matches.
