# DGIS large-graph contagion step profile

Run id: `20260522T1841Z_dgis_large_graph_cod5`
Tracking bead: `bd-98xo5.10`
Follow-up bead: `bd-98xo5.17`

## Build

```text
RUSTFLAGS='-C force-frame-pointers=yes' rch exec -- cargo build --profile release-perf -p frankenengine-node --no-default-features --features advanced-features --bench dgis_large_graph_bench
```

The remote `rch` build completed on `vmi1149989` with the bench binary
`target/release-perf/deps/dgis_large_graph_bench-79363297b5522965`.

## Criterion

All cases ran through the built Criterion binary, not through a second Cargo
build.

| Case | Actual graph | Steps | Mean / interval |
|------|--------------|------:|-----------------|
| `requested_1000n` | 1000 nodes, 999 edges | 100 | 42.003 ms `[41.937, 42.078]` |
| `requested_10000n` | 1024 nodes, 101 edges | 100 | 22.258 ms `[21.893, 22.630]` |
| `requested_50000n` | 1024 nodes, 42 edges | 50 | 10.016 ms `[9.8661, 10.261]` |
| `requested_1024n` dense | 1024 nodes, 10476 edges | 100 | 173.98 ms `[173.59, 174.44]` |

The repeated 50k run under perf measured 9.8001 ms
`[9.7664, 9.8366]`; Criterion reported no statistically significant
change from the prior same-binary run.

## Perf

Committed self-sample profile:
`dgis_large_graph_50k_self.perf.data` (232 KiB, 4688 samples, 0 lost).

Top self symbols from:

```text
perf report --stdio --no-children --no-call-graph --percent-limit 0.5 --sort comm,dso,symbol -i tests/artifacts/perf/20260522T1841Z_dgis_large_graph_cod5/dgis_large_graph_50k_self.perf.data
```

| Self cycles | Symbol |
|------------:|--------|
| 46.54% | `frankenengine_node::dgis::contagion_simulator::step` |
| 20.91% | `libc.so.6::__memcmp_avx2_movbe` |
| 15.07% | `libm.so.6::__ieee754_exp_fma` |
| 5.56% | `libm.so.6::exp@@GLIBC_2.29` |
| 2.44% | Criterion/Rayon KDE collection |
| 0.78% | `libm.so.6::__math_check_oflow` |
| 0.73% | `rayon_core::registry::WorkerThread::find_work` |
| 0.52% | `crossbeam_epoch::internal::Global::try_advance` |

Decision: acceptance branch A. `step` is above the 5% large-graph threshold,
so `bd-98xo5.17` tracks the follow-up optimization for the per-step reverse
edge rebuild, infected state clone/equality work, and BTree lookup churn.
