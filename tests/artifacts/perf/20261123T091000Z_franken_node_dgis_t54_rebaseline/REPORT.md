# DGIS T5.4 — `dgis_contagion_simulator` 200x `release-perf` Re-Baseline

Run id: `20261123T091000Z_franken_node_dgis_t54_rebaseline`  
Tracking bead: `bd-98xo5.5.4`  
Baseline reference: `20260520T231041Z_franken_node_perf_r2` (`profiles/dgis_contagion.perf.flat.txt`)  
Flat profile: [`profiles/dgis_contagion.perf.flat.txt`](profiles/dgis_contagion.perf.flat.txt)

## Summary

All three `bd-98xo5.5.4` acceptance criteria are met on the post-`80ce79d61`
`release-perf` binary (`26/26` tests passing locally in `0.27s`, `89,148` samples,
`0` lost samples):

| Acceptance Bar (`bd-98xo5.5.4`) | R2 Baseline (`20260520`, 15K samples) | Pre-`80ce79d61` (`db84b00c4`, 80K samples) | Post-`80ce79d61` (`515ab64d9`, 89K samples) | Threshold | Status |
|---|---:|---:|---:|---:|---|
| `__memcmp_{avx2,evex}_movbe` self % | `14.10%` (`__memcmp_avx2_movbe`) | `6.47%` (`__memcmp_evex_movbe`) | **`3.13%`** (`__memcmp_evex_movbe`, **4.50× drop**) | `<= 5.0%` | **PASS** |
| `BTreeMap<String, ...>` ops band | `6.81%` (`3.84%` + `2.97%` `BTreeMap<String, Vec<ContagionEdge>>`) | `0.33%` (`BTreeMap<String, u32>::insert` in `NodeInterner`) | **`0.00%`** (completely absent) | Disappears | **PASS** |
| `<String as Clone>::clone` | `0.46%` | `0.00%` | **`0.00%`** (completely absent) | Disappears | **PASS** |

Additional observed shifts:
- `ContagionGraph::generate_deterministic`: `14.85%` (R2) -> `0.45%` (`db84b00c4`) -> **`0.65%`** (`515ab64d9`, **22.8× lower share**).
- Same-host, same-26-test apples-to-apples comparison (`db84b00c4` vs `80ce79d61`/`515ab64d9`):
  - Single-run wall time: `0.30s` -> **`0.27s`** (`26/26` tests pass).
  - 200× total cycle event count (`cpu/cycles/P`): `231,908,331,363` -> **`218,129,019,532`** (`-5.94%`).
  - `__memcmp_evex_movbe`: `6.47%` -> **`3.13%`** (`-3.34 pp`, `-51.6%` relative).
  - `BTreeMap<String, u32>::insert`: `0.33%` -> **`0.00%`**.

## Iterative Diagnosis That Closed the `<= 5.0%` Bar

1. **First re-baseline (`db84b00c4`, binary `sha256:a9fc3652f2ecd8f77e67f455c9c84104446645c966cb3b26a418d8f981ad9dc0`):**
   After T5.2 + T5.3 landed, `BTreeMap<String, Vec<ContagionEdge>>` and
   `<String as Clone>::clone` were already gone, and `generate_deterministic`
   had dropped from `14.85%` to `0.45%`. However, `__memcmp_evex_movbe` was
   still `6.47%` (above the `<= 5.0%` bar) and `BTreeMap<String, u32>::insert`
   remained visible at `0.33%` because `NodeInterner` itself still backed its
   reverse lookup with a `BTreeMap<String, u32>` doing double lookups plus
   repeated `s != s.trim()` / duplicate validation on every intern call.
2. **Follow-up fix (`80ce79d61`):**
   Replaced `NodeInterner`'s internal `BTreeMap<String, u32>` lookup map with
   `HashMap<String, u32>` (preserving deterministic `NodeId` assignment order
   in `to_str: Vec<String>`), replaced `s != s.trim()` with
   `trimmed.len() != s.len()`, and added `intern_prevalidated` in
   `crates/franken-node/src/dgis/node_interner.rs` +
   `crates/franken-node/src/dgis/contagion_graph.rs`.
3. **Final re-baseline (`515ab64d9`, binary `sha256:b19755e7bb6cf164fd07b0fb7e334d3c2fb6e5dea801c422f97c01ce62eccb6e`):**
   `__memcmp_evex_movbe` dropped to `3.13%` (`<= 5.0%`), `BTreeMap<String, ...>`
   disappeared completely (`0.00%`), and `<String as Clone>::clone` remained
   absent (`0.00%`).

## Reproduction Commands

Build & retrieve `release-perf` test binary via RCH (`vmi1152480`):

```bash
rch exec --worker vmi1152480 --job --result-dir target/t54-out-v2 -- \
  env CARGO_HOME=/root/.cargo \
  CARGO_PROFILE_RELEASE_PERF_CODEGEN_UNITS=16 \
  RUSTFLAGS="-C force-frame-pointers=yes" \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="install -Dt /data/projects/franken_node/target/t54-out-v2" \
  cargo test --profile release-perf -p frankenengine-node --no-default-features \
  --test dgis_contagion_simulator --
```

Verify test execution and capture the 200× `perf` profile locally:

```bash
./target/t54-out-v2/dgis_contagion_simulator-2bd52b191ca80ef3
perf record -F 999 --call-graph dwarf -o dgis_t54_v2.perf.data -- \
  bash -c 'for i in $(seq 200); do ./target/t54-out-v2/dgis_contagion_simulator-2bd52b191ca80ef3 >/dev/null; done'
perf report -i dgis_t54_v2.perf.data -g none --no-children --stdio \
  --percent-limit 0.3 --sort overhead,symbol > profiles/dgis_contagion.perf.flat.txt
```

## Methodology Disclosures

- Checked-in `[profile.release-perf]` in `Cargo.toml` was **not** modified
  (`codegen-units = 1`, `scripts/check_release_perf_profile.py --ci` passes).
  Both the pre-fix (`db84b00c4`) and post-fix (`80ce79d61`/`515ab64d9`) builds
  used the `CARGO_PROFILE_RELEASE_PERF_CODEGEN_UNITS=16` environment override
  on RCH so `release-perf` compilation completed within the 30-minute remote
  worker deadline.
- Cross-round comparison against Round 2 (`2026-05-20`) spans a host and
  toolchain upgrade (`AMD EPYC 7282` / `rustc 1.97.0-nightly` / 8 tests ->
  `AMD EPYC-Genoa` / `rustc 1.100.0-nightly` / 26 tests, so glibc dispatches
  `__memcmp_evex_movbe` rather than `__memcmp_avx2_movbe`). The same-host,
  same-26-test `db84b00c4` -> `80ce79d61` comparison directly isolates the
  final interner hash-index reduction (`6.47%` -> `3.13%`).
- Residual top user symbols (`validate_node_id` `7.10%`, `_int_malloc` `7.43%`,
  `_int_free_merge_chunk` `4.06%`, `Sip13Rounds` `2.69%`, `step` `2.46%`)
  reflect fixture validation and test-harness allocation across the 26-test
  suite (including proptest/fuzz cases); no `BTreeMap<String, ...>` or
  `<String as Clone>::clone` hotspots remain.
