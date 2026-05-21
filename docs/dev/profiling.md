# Profiling franken_node

> **⚠️ DO NOT REMOVE `[profile.release-perf]` FROM `Cargo.toml` WITHOUT
> READING [`tests/artifacts/perf/HISTORY.md`](../../tests/artifacts/perf/HISTORY.md).**
> Every fingerprint.json under `tests/artifacts/perf/<run-id>/` was built
> against this exact profile. Deleting it silently invalidates every
> historical hotspot table and BASELINE.md in this repo.

## The profile

Workspace `Cargo.toml` carries one extra profile dedicated to performance
work:

```toml
[profile.release-perf]
inherits = "release"
opt-level = 3
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
strip = false
```

Concurrent agents working in this swarm have reverted this section more
than once. Bead [`bd-98xo5.11`](https://github.com/Dicklesworthstone/franken_node/issues)
tracks persisting the profile against future reverts; this document is
the canonical reference the comment above the profile block points at.

## Why each option matters

| key | value | reason |
|---|---|---|
| `inherits` | `"release"` | starts from `opt-level = 3, panic = "unwind"`, debug-assertions off, overflow-checks off. Don't redefine what `release` already gives. |
| `lto` | `"thin"` | thin LTO is the sweet spot for hot-path inlining across crate boundaries. **Full LTO is too slow to iterate** (multi-minute incremental link). |
| `codegen-units` | `1` | single CGU forces all functions through the same inliner pass, so inlining decisions are predictable. Multiple CGUs add noise to per-function timings. |
| `debug` | `"line-tables-only"` | required for [samply](https://github.com/mstange/samply) / `perf record` frame attribution. Full DWARF more than triples the binary size for no extra profiling value — line tables alone are enough to attribute samples to source lines. |
| `strip` | `false` | keep the symbol table so frame-pointer unwind has names to map to. With `strip = true` you get hex addresses in the flame graph. |
| `opt-level` | `3` | redundant with `inherits = "release"` but stated explicitly so a future change to the `release` profile cannot silently downgrade `release-perf`. |

## Required `RUSTFLAGS`

Samply on amd64 walks stacks via the frame pointer because the kernel
mlock budget under `perf_event_mlock_kb` is too small to fit the user
stack itself. Without frame pointers every sample comes back as a single
leaf frame.

```bash
RUSTFLAGS="-C force-frame-pointers=yes"
```

This is **not** in the profile because `RUSTFLAGS` cannot be set per-
profile in Cargo. It must be set in the environment of every
`cargo build --profile release-perf` invocation.

## Required kernel tuning

Samply / `perf record` need three sysctls relaxed from their hardened
defaults:

| sysctl | required value | reason |
|---|---|---|
| `kernel.perf_event_paranoid` | `1` (or lower) | allow user-space `perf_event_open()` for non-privileged users. |
| `kernel.kptr_restrict` | `0` | expose kernel symbol pointers so kernel-side samples have names. |
| `kernel.perf_event_mlock_kb` | `32768` (32 MiB minimum) | per-CPU mlock budget for the perf ring buffer. The default 516 KiB drops samples under load. |

These are set on the profiling host; agents don't need to set them per
run. If a run reports "no samples captured" or "all stacks single-leaf",
check these first.

## How to invoke

The canonical build incantation for any profiling run:

```bash
RUSTFLAGS="-C force-frame-pointers=yes" \
  rch exec -- cargo build --profile release-perf -p frankenengine-node --benches
```

The `--benches` flag picks up every Criterion harness registered under
`[[bench]]` in `crates/franken-node/Cargo.toml`. To target a single
bench:

```bash
RUSTFLAGS="-C force-frame-pointers=yes" \
  rch exec -- cargo build --profile release-perf -p frankenengine-node --bench <bench_name>
```

## Example historical fingerprints

Two profiling rounds have shipped against this exact profile. Their
fingerprint.json files record the toolchain, host CPU, kernel sysctls,
and bench list captured during each run:

- [`tests/artifacts/perf/20260520T214003Z_franken_node_perf/fingerprint.json`](../../tests/artifacts/perf/20260520T214003Z_franken_node_perf/fingerprint.json)
  — round 1, baseline snapshot of hotspots before any perf work
- [`tests/artifacts/perf/20260520T231041Z_franken_node_perf_r2/fingerprint.json`](../../tests/artifacts/perf/20260520T231041Z_franken_node_perf_r2/fingerprint.json)
  — round 2, post-round-1 follow-up hotspots

Run-id directories under `tests/artifacts/perf/<run-id>/` are
append-only: never edit a past run's BASELINE.md or fingerprint.json.
If a follow-up round invalidates a hotspot, file the rationale in
HISTORY.md and start a fresh run-id.

## Profile-removal protection

[`bd-98xo5.11.2`](https://github.com/Dicklesworthstone/franken_node/issues)
adds a CI gate (`scripts/check_release_perf_profile.py` + a workflow at
`.github/workflows/release-perf-profile-gate.yml`) that asserts the
profile block is intact whenever files under `tests/artifacts/perf/**`
change. That gate is the runtime backstop; this doc + the comment above
the profile in `Cargo.toml` are the design-time backstop.

## Out of scope

- **`.cargo/config.toml` instead of `Cargo.toml`.** Technically you can
  declare profiles via `.cargo/config.toml`, but that file is not
  versioned the same way and may shadow workspace settings on
  developer machines unpredictably. Stay in `Cargo.toml`.
- **Cross-platform profiling.** This doc covers amd64 Linux + samply +
  perf. macOS / arm64 / Instruments need their own playbook.
- **PGO / BOLT / Cachegrind.** Out of scope for round 1+2. If a future
  round adds them, document the toolchain expectations in a sibling
  file under `docs/dev/`.
