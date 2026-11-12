# Fuzz Regression Corpus & Seed Promotion Contract

- **Schema:** `franken-node/fuzz-regression-manifest/v1`
- **Canonical Fuzz Manifest:** `fuzz/Cargo.toml` (`146` registered `cargo-fuzz` binary targets)
- **Reconciled Crate-Local Harnesses:** `crates/franken-node/fuzz/Cargo.toml` (retained per repository no-deletion policy and linked to `../../fuzz/Cargo.toml` via `[package.metadata.franken_node]`)
- **Beads:** `bd-fuzz-regression-corpus-f28ac`, `bd-reality-20260923-26n9r.38`

## 1. Directory Responsibilities

1. **`fuzz/artifacts/<target>/crash-*`**
   - Raw `libfuzzer` / `cargo-fuzz` failure outputs captured during fuzzing campaigns.
   - Retained as immutable raw discovery evidence; every `crash-*` artifact must have a corresponding promoted entry in `fuzz/regression/manifest.json`.
2. **`fuzz/regression/<target>/`**
   - Permanent deterministic regression inputs mapped 1-to-1 to registered `[[bin]]` target names in `fuzz/Cargo.toml`.
   - Holds both the promoted `crash-<sha1>` input and, whenever Hierarchical Delta Debugging (`§6.15`) produces a strictly smaller reproducer, its `minimized-<sha1>` companion.
   - Historical `fuzz/regression/{migration,shim}/crash_20260215_*.bin` files are explicitly classified as `legacy_simulated_category_seed` in `fuzz/regression/manifest.json` rather than counted as native `cargo-fuzz` target regressions.
3. **`fuzz/corpus/<target>/`**
   - Non-empty domain-matched seed corpora (`<sha1>` content-addressed files) for every registered `[[bin]]` target in `fuzz/Cargo.toml` (`146 / 146` targets seeded).

## 2. Promotion Workflow

1. Reproduce the failure against `fuzz/fuzz_targets/<target>.rs` and identify the root cause in `crates/franken-node/src/**` or harness boundary logic.
2. Shrink the crashing input to a minimal byte sequence (`minimized-<sha1>`) via delta debugging while preserving the exact failure/boundary path.
3. Fix the underlying bug in `crates/franken-node/src/**` without weakening validation or swallowing errors.
4. Copy both `crash-<sha1>` and `minimized-<sha1>` into `fuzz/regression/<target>/` and record SHA-256 digests + remediation commit in `fuzz/regression/manifest.json`.
5. Verify via both:
   - `rch exec -- cargo test -p frankenengine-node --test remote_capability_gate_fuzz_regression`
   - `python3 scripts/check_fuzz_regression_corpus.py --json`

## 3. Blocking Gate Invariants

`scripts/check_fuzz_regression_corpus.py` and `crates/franken-node/tests/remote_capability_gate_fuzz_regression.rs` fail closed if:
- Any `fuzz/artifacts/<target>/crash-*` file lacks a promoted entry in `fuzz/regression/manifest.json` with matching SHA-256 bytes under `fuzz/regression/<target>/`;
- Any promoted target in `fuzz/regression/<target>/` is not a registered `[[bin]]` target in `fuzz/Cargo.toml`;
- Any registered `[[bin]]` target in `fuzz/Cargo.toml` has `0` seed files in `fuzz/corpus/<target>/`;
- `crates/franken-node/fuzz/Cargo.toml` lacks `[package.metadata.franken_node].canonical_fuzz_manifest = "../../fuzz/Cargo.toml"`; or
- Replaying any promoted regression input, minimized companion, or corpus seed panics or behaves non-deterministically.
