# bd-1q38 - Adversarial Contagion Simulator

## Verdict

`PASS`

## Gate

`scripts/check_dgis_contagion_simulator.py` verifies the real bd-1q38 implementation surface:

- `crates/franken-node/src/dgis/contagion_graph.rs`
- `crates/franken-node/src/dgis/contagion_simulator.rs`
- `crates/franken-node/src/dgis/contagion_profiles.rs`
- `tests/security/dgis_contagion_simulator.rs`
- `tests/security/contagion_profiles/{xz_style,dependency_confusion,typosquat}.json`
- `crates/franken-node/Cargo.toml`

## Static Evidence

- 8 required integration tests are present.
- Three shipped campaign fixtures are validated exactly.
- Fixture aggregate: 3 profiles, 65 nodes, 46 edges, 7 initial infections.
- Edge kind aggregate: 35 `DependencyImport`, 9 `NamespaceShadow`, 2 `MaintainerOverlap`.

## Full Proof

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/franken_node-snowybeaver-bd1q38-target cargo test -p frankenengine-node --test dgis_contagion_simulator -- --nocapture
```

Result:

- RCH job: `29840908367167890`
- Worker: `vmi1152480`
- Completed: `2026-05-14T08:12:32.062133Z`
- Rust result: `8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`
