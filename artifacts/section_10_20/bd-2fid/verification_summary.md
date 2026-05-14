# bd-2fid — Critical-node immunization planner

## Verdict: PASS

## Implementation
- Rust module: `crates/franken-node/src/security/dgis/immunization_planner.rs`
- Module wiring: `crates/franken-node/src/security/dgis/mod.rs`
- Spec: `docs/specs/dgis_immunization_planner.md`
- Sample catalog contract: `artifacts/10.20/dgis_barrier_plan_catalog.json`
- Integration proof target: `tests/security/dgis_immunization_planner.rs`

## Planner contract
- Synthesizes enforceable barrier candidates from articulation, betweenness,
  fan-out, trust bottleneck, and transitive-depth signals.
- Ranks bounded candidate sets by deterministic cost, overhead, and reduction
  criteria.
- Emits machine-readable per-barrier rationale with mitigated metric, metric
  value, risk-reduction delta, cost, and overhead.
- Respects policy exclusions and performance ceilings.
- Fails closed with `NoFeasiblePlan` when no constrained candidate set can
  meet the target cascade-loss threshold.
- Supports scoped incremental replanning over changed node ids.

## Verification command
```bash
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/franken_node-snowybeaver-bd2fid-target rch exec -- cargo test -p frankenengine-node --test dgis_immunization_planner --no-default-features -- --nocapture
```

Result: rch job `29840908367167960` on worker `vmi1264463`, 4 passed, 0 failed.
