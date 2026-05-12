# bd-2st: Migration Validation Runner

## Decision Rationale

After rewrite suggestions are applied, operators need a validation runner that executes lockstep checks between the original Node.js/Bun execution and franken_node execution. This ensures behavioral equivalence before committing to the migration.

## Scope

Build a migration validation runner that:
1. Executes test suites against both original runtime and franken_node
2. Compares outputs using the fixture canonicalizer
3. Reports divergences with band-aware severity classification
4. Produces a pass/fail validation report

## Architecture

```
┌──────────────────────────┐
│  Migration Validation     │
├──────────────────────────┤
│  Test Discovery           │  ← Find test files in project
├──────────────────────────┤
│  Dual Execution           │  ← Run on Node + franken_node
├──────────────────────────┤
│  Output Canonicalization  │  ← Normalize timestamps, PIDs, paths
├──────────────────────────┤
│  Delta Detection          │  ← Compare canonicalized outputs
├──────────────────────────┤
│  Validation Report        │  ← Pass/fail with divergence details
└──────────────────────────┘
```

## Validation Phases

1. **Discovery**: Find test files (`*.test.js`, `*.spec.js`, `__tests__/`)
2. **Baseline**: Run tests on Node.js, capture outputs
3. **Migration**: Run tests on franken_node, capture outputs
4. **Compare**: Canonicalize and diff outputs
5. **Report**: Classify divergences by band, produce verdict

## Primary Implementation Surface

- `scripts/migration_validation_runner.py` implements the migration validation runner, including test discovery, canonicalization, output comparison, band-aware severity classification, report emission, and the verifier self-test.
- `crates/franken-node/src/runtime/lockstep_harness.rs` is the product lockstep harness that executes Node/Bun/franken_node comparisons and emits divergence fixtures for the runtime validation path.

## Invariants

1. Validation is deterministic for identical test inputs.
2. All divergences are classified by compatibility band.
3. Core-band divergences always fail the validation.
4. Report includes enough context for divergence diagnosis.

## References

- [bd-2ew_contract.md](bd-2ew_contract.md) — Rewrite Engine
- [L1_LOCKSTEP_RUNNER.md](../../L1_LOCKSTEP_RUNNER.md)
