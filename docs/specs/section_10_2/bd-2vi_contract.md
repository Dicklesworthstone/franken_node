# bd-2vi: L1 Lockstep Runner Integration

## Decision Rationale

The canonical plan (Section 10.2) requires an L1 Product Oracle that runs the same compatibility fixtures across Node.js, Bun, and franken_node, then compares canonicalized results. This bead implements the lockstep runner framework and its validation infrastructure.

## L1 Oracle Architecture

The L1 lockstep runner:
1. Loads fixture files from `docs/fixtures/`
2. Executes each fixture against configured runtimes (Node, Bun, franken_node)
3. Canonicalizes outputs using the result canonicalizer
4. Compares canonical outputs to detect divergences
5. Produces a structured delta report

## Primary Implementation Surface

- `crates/franken-node/src/runtime/lockstep_harness.rs` is the Rust implementation for `LockstepHarness`, including runtime validation, corpus entry resolution, runtime execution, oracle comparison, divergence verdict handling, and optional fixture emission.
- `crates/franken-node/src/main.rs` wires the `franken-node verify lockstep` command to `LockstepHarness::verify_lockstep` and exits non-zero on harness failures.
- `crates/franken-node/src/cli.rs` defines `VerifyCommand::Lockstep` and `VerifyLockstepArgs`, including project path, runtime list, and `--emit-fixtures` control.

## Runner Configuration

```json
{
  "schema_version": "1.0",
  "runtimes": [
    {"name": "node", "command": "node", "version_flag": "--version"},
    {"name": "bun", "command": "bun", "version_flag": "--version"},
    {"name": "franken_node", "command": "franken-node", "version_flag": "--version"}
  ],
  "fixture_dir": "docs/fixtures",
  "output_dir": "artifacts/oracle"
}
```

## Invariants

1. `docs/L1_LOCKSTEP_RUNNER.md` design document exists.
2. `schemas/lockstep_runner_config.schema.json` defines runner configuration.
3. Runner configuration schema validates all required fields.
4. Design covers: fixture loading, runtime execution, canonicalization, delta detection.
5. Delta report format is machine-readable.

## Failure Semantics

- Missing design document: FAIL
- Missing config schema: FAIL
- Incomplete design (missing any of the 5 phases): FAIL
