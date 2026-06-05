# L1 Lockstep Runner

> Executes compatibility fixtures across configured reference runtimes in
> lockstep, canonicalizes results, and produces structured divergence reports.
> The checked-in CI/dev default is the Bun + franken runtime dyad. The Node.js
> leg is opt-in and must be backed by a real Node.js binary, not Bun's
> `node` wrapper.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md), [fixture_runner.py](../scripts/fixture_runner.py)
**Primary implementation**: `crates/franken-node/src/runtime/lockstep_harness.rs`

---

## 1. Overview

The L1 Product Oracle validates that franken_node's external behavior matches
the configured JavaScript reference runtimes for core and high-value
compatibility bands. It operates by executing identical fixture inputs across
all enabled runtimes and comparing canonicalized outputs.

The current repository default is `bun,franken-node` because the evaluation
host exposes `node` as Bun's compatibility wrapper (`/home/ubuntu/.bun/bin/node`),
which is not an independent Node.js oracle. Real Node.js coverage is still
supported by passing `--runtimes node,bun,franken-node` on hosts where
`node --version` returns a real Node.js version.

## Implementation Map

- `crates/franken-node/src/runtime/lockstep_harness.rs` owns `LockstepHarness`, runtime validation, corpus manifest validation, concurrent runtime execution, report evaluation, and divergence fixture emission.
- `crates/franken-node/src/main.rs` dispatches `franken-node verify lockstep` into `LockstepHarness::verify_lockstep` and returns a failing process status when the harness reports divergence or setup errors.
- `crates/franken-node/src/cli.rs` defines `VerifyCommand::Lockstep` and `VerifyLockstepArgs`, including the project path, comma-separated runtime list, and divergence fixture emission flag.

## 2. Architecture

### Phase 1: Fixture Loading
- Load all `*.json` fixtures from the configured fixture directory
- Validate each fixture against `schemas/compatibility_fixture.schema.json`
- Filter by band and tags if configured

### Phase 2: Runtime Execution
- For each fixture, execute the test scenario against each enabled configured runtime
- Capture: return value, error output, exit code, timing
- Timeout: 30s per fixture per runtime

### Phase 3: Result Canonicalization
- Normalize outputs using the canonicalizer from `fixture_runner.py`
- Replace timestamps, PIDs, absolute paths
- Sort object keys, round floats
- Produce canonical result per runtime per fixture

### Phase 4: Delta Detection
- Compare canonical results across runtimes
- Classify deltas by band:
  - `core` band delta → critical (blocks release in all modes)
  - `high-value` band delta → high (blocks release in strict mode)
  - `edge` band delta → informational (logged, no block)
  - `unsafe` band delta → N/A (unsafe fixtures not run in oracle)

### Phase 5: Report Generation
- Produce structured JSON delta report
- Fields: fixture_id, runtimes compared, match/diverge status, delta details
- Summary: total fixtures, matches, divergences by band
- Machine-readable for CI/release gating

## 3. Delta Report Format

```json
{
  "schema_version": "1.0",
  "timestamp": "2025-01-15T12:00:00Z",
  "runtimes": ["bun-1.3.14", "franken_node-0.1.0"],
  "excluded_runtimes": [
    {
      "name": "node",
      "reason": "excluded on this host because `node` resolves to Bun's wrapper; provide a real Node.js binary and pass --runtimes node,bun,franken-node to enable the triad"
    }
  ],
  "fixtures_executed": 100,
  "fixtures_matched": 95,
  "fixtures_diverged": 5,
  "divergences": [
    {
      "fixture_id": "fixture:fs:readFile:encoding-edge",
      "band": "edge",
      "runtimes": {
        "node": {"return_value": "..."},
        "franken_node": {"return_value": "..."}
      },
      "delta_type": "value_mismatch",
      "severity": "informational"
    }
  ]
}
```

## 4. Configuration

The runner reads `lockstep_runner_config.json` (or uses defaults):

```json
{
  "schema_version": "1.0",
  "runtimes": [
    {
      "name": "node",
      "command": "node",
      "version_flag": "--version",
      "enabled": false,
      "required": false,
      "exclusion_reason": "Bun's node wrapper is not an independent Node.js oracle in the default CI/dev image."
    },
    {"name": "bun", "command": "bun", "version_flag": "--version", "enabled": true, "required": true},
    {"name": "franken_node", "command": "franken-node", "version_flag": "--version", "enabled": true, "required": true}
  ],
  "fixture_dir": "docs/fixtures",
  "output_dir": "artifacts/oracle",
  "canonicalize": true,
  "fail_on_divergence": false
}
```

## 5. Release Gating Integration

- **Core band divergences**: Always block release (all modes)
- **High-value band divergences**: Block release in strict mode
- **Edge band divergences**: Logged but never block
- Oracle verdicts feed into release policy (Section 10.2)

## 6. Runtime Availability Contract

- The supported default runtime set is `bun,franken-node`.
- The Node.js leg is excluded by default in this checkout because `node` is a
  Bun-provided wrapper and cannot serve as an independent oracle.
- Real Node.js remains supported as an explicit triad leg when a host provides a
  real Node.js binary; operators enable it with
  `franken-node verify lockstep <path> --runtimes node,bun,franken-node`.
- Every machine-readable report or config that disables a runtime must carry an
  `exclusion_reason` so the omission is auditable.

## 7. References

- [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md) — Band definitions
- [COMPATIBILITY_MODE_POLICY.md](COMPATIBILITY_MODE_POLICY.md) — Mode enforcement
- [DIVERGENCE_LEDGER.json](DIVERGENCE_LEDGER.json) — Known divergences
- [fixture_runner.py](../scripts/fixture_runner.py) — Fixture loading and canonicalization
- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
