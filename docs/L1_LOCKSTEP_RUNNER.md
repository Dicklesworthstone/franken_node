# L1 Lockstep Runner

> Executes compatibility fixtures across Node.js, Bun, and franken_node in lockstep,
> canonicalizes results, and produces structured divergence reports.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md), [fixture_runner.py](../scripts/fixture_runner.py)

---

## 1. Overview

The L1 Product Oracle validates that franken_node's external behavior matches Node.js and Bun for core and high-value compatibility bands. It operates by executing identical fixture inputs across all configured runtimes and comparing canonicalized outputs.

## 2. Architecture

### Phase 1: Fixture Loading
- Load all `*.json` fixtures from the configured fixture directory
- Validate each fixture against `schemas/compatibility_fixture.schema.json`
- Filter by band and tags if configured

### Phase 2: Runtime Execution
- For each fixture, execute the test scenario against each configured runtime
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
  "runtimes": ["node-20.11.0", "bun-1.0.0", "franken_node-0.1.0"],
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
    {"name": "node", "command": "node", "version_flag": "--version"},
    {"name": "bun", "command": "bun", "version_flag": "--version"},
    {"name": "franken_node", "command": "franken-node", "version_flag": "--version"}
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

## 6. References

- [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md) — Band definitions
- [COMPATIBILITY_MODE_POLICY.md](COMPATIBILITY_MODE_POLICY.md) — Mode enforcement
- [DIVERGENCE_LEDGER.json](DIVERGENCE_LEDGER.json) — Known divergences
- [fixture_runner.py](../scripts/fixture_runner.py) — Fixture loading and canonicalization
- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
