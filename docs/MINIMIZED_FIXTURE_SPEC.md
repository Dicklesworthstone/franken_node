# Minimized Divergence Fixture Generation

> When divergences are detected, automatically generate the smallest fixture
> that reproduces the behavior difference.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md), [fixture_runner.py](../scripts/fixture_runner.py)

---

## 1. Purpose

When the L1 lockstep oracle detects a divergence between Node.js/Bun and franken_node, the minimized fixture generator produces the smallest possible test case that reproduces the difference. This aids debugging, reduces noise in the divergence ledger, and produces high-quality regression fixtures.

## 2. Minimization Strategies

### 2.1 Input Reduction

Progressively simplify fixture inputs:
1. Remove optional arguments one at a time
2. Reduce string arguments to shorter values
3. Remove array elements
4. Simplify object properties
5. After each simplification, re-run through oracle
6. If divergence persists → keep simplification
7. If divergence disappears → restore previous value
8. Repeat until no further reduction preserves the divergence

### 2.2 Scope Isolation

Narrow the API call surface:
1. If fixture involves multiple API calls, binary-search for the call that triggers divergence
2. Remove setup/teardown steps that don't affect the divergence
3. Inline constants rather than using file/env dependencies

### 2.3 Output Extraction

Capture canonical outputs from all runtimes:
1. Run minimized fixture through each oracle runtime
2. Canonicalize all outputs
3. Store both expected (oracle source) and actual (franken_node) as structured data
4. Annotate with divergence type (value mismatch, error difference, timing)

## 3. Generated Fixture Format

Minimized fixtures extend the standard fixture schema with:

```json
{
  "id": "fixture:fs:readFile:utf8-basic_min",
  "api_family": "fs",
  "api_name": "readFile",
  "band": "core",
  "description": "Minimized reproduction of DIV-003",
  "input": {"args": ["test.txt"]},
  "expected_output": {"return_value": "data"},
  "oracle_source": "node-20.11.0",
  "tags": ["minimized", "core", "divergence"],
  "minimized_from": "fixture:fs:readFile:utf8-basic",
  "minimization_method": "input-reduction",
  "divergence_id": "DIV-003"
}
```

## 4. Storage

- **Location**: `docs/fixtures/minimized/`
- **Naming**: `<original_id>_min.json`
- **Lifecycle**: Minimized fixtures persist as regression tests even after the divergence is resolved

## 5. Integration

- L1 lockstep runner triggers minimization on new divergences
- Minimized fixtures are added to the fixture corpus for continuous testing
- Divergence ledger entries reference their minimized fixture
- CI includes minimized fixtures in the standard fixture run

## 6. References

- [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md) — Oracle runner
- [DIVERGENCE_LEDGER.json](DIVERGENCE_LEDGER.json) — Divergence records
- [compatibility_fixture.schema.json](../schemas/compatibility_fixture.schema.json) — Fixture format
