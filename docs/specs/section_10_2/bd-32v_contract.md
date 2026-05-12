# bd-32v: Minimized Divergence Fixture Generation

## Decision Rationale

The canonical plan (Section 10.2) requires automated generation of minimal reproduction fixtures when divergences are detected. When the L1 oracle detects a divergence, the system should automatically produce the smallest fixture that reproduces the behavior difference.

## Design

### Minimization Strategy

1. **Input reduction**: Progressively simplify fixture inputs until the divergence disappears, then restore the last simplification that preserved the divergence.
2. **Scope isolation**: Narrow the API surface to the smallest API call that triggers the divergence.
3. **Output extraction**: Capture both expected (oracle) and actual (franken_node) outputs as canonical fixtures.

### Generated Fixture Format

Minimized fixtures follow the same schema as standard fixtures (`compatibility_fixture.schema.json`) with additional fields:
- `minimized_from`: ID of the original fixture
- `minimization_method`: Strategy used (input-reduction, scope-isolation)
- `divergence_id`: Reference to divergence ledger entry

### Output Location

Minimized fixtures are written to `docs/fixtures/minimized/` with naming convention:
`<original_fixture_id>_min.json`

### Implementation and Verification Paths

- Fixture-generation design: `docs/MINIMIZED_FIXTURE_SPEC.md`
- Minimized fixture output root: `docs/fixtures/minimized/`
- Verification implementation: `scripts/check_minimized_fixtures.py`
- Regression tests: `tests/test_check_minimized_fixtures.py`
- Machine evidence: `artifacts/section_10_2/bd-32v/verification_evidence.json`
- Human summary: `artifacts/section_10_2/bd-32v/verification_summary.md`

## Invariants

1. `docs/MINIMIZED_FIXTURE_SPEC.md` design document exists.
2. `docs/fixtures/minimized/` directory exists.
3. Design covers: input reduction, scope isolation, output extraction.
4. Generated fixtures conform to fixture schema.
5. Fixtures reference their parent fixture and divergence ledger entry.

## Failure Semantics

- Missing spec: FAIL
- Missing directory: FAIL
- Incomplete design: FAIL
