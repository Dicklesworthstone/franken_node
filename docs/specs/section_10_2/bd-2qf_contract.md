# bd-2qf: Compatibility Behavior Registry

## Decision Rationale

The canonical plan (Section 10.2) requires a typed registry of all compatibility behaviors (shims) that franken_node provides. Each entry captures the API surface, compatibility band, shim type, spec reference, and oracle status. This enables policy-visible compatibility, automated coverage tracking, and governance enforcement.

## Registry Format

Each behavior entry in the registry includes:
- **id**: Unique behavior identifier (e.g., `compat:fs:readFile`)
- **api_family**: API family (fs, path, process, http, crypto, etc.)
- **api_name**: Specific API name
- **band**: Compatibility band (core, high-value, edge, unsafe)
- **shim_type**: Type of compatibility implementation
  - `native` — Implemented natively on franken_engine
  - `polyfill` — Pure JS/TS polyfill
  - `bridge` — Bridge between native and JS layers
  - `stub` — Placeholder returning not-implemented error
- **spec_ref**: Reference to specification document
- **fixture_ref**: Reference to conformance fixture(s)
- **oracle_status**: Oracle validation status (validated, pending, not-applicable)
- **notes**: Optional implementation notes

## Invariants

1. `docs/COMPATIBILITY_REGISTRY.json` exists and is valid JSON.
2. A JSON schema exists at `schemas/compatibility_registry.schema.json`.
3. Every entry has all required fields.
4. Band values are one of: core, high-value, edge, unsafe.
5. Shim type values are one of: native, polyfill, bridge, stub.
6. Oracle status values are one of: validated, pending, not-applicable.

## Interface Boundaries

- **Input**: `docs/COMPATIBILITY_REGISTRY.json`
- **Input**: `schemas/compatibility_registry.schema.json`
- **Output**: PASS/FAIL verdict on registry validity

## Implementation and Verification Paths

- Primary registry implementation: `docs/COMPATIBILITY_REGISTRY.json`
- Registry schema: `schemas/compatibility_registry.schema.json`
- Verification implementation: `scripts/check_compat_registry.py`
- Regression tests: `tests/test_check_compat_registry.py`
- Machine evidence: `artifacts/section_10_2/bd-2qf/verification_evidence.json`
- Human summary: `artifacts/section_10_2/bd-2qf/verification_summary.md`

## Failure Semantics

- Missing registry: FAIL
- Missing schema: FAIL
- Invalid JSON: FAIL
- Entry missing required fields: FAIL per entry
- Invalid enum values: FAIL per entry
