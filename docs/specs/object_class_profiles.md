# Object-Class Profile Registry v1

## Scope

Defines the canonical object-class profile registry for Section 10.14 control artifacts.

The registry classifies artifact families and binds each class to deterministic policy defaults used by storage, replay, and verification surfaces.

## Required Classes

The registry MUST define all four required classes:

1. `critical_marker`
2. `trust_receipt`
3. `replay_bundle`
4. `telemetry_artifact`

## Invariants

| ID | Statement |
|----|-----------|
| INV-OCP-REQUIRED | All required classes are present in the registry. |
| INV-OCP-VERSIONED | Registry and schema versions are explicit and immutable per release. |
| INV-OCP-UNKNOWN-REJECT | Unknown object classes are rejected by default validation policy. |
| INV-OCP-DETERMINISTIC | Class policy fields are deterministic and free of implicit defaults. |

## Profile Contract

Each class definition includes:

- `retention_class`: `required` or `ephemeral`
- `max_size_bytes`: upper size bound
- `symbol_overhead_budget`: float in `[0,1]`
- `fetch_policy`: `eager`, `on_demand`, or `lazy`
- `integrity_level`: `strict`, `verified`, or `best_effort`
- `description`: human-readable summary

## Unknown Class Validation

Registry-level policy field:

- `default_unknown_class_policy = "reject"`

Validation behavior:

- unknown class lookup MUST fail with `OCP_UNKNOWN_CLASS`
- no fallback class remapping is allowed
- rejection is logged with stable event code

## Stable Event and Error Codes

### Event Codes

- `OCP_REGISTRY_LOADED`
- `OCP_CLASS_VALIDATED`
- `OCP_UNKNOWN_CLASS_REJECTED`
- `OCP_REGISTRY_VERIFIED`

### Error Codes

- `OCP_MISSING_REQUIRED_CLASS`
- `OCP_UNKNOWN_CLASS`
- `OCP_INVALID_PROFILE_FIELD`
- `OCP_VERSION_MISMATCH`

## Artifacts

- Spec: `docs/specs/object_class_profiles.md`
- Registry config: `config/object_class_profiles.toml`
- Registry snapshot: `artifacts/10.14/object_class_registry.json`
- Replay fixture: `fixtures/object_class_profiles/cases.json`
- Verifier script: `scripts/check_object_class_profiles.py`
- Unit tests: `tests/test_check_object_class_profiles.py`
- Verification evidence: `artifacts/section_10_14/bd-2573/verification_evidence.json`
- Verification summary: `artifacts/section_10_14/bd-2573/verification_summary.md`
