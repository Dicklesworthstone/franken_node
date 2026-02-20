# bd-36wa Contract: Compatibility And Threat Evidence

## Purpose

Define a mandatory, machine-verifiable contract field named
`change_summary.compatibility_and_threat_evidence` for subsystem proposals.

This field ensures each major subsystem proposal includes concrete compatibility
test evidence plus explicit threat-vector mitigation evidence.

## Contract Field

Path:
- `change_summary.compatibility_and_threat_evidence`

Required sub-fields:
1. `compatibility_test_suites` (non-empty list)
2. `regression_risk_assessment` (object)
3. `threat_vectors` (list including required vectors)

### compatibility_test_suites

Each entry MUST contain:
- `suite_name` (non-empty string)
- `pass_count` (integer >= 0)
- `fail_count` (integer >= 0)
- `artifact_path` (non-empty string path to existing artifact)

Additional rules:
- At least one test suite is required.
- The set of suites must report explicit pass/fail counts.

### regression_risk_assessment

Required fields:
- `risk_level` in `{low, medium, high, critical}`
- `api_families` (non-empty list of non-empty strings)
- `notes` (non-empty string)

### threat_vectors

Each entry MUST contain:
- `vector` (non-empty string)
- `mitigation` (non-empty string)

Required vectors:
- `privilege_escalation`
- `data_exfiltration`
- `denial_of_service`

## Enforcement

Validator:
- `scripts/check_compatibility_threat_evidence.py`

Unit tests:
- `tests/test_check_compatibility_threat_evidence.py`

CI gate:
- `.github/workflows/compatibility-threat-evidence-gate.yml`

## Event Codes

- `CONTRACT_COMPAT_THREAT_VALIDATED` (info)
- `CONTRACT_COMPAT_THREAT_MISSING` (error)
- `CONTRACT_COMPAT_THREAT_INCOMPLETE` (error)

## Acceptance Mapping

- Compatibility suites + pass/fail counts: enforced per suite entry.
- Artifact references: `artifact_path` must resolve to an existing file.
- Threat model coverage: required vectors must be present with mitigations.
- Regression risk by API family: required non-empty `api_families`.
- CI rejection behavior: gate exits non-zero on missing/incomplete contract field.
