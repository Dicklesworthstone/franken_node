# Change Summary Contract Template

Every proposal/PR that changes subsystem runtime or control-plane code must include a machine-parseable change summary companion file under `docs/change_summaries/`.

Use `docs/change_summaries/<date>-<slug>.json` and follow this contract.

## Required Fields

1. `intent`: one-line change intent statement.
2. `scope`: affected subsystems and concrete modules/files.
3. `surface_area_delta`: new APIs, removed APIs, changed signatures.
4. `affected_contracts`: related bead IDs and linked contract/spec documents.
5. `operational_impact`: what operators need to know and do.
6. `risk_delta`: pre/post risk tier and rationale.
7. `compatibility`: backward + forward compatibility assessment.
8. `dependency_changes`: added/removed/updated dependencies.
9. `compatibility_and_threat_evidence`: compatibility test evidence + threat vector mitigations.

## JSON Template

```json
{
  "summary_id": "chg-YYYYMMDD-<slug>",
  "contract_version": "1.0",
  "change_summary": {
    "intent": "One-line intent statement.",
    "scope": {
      "subsystems": ["franken_node.connector"],
      "modules": ["crates/franken-node/src/connector/example.rs"]
    },
    "surface_area_delta": {
      "new_apis": [],
      "removed_apis": [],
      "changed_signatures": []
    },
    "affected_contracts": {
      "beads": ["bd-xxxx"],
      "documents": ["docs/specs/example_contract.md"]
    },
    "operational_impact": {
      "operator_notes": "Operational implications for rollout/monitoring.",
      "required_actions": ["Run migration check before deploy."],
      "rollout_notes": "Canary first, then full rollout."
    },
    "risk_delta": {
      "previous_tier": "medium",
      "new_tier": "low",
      "rationale": "Deterministic validation removed a manual failure mode."
    },
    "compatibility": {
      "backward_compatibility": "compatible",
      "forward_compatibility": "enables",
      "details": "Adds contract checks without changing runtime behavior."
    },
    "dependency_changes": {
      "added": [],
      "removed": [],
      "updated": []
    },
    "compatibility_and_threat_evidence": {
      "compatibility_test_suites": [
        {
          "suite_name": "tests/conformance/example_suite.rs",
          "pass_count": 12,
          "fail_count": 0,
          "artifact_path": "artifacts/11/example_compatibility_report.json"
        }
      ],
      "regression_risk_assessment": {
        "risk_level": "medium",
        "api_families": ["POST /v1/example", "CLI: franken-node example"],
        "notes": "Added validation in existing control path; no removed interfaces."
      },
      "threat_vectors": [
        {
          "vector": "privilege_escalation",
          "mitigation": "Capability checks are enforced at boundary admission."
        },
        {
          "vector": "data_exfiltration",
          "mitigation": "Sensitive payloads are redacted in transport logs."
        },
        {
          "vector": "denial_of_service",
          "mitigation": "Rate limits and bounded retries prevent unbounded amplification."
        }
      ]
    }
  }
}
```

## Enforcement

- CI gate: `.github/workflows/change-summary-contract-gate.yml`
- Validator: `scripts/check_change_summary_contract.py`
- Unit tests: `tests/test_check_change_summary_contract.py`
