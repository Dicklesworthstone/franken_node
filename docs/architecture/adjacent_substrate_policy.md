# Adjacent Substrate Policy Contract (`bd-2owx`)

This document is the authoritative substrate policy for Section 10.16. It defines when `franken_node` modules must use adjacent substrates, when they should use them by default, and when optional use is acceptable with explicit rationale.

Sidecar manifest (CI-consumable): `artifacts/10.16/adjacent_substrate_policy_manifest.json`

## Canonical Scope Table

| Substrate | Version Constraint | Integration Plane |
|---|---|---|
| `frankentui` | `^0.1.0` | `presentation` |
| `frankensqlite` | `^0.1.0` | `persistence` |
| `sqlmodel_rust` | `^0.1.0` | `model` |
| `fastapi_rust` | `^0.1.0` | `service` |

## Tier Semantics

- `mandatory`: module scope is expected to bind this substrate directly; absence is a policy defect unless waived.
- `should_use`: default integration tier; deviations require documented rationale and owner review.
- `optional`: integration is permitted but not required for compliance.

Classification mode is `first_match`:
- checker evaluates `mandatory_modules`, then `should_use_modules`, then `optional_modules`
- first matching pattern is the effective tier

## Required Module Families

At minimum, policy classification covers:
- `crates/franken-node/src/connector/`
- `crates/franken-node/src/conformance/`
- `crates/franken-node/src/control_plane/`
- `crates/franken-node/src/runtime/`
- `crates/franken-node/src/security/`
- `crates/franken-node/src/supply_chain/`
- `crates/franken-node/src/cli.rs`
- `crates/franken-node/src/config.rs`

The sidecar manifest extends this to the full `crates/franken-node/src/**/*.rs` inventory.

## Exceptions And Waivers

Exceptions are declared in manifest `exceptions[]` entries:
- `module`
- `substrate`
- `reason`
- `waiver_required`

Waiver workflow reference: `bd-159q`.

Required waiver metadata fields:
- `risk_analysis`
- `scope`
- `owner_signoff`
- `expiry`

## Event Codes

- `SUBSTRATE_POLICY_LOADED` (info)
- `SUBSTRATE_POLICY_MODULE_UNMAPPED` (error)
- `SUBSTRATE_POLICY_SCHEMA_INVALID` (error)

## Machine-Readable Contract Block

<!-- POLICY_CONTRACT_START -->
{
  "policy_id": "bd-2owx-adjacent-substrate-policy",
  "schema_version": "1.0.0",
  "manifest_path": "artifacts/10.16/adjacent_substrate_policy_manifest.json",
  "classification_mode": "first_match",
  "waiver_reference_bead": "bd-159q",
  "waiver_required_metadata": [
    "risk_analysis",
    "scope",
    "owner_signoff",
    "expiry"
  ],
  "event_codes": [
    "SUBSTRATE_POLICY_LOADED",
    "SUBSTRATE_POLICY_MODULE_UNMAPPED",
    "SUBSTRATE_POLICY_SCHEMA_INVALID"
  ],
  "substrates": [
    {
      "name": "frankentui",
      "version": "^0.1.0",
      "plane": "presentation"
    },
    {
      "name": "frankensqlite",
      "version": "^0.1.0",
      "plane": "persistence"
    },
    {
      "name": "sqlmodel_rust",
      "version": "^0.1.0",
      "plane": "model"
    },
    {
      "name": "fastapi_rust",
      "version": "^0.1.0",
      "plane": "service"
    }
  ],
  "policy_hash": "sha256:50d65df5663a61811f3a363417e78113d69cb932895aed1797ba6f9debf3751d"
}
<!-- POLICY_CONTRACT_END -->
