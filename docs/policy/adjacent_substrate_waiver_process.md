# Adjacent Substrate Waiver Process (`bd-159q`)

## Purpose

This policy defines a controlled, auditable waiver workflow for justified exceptions to adjacent substrate rules. Waivers are temporary, scoped, and fail closed on expiry.

## Scope

This workflow applies to adjacent substrate policy enforcement for modules in `crates/franken-node/src` using the canonical substrate manifest:

- `artifacts/10.16/substrate_dependency_matrix.json`

## Required Waiver Fields

Every waiver record must include:

- `waiver_id`: stable unique identifier (`waiver-<date>-<slug>` style recommended)
- `module`: exact module path from substrate manifest
- `substrate`: adjacent substrate name (`frankentui`, `frankensqlite`, `sqlmodel_rust`, `fastapi_rust`)
- `rules_waived`: one or more explicit rule IDs
- `risk_analysis`: concrete risks and mitigations
- `scope_description`: bounded exception scope (what is waived and what is not)
- `owner`: accountable owner
- `approved_by`: approver identity
- `granted_at`: RFC3339 timestamp (UTC)
- `expires_at`: RFC3339 timestamp (UTC)
- `remediation_plan`: concrete plan to remove waiver dependency
- `status`: `active` | `expired` | `revoked`

## Rule Namespace

Waiver rule IDs must resolve against the substrate policy manifest using this namespace:

- `adjacent-substrate.module-listed`
- `adjacent-substrate.<integration_type>.<substrate>`

Examples:

- `adjacent-substrate.mandatory.frankensqlite`
- `adjacent-substrate.should_use.sqlmodel_rust`
- `adjacent-substrate.optional.fastapi_rust`

## Approval Workflow

1. Requester submits waiver draft with all required fields.
2. Reviewer validates bounded scope and risk analysis.
3. Approver signs off (`approved_by`) and sets expiry.
4. Waiver is recorded in `artifacts/10.16/waiver_registry.json`.
5. CI validation enforces status, expiry, and cross-reference integrity.

## Maximum Duration

- Maximum waiver duration: **90 days**.
- Longer durations are invalid and fail validation.

## Expiry Enforcement

- `active` waiver with `expires_at` in the past is a hard validation failure.
- Expired waivers must be marked `expired`; they do not implicitly renew.
- Renewal requires a **new waiver** with updated risk analysis and remediation plan.

## Revocation

- Waivers can be revoked before expiry by setting `status` to `revoked`.
- Revocation does not remove the audit record.

## Audit Trail And Event Codes

Validation and workflow events must emit stable event codes:

- `WAIVER_GRANTED` (info)
- `WAIVER_EXPIRED` (warning)
- `WAIVER_REVOKED` (info)
- `WAIVER_VALIDATION_FAIL` (error)
- `WAIVER_CROSS_REF_FAIL` (error)

All events include:

- `waiver_id`
- `module`
- trace correlation (`trace_id` or equivalent run identifier)

## Registry Schema (Reference)

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-02-20T00:00:00Z",
  "max_waiver_duration_days": 90,
  "waivers": [
    {
      "waiver_id": "waiver-2026-02-20-example",
      "module": "crates/franken-node/src/connector",
      "substrate": "frankensqlite",
      "rules_waived": [
        "adjacent-substrate.mandatory.frankensqlite"
      ],
      "risk_analysis": "...",
      "scope_description": "...",
      "owner": "owner-name",
      "approved_by": "approver-name",
      "granted_at": "2026-02-20T00:00:00Z",
      "expires_at": "2026-05-01T00:00:00Z",
      "remediation_plan": "...",
      "status": "active"
    }
  ]
}
```
