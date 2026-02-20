# bd-1gx: Signed Extension Package Manifest Schema

## Bead: bd-1gx | Section: 10.4

## Purpose

Defines the canonical signed extension manifest contract used by registry
admission, trust-card generation, and policy evaluation. The schema extends
the engine-level `ExtensionManifest` with provenance, trust metadata, and
signature policy fields.

## Invariants

| ID | Statement |
|----|-----------|
| INV-EMS-CANONICAL-FIELDS | Every manifest includes deterministic top-level fields: `schema_version`, `package`, `entrypoint`, `capabilities`, `behavioral_profile`, `minimum_runtime_version`, `provenance`, `trust`, `signature`. |
| INV-EMS-ENGINE-COMPAT | Manifest validation must map to `frankenengine_extension_host::ExtensionManifest` and pass engine validation before admission. |
| INV-EMS-PROVENANCE-CHAIN | `provenance.attestation_chain` must contain at least one attestation reference with non-empty `id`, `attestation_type`, and `digest`. |
| INV-EMS-SIGNATURE-GATE | Signatures must be base64-like payloads; `threshold_ed25519` requires a valid threshold policy and `ed25519` forbids threshold metadata. |
| INV-EMS-LOG-CODES | Validation lifecycle emits stable audit codes: `MANIFEST_CREATED`, `MANIFEST_SIGNED`, `MANIFEST_VALIDATED`, `MANIFEST_REJECTED`. |

## Canonical Schema

- JSON Schema file: `schemas/extension_manifest.schema.json`
- Draft: 2020-12
- Version: `schema_version = "1.0"`

Top-level required fields:

1. `schema_version`
2. `package`
3. `entrypoint`
4. `capabilities`
5. `behavioral_profile`
6. `minimum_runtime_version`
7. `provenance`
8. `trust`
9. `signature`

## Field Model

### Package Identity (`package`)

- `name`: extension package name
- `version`: semantic version string
- `publisher`: publishing identity
- `author`: authored-by identity

### Capability Declaration (`capabilities`)

Enum values aligned with `franken_engine` extension host:

- `fs_read`
- `fs_write`
- `network_egress`
- `process_spawn`
- `env_read`

Constraints:

- At least one capability
- Unique capability entries

### Behavioral Profile (`behavioral_profile`)

- `risk_tier`: `low | medium | high | critical`
- `summary`: human-readable behavior synopsis
- `declared_network_zones`: declared external network zones

### Provenance Envelope (`provenance`)

- `build_system`
- `source_repository`
- `source_revision`
- `reproducibility_markers[]`
- `attestation_chain[]`
  - `id`
  - `attestation_type`
  - `digest`

### Trust Metadata (`trust`)

- `certification_level`: `community | verified | hardened | critical`
- `revocation_status_pointer`: pointer/URI into canonical revocation status
- `trust_card_reference`: pointer to trust-card materialization

### Signature Contract (`signature`)

- `scheme`: `ed25519 | threshold_ed25519`
- `publisher_key_id`
- `signature` (base64-like payload)
- `signed_at` (RFC-3339)
- `threshold` (required only for `threshold_ed25519`)
  - `threshold`
  - `total_signers`
  - `signer_key_ids[]`

## Versioning Strategy

- `schema_version` is pinned to `1.0` for this bead.
- Backward-compatible additions must be optional fields with explicit defaults.
- Breaking changes require a new schema version with side-by-side validator support.

## Validation + Error Codes

| Code | Trigger |
|------|---------|
| `EMS_SCHEMA_VERSION` | Schema version mismatch |
| `EMS_MISSING_FIELD` | Required field missing/empty |
| `EMS_EMPTY_CAPABILITIES` | No capabilities declared |
| `EMS_DUPLICATE_CAPABILITY` | Duplicate capability in manifest |
| `EMS_MISSING_ATTESTATION_CHAIN` | Empty provenance attestation chain |
| `EMS_SIGNATURE_MALFORMED` | Signature payload format invalid |
| `EMS_THRESHOLD_INVALID` | Invalid threshold signature configuration |
| `EMS_ENGINE_REJECTED` | Engine-level `ExtensionManifest` validation failed |

## Implementation Artifacts

- Rust module: `crates/franken-node/src/supply_chain/manifest.rs`
- JSON Schema: `schemas/extension_manifest.schema.json`
- Integration test: `tests/integration/extension_manifest_admission.rs`
- Verification script: `scripts/check_extension_manifest_schema.py`
- Verification evidence: `artifacts/section_10_4/bd-1gx/verification_evidence.json`
- Verification summary: `artifacts/section_10_4/bd-1gx/verification_summary.md`
