# Bounded Input Policy Registry

`crates/franken-node/src/capacity_defaults.rs` is the shared source of truth
for bounded-input policy metadata. New cap hardening work should keep the
owning module's stable cap constant local, then publish a
`BoundedInputPolicy` with:

- surface name
- field name
- cap value
- stable error code
- stable audit code
- short rationale

The policy helper rejects one-past-cap inputs before downstream hash,
signature, JSON parse, or duplicate-scan work. The owning module still maps the
violation into its local error type so callers do not need compatibility shims.

## Representative Matrix

| Surface | Policy Constant | Cap | Error Code | Audit Code | Rationale |
| --- | --- | ---: | --- | --- | --- |
| `control_plane.audience_token` | `TOKEN_FIELD_INPUT_POLICY` | 4096 bytes | `ERR_ABT_TOKEN_TOO_LARGE` | `AUDIT_BOUNDED_INPUT_REJECTED` | Reject overlong token fields before hash/signature work. |
| `control_plane.audience_token` | `TOKEN_AUDIENCE_INPUT_POLICY` | 256 entries | `ERR_ABT_TOKEN_TOO_LARGE` | `AUDIT_BOUNDED_INPUT_REJECTED` | Bound token audience fanout before preimage construction. |
| `control_plane.audience_token` | `TOKEN_PREIMAGE_INPUT_POLICY` | 65536 bytes | `ERR_ABT_TOKEN_TOO_LARGE` | `AUDIT_BOUNDED_INPUT_REJECTED` | Bound canonical signature preimage growth before allocation. |
| `control_plane.audience_token` | `TOKEN_SIGNATURE_INPUT_POLICY` | 136 bytes | `ERR_ABT_TOKEN_TOO_LARGE` | `AUDIT_BOUNDED_INPUT_REJECTED` | Reject overlong signatures before hex decode and verification. |
| `extensions.artifact_contract` | `ARTIFACT_TOKEN_INPUT_POLICY` | 256 bytes | `ERR_ARTIFACT_INVALID_CONTRACT` | `AUDIT_BOUNDED_INPUT_REJECTED` | Reject overlong artifact identifiers before admission hashing/comparison. |
| `extensions.artifact_contract` | `ARTIFACT_CAPABILITY_LIST_POLICY` | 16384 entries | `ERR_ARTIFACT_INVALID_CONTRACT` | `AUDIT_BOUNDED_INPUT_REJECTED` | Bound capability list validation before duplicate scans and signature checks. |
| `control_plane.fleet_transport` | `FLEET_ACTION_RECORD_LINE_POLICY` | 4096 bytes | `ERR_BOUNDED_INPUT_CAP_EXCEEDED` | `AUDIT_BOUNDED_INPUT_REJECTED` | Bound fleet action JSONL lines before serde allocates a full record. |

## Conformance

`crates/franken-node/tests/bounded_input_policy_contract.rs` is included by the
registered `extension_artifact_contract_conformance` target. It proves the
matrix has stable names, error codes, audit code, non-zero caps,
one-past-cap rejection, and coverage across the three representative surfaces.
