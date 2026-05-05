# Operator JSON Contract Registry

`bd-mka4a` establishes a lightweight registry for operator-facing JSON outputs.
The registry lives in `crates/franken-node/src/operator_json_contracts.rs` and
uses `operator-json-contract-registry-v1.0` from `schema_versions.rs`.

## Contract Rule

Every registered surface records:

- command or route name
- schema id and version
- required fields that automation can depend on
- optional additive fields
- volatile diagnostic fields
- owner tests and gates

Removing or renaming a required field requires an explicit schema-version update.
Adding optional fields is allowed when existing required fields are preserved.
The registry is not a compatibility shim; it is a discoverable contract index and
validation helper.

## Registered Surfaces

- `doctor_report`
- `verify_release_report`
- `fleet_reconcile_report`
- `trust_card_export`
- `incident_bundle`
- `bench_run_report`
- `runtime_epoch_report`
- `remote_capability_issue_report`

## Redaction Guidance

Timestamp, path, signature, digest, trace-id, duration, and environment-dependent
fields must be normalized before golden comparisons. Redaction should preserve
field presence and semantic category while replacing only nondeterministic bytes.

## Validation

`validate_operator_json_value` fails when a required field is missing or null and
passes when extra optional fields are added. The `operator_json_contract_registry`
test module is included by the registered `cli_subcommand_goldens` target; it
validates existing golden JSON outputs and a negative fixture under
`artifacts/operator_json_contracts/`.
