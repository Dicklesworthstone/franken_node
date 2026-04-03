# bd-21z: Signed Decision Receipt Export

## Bead: bd-21z | Section: 10.5

## Purpose

Implement cryptographically signed, append-only decision receipts for
high-impact policy/control actions. Receipts are deterministic, queryable,
and exportable in machine-readable (JSON/CBOR) and human-readable (Markdown)
formats for audit, incident response, and verifier workflows.

Live CLI receipt export is an operator-trust surface. Production export paths
must use operator-managed signing material and must never fall back to a
built-in demo key or implicit trust root.

## Invariants

| ID | Statement |
|----|-----------|
| INV-RECEIPT-CANONICAL | Receipts are signed over canonical JSON (sorted keys, compact encoding). |
| INV-RECEIPT-SIGNATURE | Receipt signatures use Ed25519 detached signatures and must verify against canonical payloads. |
| INV-RECEIPT-CHAIN | Receipt stream is append-only and hash-chained via `previous_receipt_hash` + `chain_hash`. |
| INV-RECEIPT-HIGH-IMPACT | High-impact actions must produce receipts or the operation is rejected. |
| INV-RECEIPT-EXPORT | Receipt exports support JSON and CBOR round-trip fidelity and query filtering by action/time window. |
| INV-RECEIPT-NO-IMPLICIT-KEY | Live receipt export never succeeds with built-in demo signing material or any implicit trust root. |
| INV-RECEIPT-PROVENANCE | Exported signed receipts identify the signing key via a deterministic key ID so verification inputs are explicit. |

## Types

### `Decision`
- Enum: `Approved`, `Denied`, `Escalated`

### `Receipt`
- `receipt_id: String` (UUID v7)
- `action_name: String`
- `actor_identity: String`
- `timestamp: String` (RFC 3339)
- `input_hash: String` (`SHA-256` hex)
- `output_hash: String` (`SHA-256` hex)
- `decision: Decision`
- `rationale: String`
- `evidence_refs: Vec<String>`
- `policy_rule_chain: Vec<String>`
- `confidence: f64`
- `rollback_command: String`
- `previous_receipt_hash: Option<String>`

### `SignedReceipt`
- Flattened `Receipt`
- `signer_key_id: String` (deterministic key identifier derived from verifying key bytes)
- `chain_hash: String`
- `signature: String` (base64 Ed25519 detached signature)

### `ReceiptQuery`
- `action_name: Option<String>`
- `from_timestamp: Option<String>`
- `to_timestamp: Option<String>`
- `limit: Option<usize>`

### `HighImpactActionRegistry`
- Runtime registry of action names requiring receipts.
- Default classes:
  - `quarantine`
  - `revocation`
  - `policy_change`
  - `deployment_promotion`
  - `trust_level_transition`

## API Surface

- `sign_receipt(receipt, signing_key) -> SignedReceipt`
- `verify_receipt(signed, public_key) -> Result<bool, ReceiptError>`
- `append_signed_receipt(chain, receipt, signing_key) -> SignedReceipt`
- `verify_hash_chain(receipts) -> Result<(), ReceiptError>`
- `enforce_high_impact_receipt(action_name, registry, receipt) -> Result<(), ReceiptError>`
- `export_receipts(receipts, query) -> Vec<SignedReceipt>`
- `export_receipts_json(receipts, query) -> Result<String, ReceiptError>`
- `export_receipts_cbor(receipts, query) -> Result<Vec<u8>, ReceiptError>`
- `import_receipts_cbor(bytes) -> Result<Vec<SignedReceipt>, ReceiptError>`
- `export_receipts_to_path(receipts, query, path) -> Result<(), ReceiptError>`
- `write_receipts_markdown(receipts, path) -> Result<(), ReceiptError>`

## Operational Signing Material Contract

### Live export trigger

Receipt signing is only attempted when an operator explicitly requests
`--receipt-out` and/or `--receipt-summary-out`. Commands that do not request
export must not require signing material.

### Signing-material discovery order

For live CLI flows, signing-material discovery is deterministic and fail-closed:

1. Command-local `--receipt-signing-key <path>`
2. `FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH`
3. Resolved config value `security.decision_receipt_signing_key_path`
4. Otherwise: fail the command with a clear error that receipt export was
   requested but no signing key was configured

There is no built-in production fallback and no ambient demo key.

### Accepted key formats

The live receipt-signing key file contains an Ed25519 private seed and may be
encoded as one of:

- raw 32-byte seed bytes
- hex-encoded 32-byte seed
- base64-encoded 32-byte seed

If the file is unreadable or does not decode to a valid Ed25519 signing seed,
receipt export fails closed with an operator-facing error.

### Provenance and trust-root handling

- Every exported `SignedReceipt` carries `signer_key_id`, derived
  deterministically from the signing key's verifying key bytes.
- Operator-facing logs and summaries must report which signing source was used
  (`cli`, `env`, or `config`) and which `signer_key_id` produced the export.
- Receipt verification must use explicit operator-managed public keys; it must
  not assume a built-in verification key.
- Receipt key IDs should use the same derivation scheme as release verification
  so operators do not have to reason about two incompatible key-identification
  models.

### Deterministic test-fixture injection

- Deterministic demo keys remain allowed only in test fixtures, integration
  harnesses, or `test-support` helpers.
- Test code must inject fixture keys explicitly via helper APIs or temporary key
  files; production code must not import a demo signing helper into live
  command paths.
- Verification scripts and artifacts must distinguish fixture-only keys from
  live operator-managed trust roots.

## Error Codes

| Code | Trigger |
|------|---------|
| `RECEIPT_MISSING_HIGH_IMPACT` | High-impact action did not produce a receipt. |
| `RECEIPT_SIGNATURE_INVALID` | Signature cannot be decoded or fails verification. |
| `RECEIPT_HASH_CHAIN_MISMATCH` | Hash-chain linkage or computed chain hash does not match. |
| `RECEIPT_TIMESTAMP_PARSE_ERROR` | Timestamp parsing failed for time-window filtering. |
| `RECEIPT_EXPORT_WRITE_FAILED` | Export target cannot be written. |
| `RECEIPT_SIGNING_KEY_MISSING` | Receipt export was requested without configured signing material. |
| `RECEIPT_SIGNING_KEY_INVALID` | Signing material could not be decoded as a valid Ed25519 private key. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/security/decision_receipt.rs` |
| Module export | `crates/franken-node/src/security/mod.rs` |
| CLI surface | `crates/franken-node/src/cli.rs`, `crates/franken-node/src/main.rs` |
| Integration tests | `tests/integration/decision_receipt_export.rs` |
| Verification script | `scripts/check_signed_receipt.py` |
| Python verification tests | `tests/test_check_signed_receipt.py` |
| Fixture | `fixtures/security/decision_receipt_samples.json` |
| Receipt artifact | `artifacts/section_10_5/bd-21z/decision_receipt_chain.json` |
| Verification evidence | `artifacts/section_10_5/bd-21z/verification_evidence.json` |
| Verification summary | `artifacts/section_10_5/bd-21z/verification_summary.md` |
