# bd-21z: Signed Decision Receipt Export

## Bead: bd-21z | Section: 10.5

## Purpose

Implement cryptographically signed, append-only decision receipts for
high-impact policy/control actions. Receipts are deterministic, queryable,
and exportable in machine-readable (JSON/CBOR) and human-readable (Markdown)
formats for audit, incident response, and verifier workflows.

## Invariants

| ID | Statement |
|----|-----------|
| INV-RECEIPT-CANONICAL | Receipts are signed over canonical JSON (sorted keys, compact encoding). |
| INV-RECEIPT-SIGNATURE | Receipt signatures use Ed25519 detached signatures and must verify against canonical payloads. |
| INV-RECEIPT-CHAIN | Receipt stream is append-only and hash-chained via `previous_receipt_hash` + `chain_hash`. |
| INV-RECEIPT-HIGH-IMPACT | High-impact actions must produce receipts or the operation is rejected. |
| INV-RECEIPT-EXPORT | Receipt exports support JSON and CBOR round-trip fidelity and query filtering by action/time window. |

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

## Error Codes

| Code | Trigger |
|------|---------|
| `RECEIPT_MISSING_HIGH_IMPACT` | High-impact action did not produce a receipt. |
| `RECEIPT_SIGNATURE_INVALID` | Signature cannot be decoded or fails verification. |
| `RECEIPT_HASH_CHAIN_MISMATCH` | Hash-chain linkage or computed chain hash does not match. |
| `RECEIPT_TIMESTAMP_PARSE_ERROR` | Timestamp parsing failed for time-window filtering. |
| `RECEIPT_EXPORT_WRITE_FAILED` | Export target cannot be written. |

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
