# Evidence Verification Spine

`bd-hp1hy` defines one shared contract for verifier-facing evidence objects:
producer assertions are never verification evidence by themselves. A public
verification surface must derive its verdict from canonical content binding,
signer identity or trusted verification context, signature algorithm, parent or
chain membership, and a verifier-computed verdict.

## Contract Fields

Every participating surface must account for:

- `content_digest`: the verified bytes or commitment are derived from canonical
  content, not copied from producer metadata.
- `signer_key_id`: signature-bearing surfaces bind the signer key material or
  trusted signer identity into verification.
- `signature_algorithm`: signature-bearing surfaces reject missing, unsupported,
  or mismatched algorithms.
- `chain_parent_binding`: chain/capsule surfaces bind the parent link, declared
  input inventory, or trusted receipt-chain context.
- `producer_independent_verdict`: `verified=true` or equivalent producer claims
  cannot override a failed verifier computation.

## Live Surfaces

| Surface | Live verifier | Binding used by this contract |
| --- | --- | --- |
| Provenance attestation chain | `supply_chain::provenance::verify_attestation_chain` | Ed25519 link signatures, trusted signer keys, canonical link order, chain depth |
| Node universal replay capsule | `connector::universal_verifier_sdk::replay_capsule` | Ed25519 capsule signature metadata, canonical payload, exact input refs |
| External verifier SDK capsule | `frankenengine_verifier_sdk::capsule::replay` | Caller-provided verifying key, Ed25519 capsule signature, exact input refs |
| VEF evidence capsule | `vef::evidence_capsule::verify_all_with_context` | Derived receipt-chain commitment and trusted verification context |

The registered `evidence_verification_spine_contract` integration target loads
`artifacts/evidence_verification_spine/bd-hp1hy_fixture_matrix.json` and proves
the checked-in matrix against the live APIs above.

## Operator Explain Surface

`bd-6z0tq` exposes the shared spine through:

```bash
franken-node debug evidence --artifact <relative-json-path> --kind <kind> --json
```

Supported `kind` values are `auto`, `node-replay-capsule`,
`provenance-attestation`, and `vef-evidence-capsule`. The command emits
`franken-node/evidence-explain/v1` JSON with an ordered trace. Every trace step
has `check_id`, `input_artifact`, `expected_value`, `observed_value`, `verdict`,
and `recovery_hint`; human output is the same information rendered as compact
line-oriented fields.

The command delegates to the live verifier APIs listed above. It does not treat
producer-supplied `verified=true` metadata as evidence, and it exits non-zero
when any step fails. The contract artifact
`artifacts/evidence_explain/bd-6z0tq_contract.json` records the supported
artifact kinds and required negative fixture classes.
