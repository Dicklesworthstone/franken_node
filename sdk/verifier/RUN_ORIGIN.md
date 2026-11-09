# Authenticate the original run behind an incident bundle

An incident exporter and the original runtime can have different signing
authorities. Verifying a `.fnbundle` against its exporter key establishes who
signed the exported evidence. To also authenticate the original recorded run,
provide the runtime receipt authority's public key separately.

Both keys must come from the verifier's own trust configuration. A key carried
inside evidence never becomes a trust anchor. The same key can be supplied for
both roles when the verifier explicitly trusts it for both purposes.

A third independent product-root key can additionally authenticate the original
engine effect ledger. The product now exports its public session identity
capture with the incident, so this check works offline without access to the
producing machine or its protected key directory.

## Offline executable

```sh
franken-verifier verify --format incident-bundle \
  --trusted-key-hex "$TRUSTED_BUNDLE_PUBLIC_KEY" \
  --trusted-run-key-hex "$TRUSTED_RUN_PUBLIC_KEY" < incident.fnbundle
```

Successful verification returns `scope: "authenticated_run_incident"`. Its
`facts.run_origin` contains the authenticated `receipt_id`, `receipt_hash`,
`signer_public_key_hex` for the supplied run authority, and `record_sha256` for
the exact carried original record bytes. It does not return captured source,
receipt paths, telemetry, or the signed record itself.

Supplying `--trusted-run-key-hex` requires an original run proof. A historical
bundle without one fails with `RUN_ORIGIN_MISSING`; verification never falls
back to the weaker scope. A wrong original authority produces
`RUN_ORIGIN_SIGNATURE_INVALID`. The option applies only to `incident-bundle`.

Omitting this option preserves the existing one-key interface and
`authenticated_recorded_incident` scope. That result does not authenticate the
original run statement, including when the bundle happens to carry one.

To require the original engine ledger's session signature as well:

```sh
franken-verifier verify --format incident-bundle \
  --trusted-key-hex "$TRUSTED_BUNDLE_PUBLIC_KEY" \
  --trusted-run-key-hex "$TRUSTED_RUN_PUBLIC_KEY" \
  --trusted-runtime-key-hex "$TRUSTED_PRODUCT_ROOT_PUBLIC_KEY" < incident.fnbundle
```

The third key requires the run key. Success has scope
`authenticated_runtime_incident` and adds `facts.runtime_origin` with
`session_nonce`, `product_root_key_id`, `producer_id`, `evidence_key_id` and
`signed_epoch`. The epoch is a canonical decimal string, preserving every u64
value in JavaScript. Missing portable evidence fails with
`RUNTIME_ORIGIN_MISSING`; a foreign root, invalid capture signature and invalid
engine signature have distinct `RUNTIME_ORIGIN_*` errors. None silently falls
back to the one-key or two-key scope.

## Rust

```rust
use ed25519_dalek::VerifyingKey;
use frankenengine_verifier_sdk::incident_bundle::{
    IncidentBundleError, VerifiedIncidentBundleWithRunOrigin,
    verify_incident_bundle_with_run_key,
};

fn audit_original_run(
    bytes: &[u8],
    trusted_exporter: &VerifyingKey,
    trusted_run_authority: &VerifyingKey,
) -> Result<VerifiedIncidentBundleWithRunOrigin, IncidentBundleError> {
    verify_incident_bundle_with_run_key(bytes, trusted_exporter, trusted_run_authority)
}
```

The result separates ordinary bundle facts in `bundle` from original-run
attribution in `run_origin`. The existing `verify_incident_bundle` function and
`VerifiedIncidentBundle` return type remain unchanged.

For engine ledger authentication, call
`verify_incident_bundle_with_runtime_keys(bytes, trusted_exporter,
trusted_run_authority, trusted_product_root)`. It returns
`VerifiedIncidentBundleWithRuntimeOrigin`, retaining `bundle` and `run_origin`
and adding `runtime_origin: VerifiedRuntimeOrigin`. The Rust epoch field is
`u64`; its serialized form is a decimal string.

## JavaScript, TypeScript, and Python

The language bindings pass the original bytes and explicit keys to a separately
installed, trusted `franken-verifier`. They require the returned stronger scope
and check that its original-run public key equals the requested key.

```javascript
const verified = await verifyArtifact(bytes, trustedExporterHex, {
  verifier: "/trusted/bin/franken-verifier",
  trustedRunPublicKeyHex: trustedRunAuthorityHex,
});
console.log(verified.facts.run_origin.receipt_id);
```

```python
verified = verify_artifact(
    data,
    trusted_exporter_hex,
    verifier="/trusted/bin/franken-verifier",
    trusted_run_public_key_hex=trusted_run_authority_hex,
)
print(verified["facts"]["run_origin"]["receipt_id"])
```

Add `trustedRuntimePublicKeyHex: trustedProductRootHex` in JavaScript/TypeScript
or `trusted_runtime_public_key_hex=trusted_product_root_hex` in Python to require
runtime-origin verification. The bindings validate the returned root identity,
scope and exact decimal epoch. Missing metadata, downgraded scope, rounded
epochs and unsolicited claims are refused.

## What the stronger verification establishes

The verifier first performs all existing bundle checks: the trusted exporter
signature, canonical integrity and decision hashes, complete timeline and
chunk structure, independently rehashed effect receipt chains, and any native
capture's structural and source-byte integrity checks. It then verifies the
original run record under the independent receipt authority and requires:

- Matching receipt identity and hash in the signed record, its complete signed
  receipt snapshot, and the bundle's initial state.
- Matching recorded application and policy metadata within the record and
  receipt, and the same bundle policy and security-control declarations.
- Exact equality of every original host-effect entry with the bundle timeline,
  plus matching counts, chain head, and internal engine trace.
- Exact equality of the native capture envelope with the original record,
  including its signed receipt's payload-digest binding and failure declaration.
- A finalized receipt, without interruption evidence. A zero-effect run's
  terminal event must use its original receipt end time, normalized to UTC
  microseconds.

The operator trace ID and internal engine ledger trace ID are separate producer
identities; verification does not force them to be equal.

These checks authenticate the receipt authority's recorded statement. They do
not recompute the product's typed receipt-identity preimage, verify the engine
session certificate or separate ledger signature, rebuild module resolution,
execute the guest, or certify native execution equivalence. Actual native
replay remains a separate product operation.

With the third key, the SDK additionally checks the product-root signature on
the exact v1 session identity, its runtime authority class, derived public-key
ID and initial key lineage. It requires the original ledger's producer, key and
provenance to match that identity and its signed epoch to be at or after key
activation. It then verifies the ledger's detached Ed25519 signature over the
original ordered receipt bytes and all ledger summary fields. Lab identities,
unsupported rotations, pre-activation signatures and substituted session keys
fail even when the bundle exporter and run-record signer approve the change.

This is original ledger attribution. It does not execute the guest, rederive
the typed receipt ID, resolve module graphs, certify effect commitment or
quiescence, establish current revocation state, or prove historical completeness.
The native replay payload remains bound by the receipt-authority statement;
the separate engine signature covers its host-effect ledger.

## Portable origin envelope and signature compatibility

The exporter carries this object in `initial_state_snapshot.run_origin`:

```json
{
  "schema_version": "franken-node/incident-run-origin/v1",
  "record_json": "<the original authenticated run-record JSON text>"
}
```

The record is carried as a string because original signed telemetry can contain
finite floating-point values, while the enclosing bundle's canonical hash
format rejects floats. The verifier rejects duplicate members in the nested
JSON, including escaped duplicate keys, before checking the original signature.
The standalone SDK enables `serde_json/float_roundtrip` to match the producer's
number parsing exactly.

The original signature protocol remains unchanged: remove only
`record_signature`, recursively sort JSON object members, encode compact JSON,
and prepend `franken-node/run-host-effect-ledger-record-signature/v1` followed
by one zero byte. Verify the resulting bytes with Ed25519 under the caller's
run authority. There is no length prefix. Unknown signed record members remain
in the signature preimage. The raw carried record is never narrowed to a typed
subset or re-signed by the exporter.

## Portable engine identity and existing signature protocols

`initial_state_snapshot.runtime_evidence_identity_capture` carries the complete
original public `franken-node/runtime-evidence-identity-capture/v1` object.
It contains the session nonce, product-root key identity, engine public identity
and root signature. No private seed is exported. The outer bundle authenticates
this member without changing or re-signing the original `record_json`; a
verifier must still supply the product-root anchor independently.

The SDK reproduces the existing producer encodings exactly:

- Root capture: ordered typed JSON without `signature_hex`, prefixed with
  `franken-node.runtime-evidence-identity-capture.v1` and a big-endian u64 payload
  length, verified under the supplied product root.
- Ledger payload: ordered typed JSON without its signature, prefixed with
  `franken-node:host-effect-ledger-signature:v3` plus a zero byte and a big-endian
  u64 payload length.
- Engine detached signature: JSON tuple of
  `franken-engine.detached-evidence-signature.v1`, framed ledger payload as a
  byte array, and the original ordered envelope with both signature halves
  replaced by zero arrays. Verification uses only the authenticated session key.

The capture is bounded to 64 KiB and the encoded ledger to the product's 24 MiB
native-response ceiling. Encoding itself is bounded before expanding the
detached protocol's byte array. Duplicate JSON members, unknown identity fields
and unsupported schema or provenance are rejected, with diagnostics that do
not include private captured values. Older exports without a portable identity
retain their previous narrower verification scope until the product can
re-export their retained authenticated public capture.
