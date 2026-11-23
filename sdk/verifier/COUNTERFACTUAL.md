# Authenticate a counterfactual against its incident

The `counterfactual-incident` format verifies an incident bundle and a signed
counterfactual receipt together. It authenticates the baseline, requires that it
matches the verifier's independently retained integrity hash, and checks that
the receipt refers to the same incident, original policy, capture time, and
complete ordered event population.

This is authentication and context binding. The SDK does not run JavaScript,
recompute the policy model, or establish that alternate decisions would occur.
Every successful result explicitly returns `guest_execution_verified: false`.
Use the product's native replay operation when execution is required.

## Trust configuration

Supply these values from your own trust configuration:

| Value | Role |
| --- | --- |
| `--trusted-key-hex` | Ed25519 authority for the counterfactual receipt. |
| `--trusted-incident-key-hex` | Ed25519 authority for the incident bundle exporter. |
| `--expected-baseline-integrity-hash` | The exact incident selected for this verification: 64 lowercase hexadecimal digits, without a `sha256:` prefix. |
| `--signature-hex` | The detached 64-byte counterfactual receipt signature, encoded as 128 hexadecimal digits. |

The expected hash is the incident bundle's authenticated `integrity_hash`,
retained independently before accepting the candidate counterfactual. It is
neither the raw file's SHA-256 nor the transport envelope's SHA-256. Do not learn
this pin or any trust anchor from the candidate. The exporter and receipt keys
are separate trust roles; the same key is valid for both only when your policy
explicitly assigns it both roles.

## Transport and CLI

The input contains the original `.fnbundle` bytes as canonical standard base64
and the original counterfactual output as a JSON value:

```json
{
  "schema_version": "franken-verifier/counterfactual-incident-input/v1",
  "baseline_bundle_base64": "<base64 of the complete .fnbundle file>",
  "counterfactual_output": { "<original counterfactual output members>": "..." }
}
```

Construct the transport from existing files without changing the baseline:

```sh
python3 - <<'PY' > counterfactual-incident.json
import base64
import json
from pathlib import Path

envelope = {
    "schema_version": "franken-verifier/counterfactual-incident-input/v1",
    "baseline_bundle_base64": base64.b64encode(
        Path("incident.fnbundle").read_bytes()
    ).decode("ascii"),
    "counterfactual_output": json.loads(Path("counterfactual.json").read_bytes()),
}
print(json.dumps(envelope, separators=(",", ":"), allow_nan=False))
PY

franken-verifier verify --format counterfactual-incident \
  --trusted-key-hex "$TRUSTED_COUNTERFACTUAL_PUBLIC_KEY" \
  --trusted-incident-key-hex "$TRUSTED_BUNDLE_PUBLIC_KEY" \
  --expected-baseline-integrity-hash "$EXPECTED_BASELINE_INTEGRITY_HASH" \
  --signature-hex "$COUNTERFACTUAL_SIGNATURE_HEX" \
  < counterfactual-incident.json
```

The detached signature authenticates the canonical counterfactual output, not
the outer transport JSON. The incident retains its own exporter signature.
The complete input envelope is limited to 64 MiB. The composed verifier accepts
one result or a nonempty sweep of at most 20 results.

The top-level successful scope is always
`authenticated_counterfactual_incident`. Its facts contain the pinned
`baseline_integrity_hash`, `counterfactual_output_sha256` for the canonical
signed output, the receipt's `signer_public_key_hex`, `mode`, `result_count`,
`baseline_scope`, the authenticated incident facts in `baseline`, and
`guest_execution_verified: false`. The top-level `artifact_sha256` instead
identifies the exact input envelope bytes.

To require original-run attribution, also supply
`--trusted-run-key-hex "$TRUSTED_RUN_PUBLIC_KEY"`. To additionally authenticate
the original engine ledger, supply that run key and
`--trusted-runtime-key-hex "$TRUSTED_PRODUCT_ROOT_PUBLIC_KEY"`. The nested
`baseline_scope` is respectively `authenticated_recorded_incident`,
`authenticated_run_incident`, or `authenticated_runtime_incident` for the
selected trust level. Missing or invalid requested origin evidence fails;
verification never silently falls back. See [RUN_ORIGIN.md](RUN_ORIGIN.md) for
the origin proof's exact scope.

## Python

```python
from pathlib import Path
from franken_verifier import verify_artifact

verified = verify_artifact(
    Path("counterfactual-incident.json").read_bytes(),
    trusted_counterfactual_public_key_hex,
    verifier="/trusted/bin/franken-verifier",
    format="counterfactual-incident",
    trusted_incident_public_key_hex=trusted_bundle_public_key_hex,
    expected_baseline_integrity_hash=expected_baseline_integrity_hash,
    signature_hex=counterfactual_signature_hex,
)
print(verified["facts"]["baseline"]["incident_id"])
assert verified["facts"]["guest_execution_verified"] is False
```

Optional `trusted_run_public_key_hex` and `trusted_runtime_public_key_hex`
strengthen the nested incident proof. The runtime key requires the run key.

## JavaScript and TypeScript

```javascript
import { readFile } from "node:fs/promises";
import { verifyArtifact } from "./franken_verifier.mjs";

const verified = await verifyArtifact(
  await readFile("counterfactual-incident.json"),
  trustedCounterfactualPublicKeyHex,
  {
    verifier: "/trusted/bin/franken-verifier",
    format: "counterfactual-incident",
    trustedIncidentPublicKeyHex: trustedBundlePublicKeyHex,
    expectedBaselineIntegrityHash,
    signatureHex: counterfactualSignatureHex,
  },
);
if (verified.format !== "counterfactual-incident") throw new Error("unexpected format");
console.log(verified.facts.baseline.incident_id);
console.log(verified.facts.guest_execution_verified); // always false
```

The corresponding optional options are `trustedRunPublicKeyHex` and
`trustedRuntimePublicKeyHex`. TypeScript exposes required
`CounterfactualIncidentOptions` and `CounterfactualIncidentFacts`, whose
`baseline_scope` distinguishes the available origin metadata. Both language
bindings reject responses with substituted keys, a different baseline hash,
unexpected origin metadata, an incorrect proof scope, or an execution claim.

The Rust API is `counterfactual::verify_counterfactual_incident` with
`CounterfactualIncidentTrust`. The separate `counterfactual-receipt` format
continues to authenticate only a receipt and its claimed baseline hash; it does
not authenticate the baseline bundle or establish original-run attribution.
