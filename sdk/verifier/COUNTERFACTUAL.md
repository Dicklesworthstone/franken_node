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

## Verify signed promotion reports from the product

Use `counterfactual-promotion` for the existing
`franken-node/incident-counterfactual-report/v2` JSON produced by
`franken-node incident counterfactual --json --promote`. It consumes the
promotion, rollout, and rollback signatures already emitted by that command.
A separate signature over raw simulation output is not required.

The independently configured primary key is the promotion operator's public
key. The incident exporter key and retained baseline integrity pin remain
separate inputs. The verifier authenticates all three receipts, their action
and audience bindings, the executor-specific counterfactual digest, the
rollout/rollback contract digests, and their relationship to the selected
incident. A synthetic report cannot be relabeled as a production report.

Preserve the exact report bytes when transporting them. Receipt confidence and
contract fields use full-width integers; parsing and reserializing a report
with an ordinary JavaScript JSON number can change the signed values.

For an already retained incident bundle, the product command is:

```sh
franken-node incident counterfactual \
  --bundle incident.fnbundle \
  --trusted-public-key keys/replay-trust-anchor.pub \
  --policy strict --json --promote \
  --promotion-signing-key keys/promotion-signing.key \
  --operator-id incident-operator > promotion-report.json
```

The two key files have separate roles: the replay trust anchor contains the
incident exporter's hex public key; the promotion signing file contains the
operator's hex Ed25519 seed. External verification needs the corresponding
public keys and the baseline pin retained before receiving the candidate report.

Wrap the retained incident and the emitted report without reserializing either:

```sh
python3 - <<'PY' > counterfactual-promotion.json
import base64
import json
from pathlib import Path

print(json.dumps({
    "schema_version": "franken-verifier/counterfactual-promotion-input/v1",
    "baseline_bundle_base64": base64.b64encode(
        Path("incident.fnbundle").read_bytes()
    ).decode("ascii"),
    "report_base64": base64.b64encode(
        Path("promotion-report.json").read_bytes()
    ).decode("ascii"),
}, separators=(",", ":")))
PY

franken-verifier verify --format counterfactual-promotion \
  --trusted-key-hex "$TRUSTED_PROMOTION_OPERATOR_PUBLIC_KEY" \
  --trusted-incident-key-hex "$TRUSTED_BUNDLE_PUBLIC_KEY" \
  --expected-baseline-integrity-hash "$EXPECTED_BASELINE_INTEGRITY_HASH" \
  < counterfactual-promotion.json
```

The three-field transport requires canonical standard base64, rejects unknown
members, and is bounded to 64 MiB in total. The signed report must include all
three promotion receipts. An ordinary unpromoted report and the distinct native
counterfactual report do not supply this promotion evidence.

Python uses the same trust options with the new format:

```python
verified = verify_artifact(
    Path("counterfactual-promotion.json").read_bytes(),
    trusted_promotion_operator_public_key_hex,
    verifier="/trusted/bin/franken-verifier",
    format="counterfactual-promotion",
    trusted_incident_public_key_hex=trusted_bundle_public_key_hex,
    expected_baseline_integrity_hash=expected_baseline_integrity_hash,
)
assert verified["scope"] == "authenticated_counterfactual_promotion"
assert verified["facts"]["guest_execution_verified"] is False
assert verified["facts"]["rollout_authorized"] is False
```

JavaScript and TypeScript use:

```javascript
const verified = await verifyArtifact(
  await readFile("counterfactual-promotion.json"),
  trustedPromotionOperatorPublicKeyHex,
  {
    verifier: "/trusted/bin/franken-verifier",
    format: "counterfactual-promotion",
    trustedIncidentPublicKeyHex: trustedBundlePublicKeyHex,
    expectedBaselineIntegrityHash,
  },
);
if (verified.format !== "counterfactual-promotion") {
  throw new Error("unexpected verification format");
}
console.log(verified.facts.executor, verified.facts.mitigation_id);
```

Do not supply a detached signature option for this format: the signatures are
embedded in the original report. Optional original-run and runtime authority
options strengthen the nested incident proof in the same way as
`counterfactual-incident`.

The successful scope is `authenticated_counterfactual_promotion`. Facts include
the exact report-byte digest, operator identity and public key, authenticated
executor (`synthetic` or `production`), counterfactual and promotion-contract
digests, mitigation identity, result population, nested baseline scope/facts,
and signed validity interval. `expected_loss_delta`,
`valid_from_epoch_ms`, and `valid_until_epoch_ms` are canonical decimal
strings so Python, JavaScript, and TypeScript preserve the complete signed-i64
range.

This is historical authentication of a signed simulation and its mitigation
contracts. The loss estimate remains the signed model's assessment. The verifier
does not consult the current clock or confer current rollout permission:
`guest_execution_verified` and `rollout_authorized` are always false.
Execution, current policy eligibility, freshness, and deployment remain separate
operator decisions.
