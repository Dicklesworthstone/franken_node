# Require an expected publisher release

Publisher authentication establishes who signed a source capsule. A deployment
or audit can additionally require the exact release selected by its own trusted
configuration. This rejects a valid signature over a different version or
execution authority from the same publisher.

The primary pin is the SHA-256 of the **exact signed manifest bytes**. Obtain it
from the approved release record or another independently trusted channel. A pin
calculated only from the candidate being checked does not establish that the
candidate is the intended release. Whitespace changes to a newly signed manifest
change this pin even when its parsed JSON values are equal.

All pins use `sha256:` followed by exactly 64 lowercase hexadecimal digits.

| Pin | Commits to |
| --- | --- |
| `expected_manifest_sha256` | Exact publisher-signed registration bytes, including version, capsule content hash, and declared runtime authority |
| `expected_source_artifact_sha256` | Optional raw SHA-256 of the FNSGCAP1 source-capsule bytes |
| `expected_graph_input_hash` | Optional graph commitment authenticated inside that capsule |

The supplemental pins require the manifest pin. The raw source-artifact pin is
different from the domain-separated `capsule_digest` and from the CLI's top-level
`artifact_sha256`, which identifies the complete transport supplied on stdin.
Matching a graph commitment preserves `graph_hash_recomputed: false`: the SDK
does not reconstruct resolution, execute code, or authorize a workload.

## Offline CLI

```sh
franken-verifier verify --format publisher-source \
  --trusted-key-hex "$TRUSTED_PUBLISHER_KEY" \
  --signature-hex "$REGISTRATION_SIGNATURE" \
  --expected-manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --expected-source-artifact-sha256 "$APPROVED_SOURCE_ARTIFACT_SHA256" \
  --expected-graph-input-hash "$APPROVED_GRAPH_INPUT_HASH" \
  < publisher-source.json
```

The same three options work with `publisher-source-trust`, alongside its
independent revocation/provenance authorities and explicit freshness policy.
Identity matching does not bypass those checks. Other formats refuse these
options. No expected identity is taken from the transport itself.

`EXPECTED_IDENTITY_INVALID` means the caller's pins are malformed, incomplete,
or used with another format. `EXPECTED_IDENTITY_MISMATCH` means authenticated
source facts differ from a requested pin. Errors contain neither the supplied
pin nor candidate values. Successful response schemas and proof scopes remain
unchanged.

## Rust

```rust
use ed25519_dalek::VerifyingKey;
use frankenengine_verifier_sdk::publisher_source::{
    PublisherSourceIdentityError, PublisherSourceExpectedIdentity, VerifiedPublisherSource,
    verify_publisher_source_input_with_expected_identity,
};

fn verify_approved_release(
    packet: &[u8],
    signature: &[u8; 64],
    publisher: &VerifyingKey,
    approved_manifest_sha256: String,
) -> Result<VerifiedPublisherSource, PublisherSourceIdentityError> {
    let expected = PublisherSourceExpectedIdentity {
        manifest_sha256: approved_manifest_sha256,
        source_artifact_sha256: None,
        graph_input_hash: None,
    };
    verify_publisher_source_input_with_expected_identity(
        packet, signature, publisher, &expected,
    )
}
```

`verify_publisher_source_with_expected_identity` accepts separate manifest and
capsule bytes. `verify_publisher_source_trust_input_with_expected_identity` adds
the same requirement to the portable trust transport;
`verify_publisher_source_with_trust_policy_and_expected_identity` accepts its
separate source and trust-policy inputs. Each validates expected identities
before decoding candidate input and compares authenticated facts before success.
Existing APIs remain available for callers who require publisher authentication
without an exact release policy. New APIs use `PublisherSourceIdentityError`,
which preserves underlying failures in its `Source(PublisherSourceError)` variant;
the existing error enum and its exhaustive matches remain unchanged.

## JavaScript, TypeScript, and Python

```javascript
const verified = await verifyArtifact(packetBytes, trustedPublisherKey, {
  verifier: "/trusted/bin/franken-verifier",
  format: "publisher-source",
  signatureHex: registrationSignature,
  expectedManifestSha256: approvedManifestSha256,
  expectedSourceArtifactSha256: approvedSourceArtifactSha256,
  expectedGraphInputHash: approvedGraphInputHash,
});
```

```python
verified = verify_artifact(
    packet_bytes,
    trusted_publisher_key,
    verifier="/trusted/bin/franken-verifier",
    format="publisher-source",
    signature_hex=registration_signature,
    expected_manifest_sha256=approved_manifest_sha256,
    expected_source_artifact_sha256=approved_source_artifact_sha256,
    expected_graph_input_hash=approved_graph_input_hash,
)
```

Both bindings validate pins before launching a child, forward them as distinct
arguments, and independently compare the authenticated response facts against
the requested identity. An otherwise valid child success that ignores the pins
is refused. These checks also apply to `publisher-source-trust`, whose source
facts are nested under `facts.source`.
