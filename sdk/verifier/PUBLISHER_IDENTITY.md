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
Matching a graph pin alone preserves `capsule.graph_hash_recomputed: false`.
An optional graph-report witness can independently verify the commitment
preimage, as described below. Neither operation reconstructs parser/resolver
semantics, executes code, or authorizes a workload.

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
the ordinary verification APIs retain their existing behavior. The optional
graph-report APIs additionally return `PublisherSourceError::GraphReportInvalid`
when a witness fails.

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

## Verify the graph report commitment

A source capsule contains the graph hash and the recorded source observations.
It does not contain the complete report that was hashed. To check that
commitment independently, supply the exact capture's serialized
`SourceGraphReport` as an additional witness:

```sh
franken-verifier verify --format publisher-source \
  --trusted-key-hex "$TRUSTED_PUBLISHER_KEY" \
  --signature-hex "$REGISTRATION_SIGNATURE" \
  --expected-manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --graph-report captured-source-graph.json \
  < publisher-source.json
```

The file must contain the report object itself, such as the JSON serialization
of `CapturedModuleGraph::report()`, without a surrounding command-response
envelope. Both `franken-node/module-source-graph/v2` and
`franken-node/module-source-graph/v3` are supported. JSON object ordering and
whitespace may differ; array order, field values, explicit nulls, and the
producer's optional-field omission rules remain part of the commitment.

The standalone SDK uses its own schema and serialization to clear only
`input_hash`, recompute the versioned SHA-256 commitment, and compare it with
the graph hash authenticated inside the signed source capsule. It also binds
every report probe to the capsule's complete ordered observations, checks module
and resolution-target byte identities, and checks package-map manifest hashes
against captured bytes. Manifest routes through recorded workspace symlinks
resolve against the capsule inventory; no source pathname is opened on the
auditor's machine.

Successful source facts include a separate summary:

```json
{
  "graph_report": {
    "schema_version": "franken-verifier/source-graph-commitment/v1",
    "graph_hash_recomputed": true,
    "graph_semantics_reconstructed": false
  }
}
```

The full summary additionally identifies the graph hash, capsule digest, raw
report-file SHA-256, inventory counts, and the producer's
`declared_fully_resolved` claim. It omits private source text, paths, specifiers,
and diagnostics. The original `capsule.graph_hash_recomputed` remains false
because capsule inspection alone supplies no report witness. Without this
option, the original response has no `graph_report` field.

**Commitment verification does not independently derive the dependency graph.**
An authenticated producer can still make an incorrect parser or resolver claim.
`graph_semantics_reconstructed: false` is explicit even when the report says
it is fully resolved. This feature supplies no native execution, runtime
completeness, type-checking, release-certification, or new provenance claim.

The same option works with `publisher-source-trust`. Existing signature,
revocation freshness, provenance, and expected-release policies all run before
a witness is attached. A valid report cannot repair a revoked publisher, foreign
release, invalid signature, or mismatched provenance statement.

Rust callers can use:

- `verify_publisher_source_with_graph_report` for separate signed manifest,
  capsule, and report bytes.
- `verify_publisher_source_input_with_graph_report` for the portable source
  transport and an optional `PublisherSourceExpectedIdentity`.
- `verify_publisher_source_trust_input_with_graph_report` for the trust
  transport, explicit authorities/freshness policy, report bytes, and optional
  expected identity.

Graph reports are bounded to `MAX_SOURCE_GRAPH_REPORT_BYTES` (32 MiB) before
JSON decoding. Duplicate keys, unknown fields, trailing JSON, unsupported
schemas, incomplete observations, mismatched commitments, and noncanonical
field omissions are refused. The CLI reads only a regular report file and
returns `GRAPH_REPORT_IO`, `INPUT_TOO_LARGE`, or `GRAPH_REPORT_INVALID` without
echoing private witness contents.
