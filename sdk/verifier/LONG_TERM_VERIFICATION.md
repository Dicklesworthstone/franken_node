# Verify long-term evidence against an approved suite policy

Long-term verification checks that an artifact marker was included in a retained
log, that the retained roots form a valid re-attestation chain, and that a pinned
witness quorum observed the final root before the requested time and before any
applicable compromise recorded in the approved policy. It does not execute the
artifact.

The witness trust anchor includes both the witness authority and the crypto-suite
policy. An authentic historical witness signature does not establish when a
cryptographic suite became compromised. That information must come from an
independently approved policy.

## Required anchor fields

`LongTermWitnessTrustAnchor` requires all four fields:

| Field | Meaning |
| --- | --- |
| `witness_group_id` | Approved group named by the witness statement |
| `witness_policy_id` | Approved witness policy named by that statement |
| `threshold_config` | Required threshold, signer count, and independently approved public keys |
| `suite_records` | Complete approved crypto-suite validity and compromise records |

Each suite record contains `crypto_suite` and `valid_from_unix_seconds`, with
optional `valid_until_unix_seconds` and `compromised_at_unix_seconds`. Times are
unsigned 64-bit Unix seconds. A validity interval includes both endpoints; a
compromise cutoff is exclusive, so an observation exactly at the cutoff fails.
There must be between 1 and 128 records. Every record is validated, including
records following the first applicable interval. Unknown anchor fields and
unknown suite-record fields are refused.

Candidate evidence must retain the same ordered suite records as the approved
anchor. The verifier uses the anchor's records for the actual validity and
compromise decisions. Removing a compromise, moving its timestamp, changing a
validity interval, adding an unapproved suite, or dropping a record fails even
if every historical witness signature remains authentic. A separate record for
an already compromised classical suite does not invalidate an approved hybrid
suite; all compromise records for the artifact's own suite still apply.

The anchor is a policy snapshot. Successful verification does not establish that
it is the newest snapshot, that it includes every compromise, or that an omitted
compromise marker means the suite can never be compromised. Obtain the policy
and any freshness requirement from the operator's trusted configuration.

## Rust callers and producers

The verifier API keeps its explicit out-of-band anchor:

```rust
use frankenengine_verifier_sdk::{
    LongTermVerificationEvidence, LongTermWitnessTrustAnchor, VerificationVerdict,
    VerifierSdk,
};

fn accepted_under_approved_policy(
    evidence: &LongTermVerificationEvidence,
    approved: &LongTermWitnessTrustAnchor,
) -> bool {
    VerifierSdk::new("verifier://retained-artifact-audit")
        .verify_as_of_ltv(evidence, approved)
        .is_ok_and(|result| result.verdict == VerificationVerdict::Pass)
}
```

Historical anchor JSON without `suite_records` is rejected. Upgrade it through
the independently trusted policy channel. Do not copy the records from the
candidate artifact to fill the missing field.

`LongTermEvidenceRequest` now takes `suite_records` instead of
`suite_valid_from_unix_seconds`. Supply the approved policy's complete records;
the builder retains them unchanged and refuses evidence inconsistent with them.
Its internal self-check establishes producer consistency. Before publishing,
verify the built evidence against the independently approved witness anchor as
well, so different witness keys, thresholds, groups, or policies cannot be
published as approved evidence. `franken-node ltv attest --witness-anchor`
performs that producer-side check.

## Portable signed policy transport

The offline CLI accepts the existing
`franken-verifier/ltv-evidence-input/v1` envelope:

```json
{
  "schema_version": "franken-verifier/ltv-evidence-input/v1",
  "witness_anchor_base64": "<base64 of the complete approved anchor JSON bytes>",
  "witness_anchor_signature_hex": "<128 lowercase hex characters>",
  "evidence": { "...": "the retained LTV evidence" }
}
```

The detached Ed25519 signature covers the exact decoded anchor bytes, including
the suite records. The signature message is the ASCII domain
`franken-verifier/ltv-witness-anchor/v1:`, followed by the byte length as a
little-endian u64, followed by those exact bytes. The decoded anchor is limited
to 65,536 bytes. The envelope cannot choose the trusted root key:

```sh
franken-verifier verify --format ltv-evidence \
  --trusted-key-hex "$APPROVED_POLICY_ROOT_KEY" < ltv-input.json
```

A verified response has scope `authenticated_ltv_anteriority`. Its
`facts.trust_policy_sha256` is the plain lowercase SHA-256 of the exact signed
anchor bytes. It identifies both the approved witness authority and the approved
suite policy. Whitespace changes in newly signed anchor JSON change this digest.
The digest is an audit identifier, not a freshness or rollback guarantee.

Malformed or missing policy produces `EVIDENCE_INVALID`; unauthenticated anchor
changes produce `SIGNATURE_INVALID`; policy mismatches, applicable compromises,
bad timelines, and insufficient witness signatures produce
`LTV_ANTERIORITY_REJECTED`. Rejections contain no private evidence values.

## Python, JavaScript, and TypeScript

Use `format="ltv-evidence"` in Python or `format: "ltv-evidence"` in JavaScript
and TypeScript, with the independently approved policy root public key and a
trusted verifier executable. The bindings require `trust_policy_sha256` on a
successful response and independently compare it with the hash of the exact
anchor bytes in the submitted envelope. They refuse an older response without
that policy binding. They do not reserialize evidence, promote candidate policy
to a trust anchor, or round u64 time facts; time facts remain decimal strings.

The independent language-client matrix builds the Merkle commitments, witness
messages, threshold signatures, and root-signed policy envelopes using Node's
cryptography and explicit public wire encodings. Its positive controls include
pre-compromise evidence, historical verification after a later compromise,
hybrid policy, and maximum-u64 timestamps. Negative controls retain the original
witness signatures while deleting or changing compromise policy, and also cover
missing legacy policy, malformed trusted records, changed root-signed bytes,
foreign authority, and threshold failure.
