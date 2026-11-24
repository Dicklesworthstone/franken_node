# Signed verification sessions with an independent request policy

A signed session authenticates a verifier's recorded decisions. To require those
decisions to answer a particular audit request, supply a policy established
independently of the candidate transcript. The SDK, offline CLI, Python client,
and JavaScript/TypeScript client can all enforce the same exact policy.

## Policy contract

A policy is a UTF-8 JSON object with this shape:

```json
{
  "schema_version": "franken-verifier/signed-session-policy/v1",
  "session_id": "release-audit-2026-11-24",
  "verifier_identity": "verifier://release-auditor",
  "steps": [
    {
      "operation": "trust_state",
      "artifact_binding_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "verdict": "pass"
    }
  ]
}
```

The hash above is illustrative. Supply the actual operation-specific artifact
commitment from independently trusted expected inputs. Do not copy the policy
from the transcript being admitted: doing that would merely accept the
candidate's own description of its work.

The verifier requires exact session and verifier identities, exact step count,
and the listed order of operations, artifact commitments, and recorded verdicts.
Additional, missing, reordered, or substituted steps fail admission.

- Session IDs contain 1–255 ASCII letters, digits, dots, underscores, or hyphens.
- Verifier identities use `verifier://` followed by 1–255 of those characters.
- Operations are `claim`, `migration_artifact`, `trust_state`,
  `long_term_validation`, `workflow`, or `workflow_execution`.
- Artifact commitments are exactly 64 lowercase hexadecimal characters, without
  a `sha256:` prefix.
- Verdicts are `pass`, `fail`, or `inconclusive`.
- Policies admit at most 1,024 steps and 256 KiB of source bytes, including
  whitespace. Unknown fields, duplicate decoded JSON member names, missing
  fields, and alternate array/map representations are refused.

Use a fresh caller-assigned session ID when an earlier valid session must not
satisfy a new request. The policy does not itself implement expiry or a consumed
request registry.

## Offline CLI

```sh
franken-verifier verify \
  --format signed-session \
  --trusted-key-hex "$SESSION_SIGNER_PUBLIC_KEY_HEX" \
  --trusted-session-policy expected-session.json \
  < signed-session.json
```

The trusted key must come from the caller's enrolled authority, separately from
the candidate transcript. The policy flag is accepted only for
`signed-session`. The CLI requires a bounded regular policy file; on Unix it
opens the descriptor without blocking on a substituted FIFO.

After policy validation, the CLI authenticates the signed session before
comparing its contents with the request. A validly signed different audit
returns `SESSION_POLICY_MISMATCH`; signature failures retain
`SIGNATURE_INVALID`. Malformed, oversized, and unreadable policies return
`SESSION_POLICY_INVALID`, `SESSION_POLICY_TOO_LARGE`, and
`SESSION_POLICY_IO`, respectively. Diagnostics omit policy contents and paths.

Successful output retains the `authenticated_verification_session` scope and
adds `facts.trusted_session_policy_sha256`, the lowercase SHA-256 digest of
**the exact policy file bytes that were parsed and matched**. Whitespace changes
therefore change this digest. The field is absent when no policy was supplied.

A successful authentication response does not mean that all recorded checks
passed. `facts.final_verdict` remains `pass`, `fail`, or `inconclusive`.
An empty requested session remains inconclusive; a nonempty session passes only
when every recorded step passes. A caller requiring a passing audit should put
`pass` in each required step.

## Rust

```rust,ignore
use frankenengine_verifier_sdk::{
    SignedSessionTranscript, VerifierSdk, parse_signed_session_policy,
};

let policy = parse_signed_session_policy(&std::fs::read("expected-session.json")?)?;
let transcript: SignedSessionTranscript =
    serde_json::from_slice(&std::fs::read("signed-session.json")?)?;
VerifierSdk::verify_signed_session_with_policy(&trusted_signer_key, &transcript, &policy)?;
```

Callers may also construct `SignedSessionPolicy` and `SignedSessionStepPolicy`
directly. The SDK validates those values before using them. Continue using
`verify_signed_session` when only transcript authentication is required.

## Python and JavaScript

Supply an explicitly trusted verifier executable and the independent policy
path using the existing client entry points:

```python
result = verify_artifact(
    transcript_bytes,
    trusted_public_key_hex,
    verifier="/trusted/bin/franken-verifier",
    format="signed-session",
    trusted_session_policy_path="expected-session.json",
)
```

```javascript
const result = await verifyArtifact(transcriptBytes, trustedPublicKeyHex, {
  verifier: "/trusted/bin/franken-verifier",
  format: "signed-session",
  trustedSessionPolicyPath: "expected-session.json",
});
```

Both clients validate and retain the policy before invoking the CLI. They
require the response to contain its exact byte digest and matching public
session facts, rejecting a changed policy file or a narrower response as
`PROTOCOL_INVALID`. Calls without a policy continue to require the original
response shape and reject an unsolicited policy digest.

## Workflow commitment versions

New `verify_workflow_execution` results use the
`frankenengine-verifier-sdk:workflow-integrity:v2:` hash domain. Their
commitment includes the length-prefixed workflow identity, stage count, and,
in sorted stage-name order, each length-prefixed stage name, authenticated
bundle integrity hash, and selected raw Ed25519 public key. Lengths and the
stage count are unsigned 64-bit little-endian integers.

New `execute_workflow` results use the separate
`frankenengine-verifier-sdk:validation-workflow-integrity:v1:` domain,
followed by the length-prefixed mode name, bundle integrity hash, and selected
public key. Mode names are `release_validation`, `incident_validation`, and
`compliance_audit`.

These commitments distinguish different stage populations, names, modes, and
signing authorities. Existing signed transcripts remain authenticatable;
new policies pinning the strengthened commitments will not match older
workflow commitments. Obtain new workflow results when migrating such policies.

## Evidence boundary

Matching a policy authenticates the selected signer's recorded workflow and
checks that it answers the caller's exact request. It does not independently
re-execute steps, certify their private keyed result tags, establish current
freshness, or prove runtime completion. Those claims need their own evidence
and admission rules.
