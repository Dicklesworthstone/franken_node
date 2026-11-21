# Capability-Carrying Extension Artifact Format (bd-3ku8)

## Scope

This contract defines the admission and runtime enforcement protocol for
capability-carrying extension artifacts in `franken_node`. Every extension
artifact must carry an embedded capability contract that declares the exact
set of capabilities the extension requires. Admission is **fail-closed**:
missing or invalid capability contracts cause immediate rejection. At runtime,
the enforced capability envelope must match the admitted contract without drift.

## Core Invariants

- `INV-ARTIFACT-FAIL-CLOSED`: artifact admission denies any artifact whose capability contract is absent, malformed, or fails validation.
- `INV-ARTIFACT-CAPABILITY-ENVELOPE`: the runtime capability envelope exactly matches the admitted capability set; no capability outside the contract is accessible.
- `INV-ARTIFACT-NO-DRIFT`: runtime enforcement continuously verifies that the active capability set has not drifted from the admitted contract.
- `INV-ARTIFACT-SIGNED-CONTRACT`: capability contracts must carry a valid signature from a trusted signer.

## Admission Rules

1. Artifact must contain a `capability_contract` field.
2. Capability contract must include `contract_id`, `extension_id`, `capabilities`, `signer_id`, `signature`, and `schema_version`.
3. Every capability entry must specify `capability_id`, `scope`, and `max_calls_per_epoch`.
4. Contract signature must pass strict Ed25519 verification against the independently configured public key for its signer ID.
5. Contract `schema_version` must match the expected admission schema.
6. If any rule fails, admission is denied (fail-closed).

### Signature and trust-anchor encoding

`signature` is `ed25519-v1:` followed by exactly 128 lowercase hexadecimal
digits (the 64-byte Ed25519 signature). The signed message is the UTF-8 bytes of
`franken-node/capability-contract-signature/v1:` followed by the 64 lowercase
hexadecimal digits returned by `compute_contract_digest`. That digest retains
the existing `artifact_contract_digest_v1:` domain and length-prefixed byte
layout, binding the contract ID, extension ID/version, artifact ID, payload
hash, signer ID, schema, ordered capability IDs/scopes/call budgets, and issue
epoch. Its historical digest vectors remain unchanged.

The digest alone is public integrity metadata and is never an admission
signature. Historical unkeyed digest strings are rejected; they gain no signing
authority from a trusted-looking signer name or an existing trust card.

`AdmissionConfig.trusted_signers` maps independently supplied signer IDs to
32-byte Ed25519 public keys encoded as 64 lowercase hexadecimal digits.
`with_signer(id, &verifying_key)` registers a bounded trust anchor; registering
the same ID/key is idempotent, while replacing an existing ID with a different
key is rejected. Contract fields cannot supply or replace an admission key.
Malformed or absent selected anchors, foreign signing keys, and over-capacity
signer registries fail closed.
Legacy configurations containing only signer-name lists must be replaced with
explicit public-key mappings.

`compute_contract_signature`, `make_contract`, and `make_artifact` require an
explicit signing key. The artifact constructors remain fixture utilities;
their synthetic payload hashes do not verify externally installed payload
bytes. This library admission/enforcement contract is a prerequisite for the
broader signed source and runtime authority integration tracked by
`bd-reality-20260923-26n9r.28`.

## Required prefix checkpoints for capability envelopes

`MacaroonCapabilityEnvelope::verify` and `to_enforcement_engine` require an
independently trusted `CapabilityEnvelopeCheckpoint`. It contains the required
caveat count and the commitment tag at exactly that prefix. The constructor
`from_trusted_parts` accepts at most 64 caveats and exactly 64 lowercase
hexadecimal digits for the tag. Its fields are private, and it has no Serde
deserialization implementation: received envelope metadata cannot itself
establish a trusted checkpoint.

The caller must retain the checkpoint from trusted policy issuance or regenerate
it independently from authenticated authority and trusted policy. For example,
where `trusted_count` and `trusted_tag` come from that independent source:

```rust
let checkpoint = CapabilityEnvelopeCheckpoint::from_trusted_parts(
    trusted_count,
    trusted_tag,
)?;
let ceiling = candidate.verify(Some(&trusted_publisher), &checkpoint)?;
```

Verification rejects candidates shorter than the required prefix and compares
the recomputed prefix tag in constant time. A zero-caveat checkpoint still pins
the root, including its capability ceiling. Publisher signatures for signed
contract roots, every caveat commitment, layer ordering, the final tail tag,
and monotonic narrowing remain checked. A mismatched or missing required
prefix returns `ERR_ARTIFACT_REQUIRED_PREFIX_MISMATCH` before returning an
effective ceiling or constructing an enforcement engine.

The HMAC construction uses public root inputs and exposes intermediate tags.
These tags are commitments, not secret-key delegation authority. They do not
authenticate the actors named by registry, deployment, or module-edge layer
labels. The `VerifiedPublisherApproval` root variant holds approval metadata;
its name and publisher public key alone do not authenticate those fields.
Its trusted checkpoint must originate in a context that has already verified
the publisher's signatures and source closure.

A verified envelope may append stricter caveats after the required prefix.
Such an unpinned suffix remains removable or replaceable with another valid
suffix within the pinned ceiling. If module-edge restrictions are mandatory,
the trusted checkpoint must include those restrictions. The registry admission
helper pins its own locally regenerated envelope from the previously
authenticated approval and current trusted configuration; it does not accept
a received envelope as its checkpoint source. Approval `validate()` checks
structure and does not replace publisher authentication.

This requirement changes the Rust verification API while preserving the v1
envelope wire format. It establishes the required policy prefix. The native
publisher-approved execution path now applies the supported host, environment,
capability, and invocation predicates at the host-effect boundary as described
below. Filesystem path caveats and nonempty module-scope caveats cannot be
enforced by that provider and are rejected before execution. They must not be
treated as effective restrictions merely because envelope verification succeeds.

## Publisher-signed native host restrictions

A v2 publisher-approved source capsule may include an optional `host_io` object
inside its existing `runtime_authority`. The complete object participates in
the authority commitment and publisher signature. For example, an authority
that already declares `network_egress`, `env_read`, and `fs_read` can narrow them
with:

```json
{
  "host_io": {
    "host_ports": ["api.example.com:443", "[::1]:8443"],
    "env_keys": ["APP_REGION", "NODE_ENV"],
    "max_calls_per_epoch": {
      "network_egress": 8,
      "env_read": 4,
      "fs_read": 32
    }
  }
}
```

This is a fragment of `runtime_authority`, not a complete registration manifest.
The publisher signs it with the rest of the authority and source capsule.
Changing or removing it after signing invalidates approval. Omitting `host_io`
preserves the canonical signed representation of existing authorities.

The restrictions have these meanings:

- `host_ports` is an optional set of exact, canonical lowercase endpoints with
  explicit ports. IPv6 addresses use brackets. Wildcards, URL paths, userinfo,
  and implicit ports are not accepted. At most 128 endpoints are supported.
- `env_keys` is an optional set of at most 128 exact ASCII names, each 1–128
  bytes using letters, digits, or underscore. It is intersected with the
  operator's `runtime.environment_allowlist`; publisher approval never exposes
  an otherwise unapproved host variable. Publisher execution refuses operator
  environment scopes that the bounded envelope cannot represent.
- `max_calls_per_epoch` accepts only declared host capabilities: `fs_read`,
  `fs_write`, `network_egress`, `random_read`, `env_read`, and `process_spawn`. A limit cannot
  exceed the authority's instruction ceiling. These counters cover one native
  execution, reset for a new run, and are not distributed fleet quotas.
- `process_spawn` counts each guest process-provider call: synchronous run,
  spawn, stdin write/close, wait, and kill. It is a call budget, not a child
  count. An asynchronous spawn and its scheduled wait consume separate calls.
  An admitted attempt consumes budget even if cancellation or the
  independently signed process policy later refuses it, or the native provider
  fails. Supervisor-owned handle cleanup remains available after exhaustion;
  a guest cannot use that cleanup path to escape its budget. Neither a quota
  nor its absence grants process-spawn authority.
- An omitted scope leaves that dimension unrestricted by the publisher. An
  explicit empty endpoint/key set denies the corresponding effect family;
  a zero invocation budget denies every invocation of that capability.

Every request is checked before accessing the environment snapshot, reaching
the host-I/O WAL, or invoking the real provider. Scope violations do not spend
quota. Authorized attempts reserve their invocation budget before calling the
provider, including attempts whose provider subsequently returns an error:
an error does not establish that no side effect occurred. Quota reservation
is synchronized across calls to the same execution provider. Denied requests
remain in the engine's I/O transcript. Refusal incidents can replay when the
engine finalizes a supported completed or typed-failure capture. Some filesystem
provider denials currently become engine internal errors rather than supported
typed failures; those incidents remain uncapturable and cannot establish replay
equivalence.

These restrictions only narrow authority. The runtime profile, sandbox,
current containment state, IFC rules, SSRF protection, and separately signed
process-spawn admission still apply. In particular,
`security.network_policy.allowlist` remains an SSRF exception list; it is not
repurposed as an exclusive egress destination scope. Filesystem path restrictions
are not specified by `host_io`; process execution still requires the operator's
separately signed admission and executable policy.

Native replay captures the effective ceiling used by publisher-approved
execution. Replay validates the recorded request sequence against a fresh
instance of the same authority evaluator before consuming recorded outcomes;
it does not perform live host effects. A publisher-scope denial must match the
recorded denial, and missing or inconsistent scope context cannot establish
policy-equivalent replay. This bounded integration contributes to
`bd-reality-20260923-26n9r.29`; it does not close the broader module-authority or
independent qualification work.

## Enforcement Rules

1. At runtime, the enforced capability set is the intersection of the admitted contract capabilities and the runtime policy.
2. Any capability invocation outside the admitted envelope triggers an enforcement violation.
3. Periodic drift checks compare the active capability set against the admitted contract.
4. Drift detection triggers an immediate enforcement event and optional quarantine.

## Capability Contract Schema

Required fields:

- `contract_id`
- `extension_id`
- `extension_version`
- `artifact_id`
- `payload_hash` (lowercase SHA-256 hexadecimal digest)
- `capabilities` (array of `CapabilityEntry`)
- `signer_id`
- `signature`
- `schema_version`
- `issued_epoch_ms`

### CapabilityEntry

- `capability_id`
- `scope` (e.g., `"filesystem:read"`, `"network:egress"`)
- `max_calls_per_epoch`

## Event Codes

- `ARTIFACT_ADMISSION_START`
- `ARTIFACT_CAPABILITY_VALIDATED`
- `ARTIFACT_ADMISSION_ACCEPTED`
- `ARTIFACT_ENFORCEMENT_CHECK`
- `ARTIFACT_DRIFT_DETECTED`

## Error Codes

- `ERR_ARTIFACT_MISSING_CONTRACT`
- `ERR_ARTIFACT_INVALID_CAPABILITY`
- `ERR_ARTIFACT_SIGNATURE_INVALID`
- `ERR_ARTIFACT_SCHEMA_MISMATCH`
- `ERR_ARTIFACT_ENFORCEMENT_DRIFT`
- `ERR_ARTIFACT_ADMISSION_DENIED`
- `ERR_ARTIFACT_REQUIRED_PREFIX_MISMATCH`

## Required Artifacts

- `crates/franken-node/src/extensions/artifact_contract.rs`
- `crates/franken-node/src/extensions/mod.rs`
- `tests/conformance/capability_artifact_admission.rs`
- `artifacts/10.17/capability_artifact_vectors.json`
- `artifacts/section_10_17/bd-3ku8/verification_evidence.json`
- `artifacts/section_10_17/bd-3ku8/verification_summary.md`
