# Public API Fixtures Provenance

## Generation Method

These fixtures are checked-in golden artifacts for the verifier SDK public API
conformance harness in `sdk/verifier/tests/public_api_contract.rs`.
They use deterministic but live-shape values so the harness can freeze JSON
contracts without teaching stale mock-only formats.

## Deterministic Live Values Used

- **Timestamps**: Fixed RFC 3339 / RFC 3339-like UTC strings such as
  `2026-04-21T12:00:00.000000Z`, `2026-04-21T12:00:00Z`, and the
  bundle timeline sequence rooted at `2026-04-21T00:00:00.000000Z`
- **Digests**: Bare lowercase 64-nybble SHA-256 hex values with no
  `sha256:` prefix
- **Signatures**: Bare lowercase 64-nybble hex fixture values matching the
  current public JSON contract for `verifier_signature`, `step_signature`,
  and `signature.signature_hex`
- **Verifier Identity**: Stable verifier URI `verifier://facade-test`
- **Bundle / Incident IDs**: Stable live-shape IDs such as
  `facade-bundle-001`, `facade-incident-001`, and `evt-facade-001`
- **Counters**: Minimal predictable values such as `step_index: 1`,
  `leaf_index: 0`, and `tree_size: 1`

## Fixture Files

### facade_result.json
- **Source**: Frozen `VerificationResult` JSON shape
- **Purpose**: Golden reference for the main verifier facade result contract
- **Key Fields**: Bare 64-hex `artifact_binding_hash`, bare 64-hex
  `verifier_signature`, `verifier://facade-test`, and the current
  `vsdk-v1.0` SDK version

### session_step.json
- **Source**: Frozen `SessionStep` JSON shape
- **Purpose**: Golden reference for session step format
- **Key Fields**: `step_index`, operation/verdict enums, bare 64-hex
  `artifact_binding_hash`, RFC 3339 timestamp, and bare 64-hex `step_signature`

### transparency_entry.json
- **Source**: Frozen `TransparencyLogEntry` JSON shape
- **Purpose**: Golden reference for transparency log format
- **Key Fields**: Bare 64-hex `result_hash`, `verifier://facade-test`, and
  a Merkle proof array shaped as `root:<digest>`, `leaf_index:<usize>`,
  `tree_size:<usize>`, then optional `left:<digest>` / `right:<digest>` steps

### bundle_canonical.json
- **Source**: Frozen canonical `ReplayBundle` JSON from `bundle.rs`
- **Purpose**: Golden reference for canonical bundle format
- **Key Fields**: `facade-bundle-001`, `facade-incident-001`,
  `verifier://facade-test`, canonical artifact/chunk digests, and sealed
  `integrity_hash` / `signature.signature_hex`

### error_matrix.json
- **Source**: Frozen expected display strings for public bundle / SDK errors
- **Purpose**: Expected error display format testing
- **Structure**: Organized by error category (bundle_errors, sdk_errors)

### api_manifest.json
- **Source**: Frozen extraction of the public verifier SDK surface
- **Purpose**: API contract metadata and breaking change policies
- **Structure**: Constants, enums, structures, functions, and breaking-change
  policy with `frozen_at` metadata

## Regeneration Instructions

To regenerate these fixtures if the API changes:

1. **Constants / manifest**: Refresh `api_manifest.json` from
   `sdk/verifier/src/lib.rs` and `sdk/verifier/src/bundle.rs`
2. **Enums / structures**: Keep serde field names and required fields aligned
   with the live public structs
3. **Fixture values**: Preserve deterministic timestamps and IDs, but keep
   hashes and signatures in the same live wire format the harness enforces:
   bare lowercase 64-hex strings with no algorithm prefix
4. **Transparency proof**: Preserve the proof entry contract
   `root:/leaf_index:/tree_size:/left:/right:`
5. **Validation**: Run
   `rch exec -- cargo test --manifest-path sdk/verifier/Cargo.toml --test public_api_contract public_api_conformance_suite -- --nocapture`
   and confirm the fixture-backed API contract cases pass

Do not reintroduce legacy placeholder values such as `sha256:...`,
`deadbeef...`, or `test-verifier-deterministic`; those no longer describe the
checked-in public API contract.

## Last Updated

- 2026-04-21 - Initial fixture set for the verifier public API conformance harness
- 2026-04-23 - Fixture contracts refreshed to match the live verifier surface
- 2026-04-24 - Provenance guidance updated to match the enforced live fixture formats (`bd-2w7jg`)

## SDK Version Compatibility

These fixtures are compatible with SDK version `vsdk-v1.0` and replay bundle schema `vsdk-replay-bundle-v1.0`.
