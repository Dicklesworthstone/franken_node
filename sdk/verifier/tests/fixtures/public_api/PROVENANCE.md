# Public API Fixtures Provenance

## Source of Truth

These files are checked-in contract fixtures for the verifier SDK public API.
They are not historical mock examples. The authoritative behavior comes from:

- `sdk/verifier/tests/public_api_contract.rs`
- `sdk/verifier/tests/conformance_harness.rs`
- `sdk/verifier/src/lib.rs`
- `sdk/verifier/src/bundle.rs`

If this document disagrees with those files, the code and tests win.

## Live Contract Shape

The fixtures use stable values, but they must stay in the same wire format that
the live verifier surfaces enforce:

- **Digests**: bare lowercase 64-hex strings with no `sha256:` prefix
- **Signatures**: bare lowercase 64-hex strings for
  `verifier_signature`, `step_signature`, and `signature.signature_hex`
- **Verifier identity**: URI form such as `verifier://facade-test`
- **Timestamps**: RFC 3339 UTC strings
- **Merkle proof entries**:
  `root:<digest>`, `leaf_index:<usize>`, `tree_size:<usize>`, then optional
  `left:<digest>` / `right:<digest>` siblings
- **Bundle signature metadata**: `signature.algorithm` currently matches the
  bundle hash algorithm and is serialized as `"sha256"`

Do not reintroduce obsolete placeholder contracts such as:

- `sha256:<digest>` prefixes
- fixed fake Ed25519 blobs
- verifier IDs like `test-verifier-deterministic`
- dummy filler values such as `deadbeef...`

## Fixture Roles

### `facade_result.json`

Frozen `VerificationResult` JSON used by `public_api_contract.rs` to assert the
serde contract and digest/signature field format for the verifier facade.

### `session_step.json`

Frozen `SessionStep` JSON used to assert the live session-step wire format,
including the signed step digest shape.

### `transparency_entry.json`

Frozen `TransparencyLogEntry` JSON used to assert the live transparency-log
shape, including the current Merkle proof entry prefixes and bare-hex result
hash contract.

### `bundle_canonical.json`

Canonical `ReplayBundle` fixture aligned with `bundle.rs` serialization and the
conformance harness. This fixture must remain a valid replay bundle under the
current bundle parser and validator, not just a documentation sample.

### `error_matrix.json`

Expected display strings for public bundle and SDK errors. Keep this aligned
with the live `Display` output of the public error types.

### `api_manifest.json`

Frozen extraction of the public SDK surface and compatibility policy metadata.

## Regeneration Rules

When the verifier public contract changes:

1. Refresh fixture contents from the live public structs, serializers, and
   validation rules in `sdk/verifier/src/lib.rs` and `sdk/verifier/src/bundle.rs`.
2. Keep fixture values stable where possible, but only in formats the current
   tests accept.
3. Rebuild any bundle fixture using the current bundle sealing rules so that
   `integrity_hash`, artifact digests, and `signature.signature_hex` remain
   internally consistent.
4. Preserve the transparency proof entry contract
   `root:/leaf_index:/tree_size:/left:/right:`.
5. Re-run the fixture-backed checks:
   `rch exec -- cargo test --manifest-path sdk/verifier/Cargo.toml --test public_api_contract public_api_conformance_suite -- --nocapture`

## Last Updated

- 2026-04-21 - Initial verifier public API fixture set
- 2026-04-23 - Fixture contracts refreshed to match the live verifier surface
- 2026-04-24 - Provenance guidance aligned with live wire-format and bundle-validation rules (`bd-3toal`)

## SDK Version Compatibility

These fixtures currently target SDK version `vsdk-v1.0` and replay bundle
schema `vsdk-replay-bundle-v1.0`.
