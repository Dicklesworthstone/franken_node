# Canonical Vector Changelog

This changelog is required by `bd-s6y` gate policy.
Any canonical vector update must add an entry that lists changed vector paths.

## [Unreleased] - 2026-04-26

### Added
- Source `bd-3humk/v1`: `artifacts/conformance_vectors/v1/index.json`
- Source `bd-3humk/v1`: `artifacts/conformance_vectors/v1/decision_receipt.json`
- Source `bd-3humk/v1`: `artifacts/conformance_vectors/v1/supply_chain_attestation_manifest.json`
- Source `bd-3humk/v1`: `artifacts/conformance_vectors/v1/vef_execution_receipt.canonical.json`

## [1.0.0] - 2026-02-22

### Added
- Canonical manifest: `vectors/canonical_manifest.toml`
- Source `10.13-golden-vectors`: `vectors/fnode_trust_vectors_v1.json`
- Source `10.13-interop-vectors`: `fixtures/interop/interop_test_vectors.json`
- Source `10.13-fuzz-corpus`: `fuzz/corpus/migration`, `fuzz/corpus/shim`
- Source `10.14-vector-artifacts`: `artifacts/10.14/idempotency_vectors.json`
- Source `10.14-vector-artifacts`: `artifacts/10.14/epoch_key_vectors.json`
- Source `10.14-vector-artifacts`: `artifacts/10.14/seed_derivation_vectors.json`
- Source `10.14-vector-artifacts`: `artifacts/10.14/mmr_proof_vectors.json`

### Notes
- `source_bead_id` and `source_version` traceability is required for every imported vector set.
- New files matching manifest discovery globs are auto-discovered and must be added to this changelog.
