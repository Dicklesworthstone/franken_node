# franken_node__cod_1 Review

## Scope

- Reviewed pane 2 / cod_1 replay and tools-domain commits with:
  `git log 9707c9e1..HEAD --oneline --no-merges -- crates/franken-node/src/replay crates/franken-node/src/tools crates/franken-node/tests/adversarial*`
- Path-limited commits observed:
  `784b9513`, `82079cb1`, `4b1a57d4`, `a6a0dbb7`, `26e20b5f`, `e203b695`, `15e5d86a`, `b58ce5b`.
- Also inspected named key commits outside that path filter: `2d44bf9e`, `d3974ddd`, `675e582e`.
- Review lens: fuzz harness false-negatives, canonical/signature stability, timing-safe comparisons, and bounded-growth behavior.

## Summary

- Critical: 0
- High: 2
- Medium: 4
- Low: 0

## High Findings

### H1 — JSON-leading whitespace bypasses canonical no-float signing guard

- Location: `crates/franken-node/src/connector/canonical_serializer.rs:594`
- Related coverage: `crates/franken-node/tests/canonical_serializer_fuzz_harness.rs:425`
- Issue: `contains_float_marker` only scans for float markers when the raw UTF-8 payload starts with `{` or `[`. JSON with leading whitespace, such as `b" {\"score\":3.14}"` or `b"\\n[{\"ratio\":1e9}]"`, does not enter the scanner and can be serialized and included in a signature preimage even though `INV-CAN-NO-FLOAT` says signed trust artifacts reject floats.
- Impact: This is a signature-preimage bypass, not just a missing test. A whitespace-prefixed JSON payload can carry non-deterministic numeric semantics while still being length-prefixed and signed by `CanonicalSerializer::build_preimage`.
- Root cause: The fuzz tests added in `2d44bf9e` cover float tokens only at byte 0 JSON boundaries, while production detection uses a raw `starts_with` heuristic rather than parsing JSON after trimming legal leading JSON whitespace.
- Recommended fix: Replace the heuristic with JSON-aware validation for payloads whose `trim_start` begins with `{` or `[`, and reject any `serde_json::Number` where `is_f64()` is true. Add fuzz seeds for leading spaces, tabs, CRLF, BOM if supported, nested floats, exponents, and float-like strings to prove strings still pass.

### H2 — Compromise-reduction benchmark passes when no baseline ran

- Location: `crates/franken-node/tests/compromise_reduction_baseline_bench.rs:790`
- Issue: If `bun` or `node` is unavailable, `build_payload` emits `status: "baseline_unavailable"` with `pass_criterion.passed: false`, but the test prints a message and returns successfully before any assertion fails.
- Impact: CI can report the compromise-reduction benchmark as passing while collecting zero or partial raw-runtime baseline evidence. Because the test also writes `artifacts/adversarial/compromise_reduction_v2.json`, a missing-runtime environment can overwrite the measured artifact with a signed-but-failing evidence payload without failing the test.
- Root cause: The harness treats missing measurement prerequisites as a skip but implements it as an ordinary successful return from a normal `#[test]`.
- Recommended fix: Fail closed when required baselines are missing, or explicitly mark the benchmark ignored/env-gated and require an operator opt-in. Do not write the tracked artifact when the baseline is unavailable. Add a test/helper assertion that `status != "baseline_unavailable"` for committed measured evidence.

## Medium Findings

### M1 — Signed adversarial artifacts are never verified after writing

- Location: `crates/franken-node/tests/adversarial_extension_harness.rs:405`
- Location: `crates/franken-node/tests/adversarial_extension_harness.rs:460`
- Location: `crates/franken-node/tests/compromise_reduction_baseline_bench.rs:716`
- Location: `crates/franken-node/tests/adversarial_detection_latency.rs:377`
- Issue: The harnesses create Ed25519 signatures and assert only string prefixes such as `ed25519:` and `sha256:`. They do not read the artifact back, recompute `payload_sha256`, verify the Ed25519 signature with the embedded public key, or run a tamper-negative case.
- Impact: A regression that signs the wrong preimage, writes corrupted JSON, or drifts the on-disk artifact after signing can pass these tests while publishing unverifiable evidence.
- Recommended fix: Add a shared artifact verifier that parses the written file, removes the `signature` object, serializes the payload with the declared deterministic encoding, recomputes `payload_sha256`, verifies Ed25519, and asserts a single-byte payload mutation fails.

### M2 — Measured artifacts are not reproducible goldens

- Location: `crates/franken-node/tests/compromise_reduction_baseline_bench.rs:699`
- Location: `crates/franken-node/tests/adversarial_detection_latency.rs:362`
- Issue: The v2 compromise and latency tests write tracked artifacts with `Utc::now()` and environment-dependent measured values. Re-running the tests changes timestamps, latency samples, signatures, and hashes.
- Impact: The artifacts are useful measurements, but they are not pinned/reproducible goldens. This makes review diffs noisy and weakens claims that the committed JSON is a stable evidence artifact.
- Recommended fix: Split measurement generation from CI assertions. Keep deterministic scrubbed goldens for committed artifacts, and write fresh measurements only to an ignored output path unless an explicit regeneration command is invoked.

### M3 — Replay batch fuzz entry has no batch/input growth cap

- Location: `crates/franken-node/src/tools/replay_bundle.rs:829`
- Issue: `replay_bundle_batch_adversarial_fuzz_one` parses arbitrary input into a full `serde_json::Value`, then a full `Vec<ReplayBundle>`, then a `BTreeSet` of bundle IDs before enforcing any batch count or byte budget.
- Impact: As a fuzz boundary this can spend most cycles on allocator pressure instead of replay invariants; if reused outside tests, it is an avoidable memory/CPU DoS surface.
- Recommended fix: Add explicit maximum input bytes and maximum batch length before full deserialization, or stream-deserialize the outer array and fail closed once the cap is exceeded.

### M4 — Replay bundle integrity remains self-authenticating only

- Location: `crates/franken-node/src/tools/replay_bundle.rs:1117`
- Issue: `integrity_hash` is a SHA-256 checksum over canonical bundle fields, not an authenticity mechanism. An attacker who can rewrite a bundle can also recompute `bundle_id`, `manifest`, `chunks`, and `integrity_hash`.
- Impact: This is acceptable only if callers layer Ed25519 verification from `sdk/verifier` or another registry key path before trusting replay bundles. The replay/tools API name reads stronger than the guarantee it provides.
- Recommended fix: Document the boundary as structural integrity only, or add first-class signed replay bundle helpers that bind canonical replay JSON to a public key and include tamper-negative tests.

## Notes

- I did not find evidence of timing-sensitive digest comparisons in the reviewed replay path: `validate_bundle_integrity` and replay sequence matching use `constant_time::ct_eq`.
- The path-limited log requested by the prompt does not include `2d44bf9e`; that commit was reviewed directly because it was called out as a key commit.
