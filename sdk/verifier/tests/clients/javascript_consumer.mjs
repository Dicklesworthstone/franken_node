import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MAX_INPUT_BYTES, VerifierError, verifyArtifact } from "./franken_verifier.mjs";

for (const path of JSON.parse(process.env.ABSENT_CHECKOUTS ?? "[]")) assert.equal(existsSync(path), false, `product checkout visible: ${path}`);
assert.equal(existsSync("Cargo.toml"), false);
assert.equal(existsSync("src"), false);
const cases = JSON.parse(readFileSync("vectors.json", "utf8"));
const executable = process.env.VERIFIER_EXECUTABLE ?? resolve("verifier");
for (const test of cases) {
  const data = Buffer.from(test.input_hex, "hex");
  try {
    const result = await verifyArtifact(data, test.anchor, { verifier: executable, format: test.format, signatureHex: test.signature_hex,
      trustedRunPublicKeyHex: test.run_anchor, trustedRuntimePublicKeyHex: test.runtime_anchor,
      trustedRevocationPublicKeyHex: test.revocation_anchor,
      trustedProvenancePublicKeyHex: test.provenance_anchor ?? undefined,
      evaluationTime: test.evaluation_time, maxRevocationAgeSecs: test.max_revocation_age_secs });
    assert.equal(test.expected, "verified", test.name);
    assert.equal(result.artifact_sha256, createHash("sha256").update(data).digest("hex"));
    if (test.format === "incident-bundle") {
      if (test.run_anchor !== undefined) {
        assert.equal(result.scope, test.runtime_anchor === undefined ? "authenticated_run_incident" : "authenticated_runtime_incident");
        assert.equal(result.facts.run_origin.signer_public_key_hex, test.run_anchor.toLowerCase());
        assert.match(result.facts.run_origin.receipt_hash, /^sha256:[0-9a-f]{64}$/u);
        if (test.event_count !== undefined) assert.equal(result.facts.event_count, test.event_count);
        if (test.runtime_anchor !== undefined) {
          assert.equal(result.facts.runtime_origin.product_root_key_id, `ed25519:${test.runtime_anchor}`);
          assert.equal(result.facts.runtime_origin.signed_epoch, "18446744073709551615");
        }
      } else {
        assert.equal(result.scope, "authenticated_recorded_incident");
        assert.equal(result.facts.event_count, 3);
        assert.equal(result.facts.signing_identity, "339eefa3a988f613");
        assert.equal(Object.hasOwn(result.facts, "run_origin"), false);
      }
    } else if (test.format === "resolution-receipt") {
      assert.equal(result.scope, "authenticated_resolution_decision");
      assert.equal(result.facts.decision, test.decision);
      assert.equal(result.facts.module_graph_hash, test.graph_hash);
      assert.equal(result.facts.selected_version, test.decision === "admit" ? "1.2.3" : null);
      assert.equal(result.facts.capability_budget_mode, "enforced");
    }
    if (test.format === "publisher-source") {
      assert.equal(result.scope, "authenticated_publisher_source_content");
      assert.deepEqual(result.facts, test.publisher_facts);
      assert.equal(result.facts.capsule.graph_hash_recomputed, false);
    }
    if (test.format === "publisher-source-trust") {
      assert.equal(result.scope, "authenticated_publisher_source_trust");
      assert.deepEqual(result.facts, test.publisher_trust_facts);
      assert.equal(result.facts.source.capsule.graph_hash_recomputed, false);
    }
    if (test.format === "counterfactual-receipt") {
      assert.equal(result.scope, "authenticated_counterfactual_receipt");
      assert.equal(result.facts.mode, test.cf_mode);
      assert.equal(result.facts.result_count, test.cf_count);
      assert.equal(result.facts.baseline_integrity_hash, test.cf_baseline);
    }
    assert.equal(JSON.stringify(result).includes("PRIVATE-"), false);
    console.log(JSON.stringify({ case: test.name, result: "verified", scope: result.scope }));
  } catch (error) {
    assert(error instanceof VerifierError, `${test.name}: ${error}`);
    assert.equal(error.code, test.expected, test.name);
    if (["publisher-source", "publisher-source-trust"].includes(test.format)) assert.equal(error.message.includes("PRIVATE-"), false);
    console.log(JSON.stringify({ case: test.name, result: error.code }));
  }
}
const clientControls = [
  ["oversize_client_input", new Uint8Array(MAX_INPUT_BYTES + 1), cases[0].anchor, {}, "INPUT_TOO_LARGE"],
  ["bad_key_shape", Buffer.from("{}"), "00", {}, "ANCHOR_INVALID"],
  ["bad_run_key_shape", Buffer.from("{}"), cases[0].anchor, { trustedRunPublicKeyHex: "00" }, "RUN_ANCHOR_INVALID"],
  ["run_key_wrong_format", Buffer.from("{}"), cases[0].anchor, { format: "capsule", trustedRunPublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
  ["runtime_key_requires_run_key", Buffer.from("{}"), cases[0].anchor, { trustedRuntimePublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
  ["bad_runtime_key_shape", Buffer.from("{}"), cases[0].anchor, { trustedRunPublicKeyHex: cases[0].anchor, trustedRuntimePublicKeyHex: "00" }, "RUNTIME_ANCHOR_INVALID"],
  ["invalid_timeout", Buffer.from("{}"), cases[0].anchor, { timeoutMs: 0 }, "TIMEOUT_INVALID"],
  ["missing_executable", Buffer.from("{}"), cases[0].anchor, { verifier: resolve("does-not-exist") }, "PROCESS_UNAVAILABLE"],
];
for (const [name, data, key, options, expected] of clientControls) {
  await assert.rejects(verifyArtifact(data, key, { verifier: resolve("verifier"), ...options }), (error) => error instanceof VerifierError && error.code === expected, name);
  console.log(JSON.stringify({ case: name, result: expected }));
}
const controls = ["malformed", "duplicate", "wrong_schema", "wrong_scope", "wrong_hash", "wrong_anchor",
  "unsafe_count", "invalid_capture_state", "extra_member", "success_with_failure_exit",
  "rejection_with_success_exit", "invalid_utf8", "oversize", "deep_response", "timeout"];
for (const mode of controls) {
  const expected = mode === "timeout" ? "PROCESS_TIMEOUT" : "PROTOCOL_INVALID";
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), timeoutMs: mode === "timeout" ? 100 : 10_000 }),
  (error) => error instanceof VerifierError && error.code === expected, `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: expected }));
}
const runAnchor = cases.find((test) => test.name === "foreign_anchor").anchor;
const runControls = ["run_scope_downgrade", "run_origin_missing", "run_wrong_anchor", "run_invalid_receipt_id",
  "run_invalid_receipt_hash", "run_invalid_record_digest", "run_extra_origin_field", "run_origin_non_object", "run_duplicate_origin"];
for (const mode of runControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), trustedRunPublicKeyHex: runAnchor.toUpperCase() }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
await assert.rejects(verifyArtifact(Buffer.from('{"protocol_control":"run_unrequested_scope"}'), cases[0].anchor,
  { verifier: resolve("fake_verifier") }),
(error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_run_unrequested_scope");
console.log(JSON.stringify({ case: "protocol_run_unrequested_scope", result: "PROTOCOL_INVALID" }));
const runtimeAnchor = cases.find((test) => test.name === "independently_signed_runtime_origin").runtime_anchor;
const runtimeControls = ["runtime_scope_downgrade", "runtime_origin_missing", "runtime_wrong_root",
  "runtime_rounded_epoch", "runtime_overflow_epoch", "runtime_extra_claim"];
for (const mode of runtimeControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), trustedRunPublicKeyHex: runAnchor, trustedRuntimePublicKeyHex: runtimeAnchor.toUpperCase() }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
const resolutionControls = ["resolution_invalid_decision", "resolution_reject_with_candidate", "resolution_admit_without_candidate",
  "resolution_bad_graph", "resolution_wrong_signer", "resolution_unsafe_count", "resolution_wrong_scope", "resolution_unknown_field",
  "resolution_bad_profile", "resolution_bad_budget_mode", "resolution_invalid_unicode"];
for (const mode of resolutionControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "resolution-receipt" }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
const publisherControls = ["publisher_wrong_scope", "publisher_wrong_signer", "publisher_graph_recomputed",
  "publisher_unknown_field", "publisher_authority_missing", "publisher_v1_authority", "publisher_rounded_ceiling",
  "publisher_overflow_ceiling", "publisher_zero_ceiling", "publisher_invalid_capability", "publisher_authority_extra",
  "publisher_count_inconsistent", "publisher_unsafe_count", "publisher_bad_digest", "publisher_capsule_not_object"];
for (const mode of publisherControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "publisher-source", signatureHex: "00".repeat(64) }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
const publisherTrustOptions = {
  format: "publisher-source-trust", signatureHex: "00".repeat(64),
  trustedRevocationPublicKeyHex: "11".repeat(32), trustedProvenancePublicKeyHex: "22".repeat(32),
  evaluationTime: "2026-10-24T00:00:30.123456789Z", maxRevocationAgeSecs: "60",
};
const publisherTrustInputs = [
  ["trust_missing_revocation_key", { trustedRevocationPublicKeyHex: undefined }, "REVOCATION_ANCHOR_INVALID"],
  ["trust_bad_revocation_key", { trustedRevocationPublicKeyHex: "00" }, "REVOCATION_ANCHOR_INVALID"],
  ["trust_bad_provenance_key", { trustedProvenancePublicKeyHex: "00" }, "PROVENANCE_ANCHOR_INVALID"],
  ["trust_missing_time", { evaluationTime: undefined }, "EVALUATION_TIME_INVALID"],
  ["trust_invalid_calendar_date", { evaluationTime: "2026-02-30T00:00:00Z" }, "EVALUATION_TIME_INVALID"],
  ["trust_leap_second", { evaluationTime: "2026-10-24T00:00:60Z" }, "EVALUATION_TIME_INVALID"],
  ["trust_excess_time_precision", { evaluationTime: "2026-10-24T00:00:30.1234567890Z" }, "EVALUATION_TIME_INVALID"],
  ["trust_time_trailing_newline", { evaluationTime: "2026-10-24T00:00:30Z\n" }, "EVALUATION_TIME_INVALID"],
  ["trust_missing_window", { maxRevocationAgeSecs: undefined }, "REVOCATION_FRESHNESS_POLICY_INVALID"],
  ["trust_numeric_window", { maxRevocationAgeSecs: 60 }, "REVOCATION_FRESHNESS_POLICY_INVALID"],
  ["trust_zero_window", { maxRevocationAgeSecs: "0" }, "REVOCATION_FRESHNESS_POLICY_INVALID"],
  ["trust_noncanonical_window", { maxRevocationAgeSecs: "060" }, "REVOCATION_FRESHNESS_POLICY_INVALID"],
  ["trust_overflow_window", { maxRevocationAgeSecs: "18446744073709551616" }, "REVOCATION_FRESHNESS_POLICY_INVALID"],
  ["trust_window_trailing_newline", { maxRevocationAgeSecs: "60\n" }, "REVOCATION_FRESHNESS_POLICY_INVALID"],
  ["trust_options_wrong_format", { format: "publisher-source" }, "INPUT_INVALID"],
  ["trust_missing_source_signature", { signatureHex: undefined }, "SIGNATURE_MALFORMED"],
];
for (const [name, overrides, expected] of publisherTrustInputs) {
  // A missing executable proves malformed trusted inputs fail before spawn.
  await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
    { verifier: resolve("does-not-exist"), ...publisherTrustOptions, ...overrides }),
  (error) => error instanceof VerifierError && error.code === expected && error.exitCode === null, name);
  console.log(JSON.stringify({ case: name, result: expected }));
}
const publisherTrustControls = [
  "publisher_trust_scope_downgrade", "publisher_trust_format_downgrade",
  "publisher_trust_wrong_revocation_anchor", "publisher_trust_wrong_provenance_anchor",
  "publisher_trust_missing_provenance", "publisher_trust_unrequested_provenance",
  "publisher_trust_partial_provenance", "publisher_trust_zero_provenance",
  "publisher_trust_overflow_provenance", "publisher_trust_unsafe_provenance",
  "publisher_trust_unknown_field", "publisher_trust_bad_revocation_digest",
  "publisher_trust_bad_provenance_digest", "publisher_trust_wrong_evaluation_time",
  "publisher_trust_rounded_evaluation_time", "publisher_trust_wrong_window",
  "publisher_trust_rounded_window", "publisher_trust_future_revocations",
  "publisher_trust_stale_revocations", "publisher_trust_malformed_time",
  "publisher_trust_nested_wrong_signer", "publisher_trust_nested_authority_missing",
  "publisher_trust_nested_unknown_field", "publisher_trust_nested_non_object",
];
for (const mode of publisherTrustControls) {
  const options = { ...publisherTrustOptions };
  if (mode === "publisher_trust_unrequested_provenance") options.trustedProvenancePublicKeyHex = undefined;
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), ...options }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
const publisherTrustPositives = [
  ["publisher_trust_valid", {}],
  ["publisher_trust_valid_no_provenance", { trustedProvenancePublicKeyHex: undefined }],
  ["publisher_trust_equivalent_offset", { evaluationTime: "2026-10-24T01:00:30.123456789+01:00" }],
  ["publisher_trust_large_window", { maxRevocationAgeSecs: "18446744073709551615" }],
  ["publisher_trust_before_boundary", {}],
];
for (const [mode, overrides] of publisherTrustPositives) {
  const verified = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), ...publisherTrustOptions, ...overrides });
  assert.equal(verified.scope, "authenticated_publisher_source_trust", mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "verified" }));
}

const counterfactualControls = ["counterfactual_wrong_scope", "counterfactual_invalid_mode",
  "counterfactual_single_count_mismatch", "counterfactual_zero_count", "counterfactual_unknown_field"];
for (const mode of counterfactualControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "counterfactual-receipt", signatureHex: "00".repeat(64) }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
const ltvControls = ["ltv_wrong_scope", "ltv_rounded_timestamp", "ltv_overflow_timestamp",
  "ltv_bad_artifact_hash", "ltv_unknown_field"];
for (const mode of ltvControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "ltv-evidence" }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
console.log(JSON.stringify({ consumer: "javascript", matrix_cases: cases.length,
  client_cases: clientControls.length + publisherTrustInputs.length,
  protocol_cases: controls.length + runControls.length + runtimeControls.length + resolutionControls.length
    + publisherControls.length + publisherTrustControls.length + publisherTrustPositives.length
    + counterfactualControls.length + ltvControls.length + 1, passed: true }));
