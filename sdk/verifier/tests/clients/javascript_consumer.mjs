import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { closeSync, existsSync, ftruncateSync, mkdtempSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { MAX_INPUT_BYTES, MAX_NATIVE_SESSION_INPUT_BYTES, MAX_SOURCE_GRAPH_REPORT_BYTES, VerifierError, verifyArtifact } from "./franken_verifier.mjs";

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
      trustedIncidentPublicKeyHex: test.incident_anchor,
      expectedBaselineIntegrityHash: test.expected_baseline_integrity_hash,
      trustedRevocationPublicKeyHex: test.revocation_anchor,
      trustedProvenancePublicKeyHex: test.provenance_anchor ?? undefined,
      evaluationTime: test.evaluation_time, maxRevocationAgeSecs: test.max_revocation_age_secs,
      trustedFleetPolicy: test.fleet_policy_path,
      trustedCoordinatorId: test.coordinator_id,
      trustedCoordinatorPublicKeyHex: test.coordinator_key_hex,
      expectedManifestSha256: test.expected_manifest_sha256,
      expectedSourceArtifactSha256: test.expected_source_artifact_sha256,
      expectedGraphInputHash: test.expected_graph_input_hash,
      graphReport: test.graph_report_path,
      expectedSessionNonce: test.expected_session_nonce,
      expectedAdmissionSha256: test.expected_admission_sha256 });
    assert.equal(test.expected, "verified", test.name);
    assert.equal(result.artifact_sha256, createHash("sha256").update(data).digest("hex"));
    if (test.format === "incident-bundle") {
      if (test.incident_graph_report !== undefined) {
        assert.deepEqual(result.facts.graph_report, test.incident_graph_report, test.name);
        assert.notEqual(result.facts.native_capture, null);
      } else {
        assert.equal(Object.hasOwn(result.facts, "graph_report"), false);
      }
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
    } else if (test.format === "native-session-forensics") {
      assert.equal(result.scope, "authenticated_supervisor_observations");
      assert.deepEqual(result.facts, test.native_facts, test.name);
      assert.equal(result.facts.replay_certified, false);
      assert.equal(result.facts.quiescence_certified, false);
      assert.equal(result.facts.historical_completeness, false);
      assert.equal(typeof result.facts.security_epoch, "string");
    } else if (test.format === "resolution-receipt") {
      assert.equal(result.scope, "authenticated_resolution_decision");
      assert.equal(result.facts.decision, test.decision);
      assert.equal(result.facts.module_graph_hash, test.graph_hash);
      assert.equal(result.facts.selected_version, test.decision === "admit" ? "1.2.3" : null);
      assert.equal(result.facts.capability_budget_mode, "enforced");
    }
    if (test.format === "signed-session") {
      assert.equal(result.scope, "authenticated_verification_session");
      assert.deepEqual(result.facts, test.session_facts, test.name);
      assert.equal(Object.hasOwn(result.facts, "steps"), false);
      assert.equal(Object.hasOwn(result.facts, "replay_certified"), false);
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
    if (test.format === "counterfactual-incident") {
      assert.equal(result.scope, "authenticated_counterfactual_incident");
      const facts = result.facts;
      assert.equal(facts.mode, test.cf_mode);
      assert.equal(facts.result_count, test.cf_count);
      assert.equal(facts.baseline_integrity_hash, test.cf_baseline);
      assert.equal(facts.counterfactual_output_sha256, test.cf_output_hash);
      assert.equal(facts.signer_public_key_hex, test.anchor);
      assert.equal(facts.guest_execution_verified, false);
      assert.equal(facts.baseline.integrity_hash, test.cf_baseline);
      assert.equal(facts.baseline.signer_public_key_hex, test.incident_anchor);
      let expectedScope = "authenticated_recorded_incident";
      if (test.run_anchor !== undefined) {
        expectedScope = "authenticated_run_incident";
        assert.equal(facts.baseline.run_origin.signer_public_key_hex, test.run_anchor);
      }
      if (test.runtime_anchor !== undefined) {
        expectedScope = "authenticated_runtime_incident";
        assert.equal(facts.baseline.runtime_origin.product_root_key_id, `ed25519:${test.runtime_anchor}`);
        assert.equal(facts.baseline.runtime_origin.signed_epoch, "18446744073709551615");
      }
      assert.equal(facts.baseline_scope, expectedScope);
    }
    if (test.format === "counterfactual-promotion") {
      assert.equal(result.scope, "authenticated_counterfactual_promotion");
      const facts = result.facts;
      for (const [key, expected] of Object.entries(test.promotion_expected ?? {})) assert.deepEqual(facts[key], expected, `${test.name}: ${key}`);
      assert.equal(facts.baseline_integrity_hash, test.expected_baseline_integrity_hash);
      assert.equal(facts.baseline.integrity_hash, test.expected_baseline_integrity_hash);
      assert.equal(facts.signer_public_key_hex, test.anchor.toLowerCase());
      assert.equal(facts.baseline.signer_public_key_hex, test.incident_anchor.toLowerCase());
      const report = Buffer.from(JSON.parse(data.toString("utf8")).report_base64, "base64");
      assert.equal(facts.report_sha256, createHash("sha256").update(report).digest("hex"));
      assert.equal(facts.guest_execution_verified, false);
      assert.equal(facts.rollout_authorized, false);
      assert(["synthetic", "production"].includes(facts.executor));
      assert(["single", "sweep"].includes(facts.mode));
      assert(facts.result_count >= 1 && facts.result_count <= 20);
      for (const key of ["expected_loss_delta", "valid_from_epoch_ms", "valid_until_epoch_ms"]) {
        assert.equal(typeof facts[key], "string");
      }
      assert(BigInt(facts.expected_loss_delta) > 0n);
      assert(BigInt(facts.valid_until_epoch_ms) > BigInt(facts.valid_from_epoch_ms));
      const expectedScope = test.runtime_anchor !== undefined ? "authenticated_runtime_incident"
        : test.run_anchor !== undefined ? "authenticated_run_incident" : "authenticated_recorded_incident";
      assert.equal(facts.baseline_scope, expectedScope);
      if (test.run_anchor !== undefined) assert.equal(facts.baseline.run_origin.signer_public_key_hex, test.run_anchor.toLowerCase());
      if (test.runtime_anchor !== undefined) assert.equal(facts.baseline.runtime_origin.product_root_key_id, `ed25519:${test.runtime_anchor.toLowerCase()}`);
    }
    if (test.format === "ltv-evidence") {
      assert.equal(result.scope, "authenticated_ltv_anteriority");
      assert.deepEqual(result.facts, test.ltv_facts, test.name);
    }
    if (test.format === "fleet-quiescence-observations") {
      assert.equal(result.scope, "authenticated_fleet_supervisor_observations");
      assert.deepEqual(result.facts, test.fleet_facts, test.name);
      assert.equal(result.facts.epoch_commit_authenticated, false);
      assert.equal(result.facts.current_quiescence_proven, false);
      assert.equal(typeof result.facts.admitted_sessions, "string");
      assert.equal(typeof result.facts.terminal_sessions, "string");
      assert.equal(result.facts.trusted_policy_input_sha256,
        createHash("sha256").update(readFileSync(test.fleet_policy_path)).digest("hex"));
      assert.equal(JSON.stringify(result).includes("trace-maintenance"), false);
    }
    if (test.format === "fleet-epoch-commit") {
      assert.equal(result.scope, "authenticated_fleet_epoch_commit");
      assert.deepEqual(result.facts, test.epoch_facts, test.name);
      assert.equal(result.facts.epoch_commit_authenticated, true);
      assert.equal(result.facts.current_quiescence_proven, false);
      assert.equal(typeof result.facts.committed_epoch, "string");
      assert.equal(typeof result.facts.admitted_sessions, "string");
      assert.equal(result.facts.trusted_policy_input_sha256,
        createHash("sha256").update(readFileSync(test.fleet_policy_path)).digest("hex"));
      assert.equal(JSON.stringify(result).includes("trace-maintenance"), false);
    }
    assert.equal(JSON.stringify(result).includes("PRIVATE-"), false);
    console.log(JSON.stringify({ case: test.name, result: "verified", scope: result.scope }));
  } catch (error) {
    assert(error instanceof VerifierError, `${test.name}: ${error}`);
    assert.equal(error.code, test.expected, test.name);
    if (["publisher-source", "publisher-source-trust", "native-session-forensics", "signed-session"].includes(test.format)) assert.equal(error.message.includes("PRIVATE-"), false);
    console.log(JSON.stringify({ case: test.name, result: error.code }));
  }
}
const cfIncidentCase = cases.find((test) => test.name === "counterfactual_incident_runtime_origin");
const cfIncidentOptions = {
  verifier: resolve("fake_verifier"), format: "counterfactual-incident",
  signatureHex: cfIncidentCase.signature_hex,
  trustedIncidentPublicKeyHex: cfIncidentCase.incident_anchor,
  expectedBaselineIntegrityHash: cfIncidentCase.expected_baseline_integrity_hash,
  trustedRunPublicKeyHex: cfIncidentCase.run_anchor,
  trustedRuntimePublicKeyHex: cfIncidentCase.runtime_anchor,
};
for (const mode of [
  "cf_incident_wrong_pin", "cf_incident_wrong_nested_pin", "cf_incident_wrong_receipt_signer",
  "cf_incident_wrong_exporter", "cf_incident_guest_execution_claim", "cf_incident_wrong_scope",
  "cf_incident_downgraded_baseline", "cf_incident_missing_run_origin", "cf_incident_missing_runtime_origin",
  "cf_incident_extra_field", "cf_incident_bad_output_hash", "cf_incident_noncanonical_output_hash",
  "cf_incident_boolean_count", "cf_incident_excessive_count", "cf_incident_single_count_mismatch",
]) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })),
    cfIncidentCase.anchor, cfIncidentOptions),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
const cfIncidentProtocol = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: "cf_incident_valid" })),
  cfIncidentCase.anchor, cfIncidentOptions);
assert.equal(cfIncidentProtocol.facts.baseline_scope, "authenticated_runtime_incident");
assert.equal(cfIncidentProtocol.facts.guest_execution_verified, false);
console.log(JSON.stringify({ case: "protocol_cf_incident_valid", result: "verified" }));
const promotionCases = cases.filter((test) => test.format === "counterfactual-promotion");
assert(promotionCases.filter((test) => test.expected === "verified").length >= 5);
assert(promotionCases.filter((test) => test.expected !== "verified").length >= 20);
const promotionCase = promotionCases.find((test) => test.expected === "verified" && test.runtime_anchor !== undefined);
const promotionOptions = {
  verifier: resolve("fake_verifier"), format: "counterfactual-promotion",
  trustedIncidentPublicKeyHex: promotionCase.incident_anchor,
  expectedBaselineIntegrityHash: promotionCase.expected_baseline_integrity_hash,
  trustedRunPublicKeyHex: promotionCase.run_anchor,
  trustedRuntimePublicKeyHex: promotionCase.runtime_anchor,
};
const promotionControls = [
  "cf_promotion_wrong_scope", "cf_promotion_wrong_format", "cf_promotion_wrong_signer",
  "cf_promotion_wrong_pin", "cf_promotion_wrong_nested_pin", "cf_promotion_wrong_exporter",
  "cf_promotion_wrong_run_signer", "cf_promotion_wrong_runtime_key", "cf_promotion_missing_run_origin",
  "cf_promotion_missing_runtime_origin", "cf_promotion_downgraded_baseline", "cf_promotion_missing_field",
  "cf_promotion_extra_field", "cf_promotion_bad_report_hash", "cf_promotion_bad_output_hash",
  "cf_promotion_bad_counterfactual_digest", "cf_promotion_bad_contract_digest", "cf_promotion_empty_operator",
  "cf_promotion_operator_whitespace", "cf_promotion_operator_control", "cf_promotion_operator_oversize",
  "cf_promotion_operator_surrogate", "cf_promotion_empty_mitigation", "cf_promotion_mitigation_whitespace",
  "cf_promotion_mitigation_control", "cf_promotion_invalid_executor", "cf_promotion_invalid_mode",
  "cf_promotion_zero_count", "cf_promotion_boolean_count", "cf_promotion_single_count_mismatch",
  "cf_promotion_excessive_count", "cf_promotion_numeric_delta", "cf_promotion_overflow_delta",
  "cf_promotion_zero_delta", "cf_promotion_negative_delta", "cf_promotion_noncanonical_delta",
  "cf_promotion_numeric_from", "cf_promotion_underflow_from", "cf_promotion_plus_from",
  "cf_promotion_negative_zero_from", "cf_promotion_numeric_until", "cf_promotion_overflow_until",
  "cf_promotion_newline_until", "cf_promotion_empty_window", "cf_promotion_reversed_window",
  "cf_promotion_guest_execution_claim", "cf_promotion_rollout_claim", "cf_promotion_boolean_number",
];
for (const mode of promotionControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })),
    promotionCase.anchor, promotionOptions),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
for (const mode of ["cf_promotion_valid", "cf_promotion_valid_sweep"]) {
  const promoted = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })),
    promotionCase.anchor, promotionOptions);
  assert.equal(promoted.facts.rollout_authorized, false);
  assert.equal(promoted.facts.guest_execution_verified, false);
  assert.equal(promoted.facts.expected_loss_delta, mode.endsWith("_sweep") ? "9223372036854775807" : "9007199254740993");
  assert.equal(promoted.facts.valid_from_epoch_ms, mode.endsWith("_sweep") ? "0" : "-9223372036854775808");
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "verified" }));
}
const promotionInputs = [
  ["promotion_missing_exporter", { trustedIncidentPublicKeyHex: undefined }, "INCIDENT_ANCHOR_INVALID"],
  ["promotion_bad_exporter", { trustedIncidentPublicKeyHex: "bad-key" }, "INCIDENT_ANCHOR_INVALID"],
  ["promotion_missing_pin", { expectedBaselineIntegrityHash: undefined }, "EXPECTED_BASELINE_INVALID"],
  ["promotion_noncanonical_pin", { expectedBaselineIntegrityHash: "A".repeat(64) }, "EXPECTED_BASELINE_INVALID"],
  ["promotion_prefixed_pin", { expectedBaselineIntegrityHash: "sha256:" + "a".repeat(64) }, "EXPECTED_BASELINE_INVALID"],
  ["promotion_detached_signature", { signatureHex: "00".repeat(64) }, "INPUT_INVALID"],
  ["promotion_runtime_requires_run", { trustedRunPublicKeyHex: undefined }, "INPUT_INVALID"],
];
for (const [name, overrides, code] of promotionInputs) {
  await assert.rejects(verifyArtifact(Buffer.from("{}"), promotionCase.anchor, { ...promotionOptions, ...overrides }),
    (error) => error instanceof VerifierError && error.code === code, name);
  console.log(JSON.stringify({ case: name, result: code }));
}
const fleetCase = cases.find((test) => test.name === "fleet_independent_http_observations");
const epochCase = cases.find((test) => test.name === "epoch_independent_http_commit");
const epochControls = [
  "epoch_wrong_scope", "epoch_wrong_format", "epoch_wrong_schema", "epoch_missing_field",
  "epoch_unknown_field", "epoch_wrong_coordinator", "epoch_wrong_key", "epoch_missing_commit_claim",
  "epoch_current_quiescence_claim", "epoch_numeric_epoch", "epoch_noncanonical_epoch",
  "epoch_overflow_epoch", "epoch_wrong_committed_epoch", "epoch_bad_statement_hash",
  "epoch_uppercase_statement_hash", "epoch_empty_transition", "epoch_transition_control",
  "epoch_wrong_policy_input", "epoch_wrong_evidence_input", "epoch_unverified_supervisors",
];
const epochOptions = { verifier: resolve("fake_verifier"), format: "fleet-epoch-commit",
  trustedFleetPolicy: epochCase.fleet_policy_path, trustedCoordinatorId: epochCase.coordinator_id,
  trustedCoordinatorPublicKeyHex: epochCase.coordinator_key_hex };
for (const mode of epochControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), null, epochOptions),
    (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
for (const name of ["epoch_independent_http_commit", "epoch_exact_u64_maximum_commit"]) {
  const candidate = cases.find((test) => test.name === name);
  const result = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: "epoch_valid" })), null,
    { ...epochOptions, trustedFleetPolicy: candidate.fleet_policy_path });
  assert.equal(result.facts.committed_epoch, candidate.epoch_facts.committed_epoch);
  assert.equal(result.facts.epoch_commit_authenticated, true);
  assert.equal(result.facts.current_quiescence_proven, false);
  console.log(JSON.stringify({ case: "protocol_" + name, result: "verified" }));
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: "epoch_wrong_committed_epoch" })), null,
    { ...epochOptions, trustedFleetPolicy: candidate.fleet_policy_path }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_wrong_epoch_" + name);
  console.log(JSON.stringify({ case: "protocol_wrong_epoch_" + name, result: "PROTOCOL_INVALID" }));
}
const fleetControls = [
  "fleet_wrong_scope", "fleet_wrong_format", "fleet_unknown_field", "fleet_missing_field",
  "fleet_wrong_policy_input", "fleet_canonical_hash_as_input_hash", "fleet_malformed_policy_hash",
  "fleet_wrong_evidence_input", "fleet_wrong_evaluation_time", "fleet_stale_observation",
  "fleet_future_observation", "fleet_wrong_population", "fleet_boolean_population",
  "fleet_numeric_count", "fleet_noncanonical_count", "fleet_overflow_count", "fleet_terminal_mismatch",
  "fleet_unverified_signatures", "fleet_incomplete_population", "fleet_unmatched_action_context",
  "fleet_epoch_commit_claim", "fleet_current_quiescence_claim",
];
for (const mode of fleetControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), null,
    { verifier: resolve("fake_verifier"), format: "fleet-quiescence-observations", trustedFleetPolicy: fleetCase.fleet_policy_path }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
for (const [mode, count] of [["fleet_valid", "18446744073709551615"], ["fleet_valid_empty_session_set", "0"]]) {
  const result = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), null,
    { verifier: resolve("fake_verifier"), format: "fleet-quiescence-observations", trustedFleetPolicy: fleetCase.fleet_policy_path });
  assert.equal(result.facts.admitted_sessions, count);
  assert.equal(result.facts.terminal_sessions, count);
  assert.equal(result.facts.epoch_commit_authenticated, false);
  assert.equal(result.facts.current_quiescence_proven, false);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "verified" }));
}
const mutableFleetInput = Buffer.from(JSON.stringify({ protocol_control: "fleet_valid", input: "original" }));
const requestedFleetDigest = createHash("sha256").update(mutableFleetInput).digest("hex");
const pendingFleetVerification = verifyArtifact(mutableFleetInput, null,
  { verifier: resolve("fake_verifier"), format: "fleet-quiescence-observations", trustedFleetPolicy: fleetCase.fleet_policy_path });
mutableFleetInput.write("modified", mutableFleetInput.indexOf("original"));
assert.notEqual(createHash("sha256").update(mutableFleetInput).digest("hex"), requestedFleetDigest);
const snapshottedFleetVerification = await pendingFleetVerification;
assert.equal(snapshottedFleetVerification.artifact_sha256, requestedFleetDigest,
  "policy I/O must not change the evidence bytes retained at invocation");
console.log(JSON.stringify({ case: "fleet_input_snapshot_before_policy_io", result: "verified" }));
const sessionControls = [
  "session_wrong_scope", "session_wrong_signer", "session_unknown_field", "session_missing_field",
  "session_boolean_count", "session_negative_count", "session_excessive_count",
  "session_empty_pass", "session_nonempty_inconclusive", "session_bad_identity",
  "session_empty_id", "session_long_id", "session_id_newline", "session_bad_time",
  "session_bad_verdict", "session_bad_hash", "session_uppercase_hash",
];
for (const mode of sessionControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "signed-session" }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
for (const [mode, verdict] of [["session_valid", "pass"], ["session_fail", "fail"], ["session_empty", "inconclusive"]]) {
  const result = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "signed-session" });
  assert.equal(result.facts.final_verdict, verdict);
  assert.equal(result.facts.step_count === 0, verdict === "inconclusive");
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "verified" }));
}
const clientControls = [
  ["oversize_client_input", new Uint8Array(MAX_INPUT_BYTES + 1), cases[0].anchor, {}, "INPUT_TOO_LARGE"],
  ["bad_key_shape", Buffer.from("{}"), "00", {}, "ANCHOR_INVALID"],
  ["bad_run_key_shape", Buffer.from("{}"), cases[0].anchor, { trustedRunPublicKeyHex: "00" }, "RUN_ANCHOR_INVALID"],
  ["run_key_wrong_format", Buffer.from("{}"), cases[0].anchor, { format: "capsule", trustedRunPublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
  ["runtime_key_requires_run_key", Buffer.from("{}"), cases[0].anchor, { trustedRuntimePublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
  ["bad_runtime_key_shape", Buffer.from("{}"), cases[0].anchor, { trustedRunPublicKeyHex: cases[0].anchor, trustedRuntimePublicKeyHex: "00" }, "RUNTIME_ANCHOR_INVALID"],
  ["native_detached_signature_refused", Buffer.from("{}"), cases[0].anchor, { format: "native-session-forensics", signatureHex: "00".repeat(64) }, "INPUT_INVALID"],
  ["native_run_anchor_refused", Buffer.from("{}"), cases[0].anchor, { format: "native-session-forensics", trustedRunPublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
  ["session_detached_signature_refused", Buffer.from("{}"), cases[0].anchor, { format: "signed-session", signatureHex: "00".repeat(64) }, "INPUT_INVALID"],
  ["session_run_anchor_refused", Buffer.from("{}"), cases[0].anchor, { format: "signed-session", trustedRunPublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
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
const nativeControls = [
  "native_wrong_scope",
  "native_wrong_nested_scope",
  "native_wrong_root",
  "native_bad_nonce",
  "native_bad_admission_digest",
  "native_bad_paths",
  "native_numeric_epoch",
  "native_overflow_epoch",
  "native_noncanonical_epoch",
  "native_negative_epoch",
  "native_epoch_trailing_newline",
  "native_bad_admission_time",
  "native_bad_observation_time",
  "native_unknown_field",
  "native_missing_field",
  "native_pending_with_outcome",
  "native_impossible_process",
  "native_impossible_effect",
  "native_unknown_outcome",
  "native_unsafe_count",
  "native_boolean_count",
  "native_missing_count",
  "native_impossible_wal_count",
  "native_missing_completeness",
  "native_impossible_ledger_count",
  "native_replay_claim",
  "native_quiescence_claim",
  "native_history_claim",
  "native_v1_with_journal",
  "native_v2_without_journal",
  "native_unknown_schema",
  "native_journal_wrong_nonce",
  "native_journal_wrong_root",
  "native_journal_wrong_admission",
  "native_journal_wrong_scope",
  "native_journal_wrong_schema",
  "native_journal_empty_prefix",
  "native_journal_event_mismatch",
  "native_journal_call_mismatch",
  "native_journal_missing_pending",
  "native_journal_bad_head",
  "native_journal_bad_torn_flag",
  "native_journal_unknown_field",
  "native_journal_replay_claim",
  "native_journal_quiescence_claim",
  "native_journal_history_claim",
  "native_journal_contradicts_complete_outcome",
  "native_v3_missing_source",
  "native_v3_null_source",
  "native_v3_source_wrong_schema",
  "native_v3_source_wrong_graph",
  "native_v3_source_graph_claim",
  "native_v3_source_unknown_field",
  "native_v3_source_oversize",
  "native_v3_source_payload_oversize",
  "native_v3_source_payload_exceeds_capsule",
  "native_v3_source_counts_disagree",
  "native_v3_source_boolean_count",
  "native_v3_source_excess_inputs",
  "native_v3_source_forbidden_symlink",
  "native_v3_source_excess_conditions",
  "native_v3_source_on_v1",
  "native_v3_source_on_v2",
];
for (const mode of nativeControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "native-session-forensics" }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", "protocol_" + mode);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "PROTOCOL_INVALID" }));
}
const nativePositives = ["native_valid", "native_zero_epoch", "native_pending_prefix", "native_incomplete_with_later_journal",
  "native_v3_valid", "native_v3_without_journal", "native_v3_maximum_source"];
for (const mode of nativePositives) {
  const verified = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "native-session-forensics" });
  assert.equal(verified.scope, "authenticated_supervisor_observations", mode);
  assert.equal(verified.facts.historical_completeness, false, mode);
  if (mode === "native_pending_prefix") {
    assert.equal(verified.facts.completed_provider_calls, null);
    assert.equal(verified.facts.durable_journal.admitted_provider_calls, 2);
  }
  if (mode === "native_incomplete_with_later_journal") {
    assert.equal(verified.facts.journal_complete, false);
    assert.equal(verified.facts.durable_journal.returned_provider_calls, 1);
  }
  if (mode.startsWith("native_v3_")) {
    assert.equal(verified.facts.source_capsule.graph_hash_recomputed, false);
    assert.equal(verified.facts.source_capsule.input_count, 3);
  }
  if (mode === "native_v3_without_journal") assert.equal(verified.facts.durable_journal, null);
  console.log(JSON.stringify({ case: "protocol_" + mode, result: "verified" }));
}
// A distributed executable must not silently ignore a requested admission.
const nativeIdentityPins = { expectedSessionNonce: "0199abcd-1234-7000-8000-123456789abc",
  expectedAdmissionSha256: "a".repeat(64) };
const nativeIdentityInput = Buffer.from(JSON.stringify({ protocol_control: "native_valid" }));
await verifyArtifact(nativeIdentityInput, cases[0].anchor,
  { verifier: resolve("fake_verifier"), format: "native-session-forensics", ...nativeIdentityPins });
for (const [field, value] of [["expectedSessionNonce", "0199abcd-1234-7000-8000-123456789abd"],
  ["expectedAdmissionSha256", "b".repeat(64)]]) {
  await assert.rejects(verifyArtifact(nativeIdentityInput, cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "native-session-forensics", ...nativeIdentityPins, [field]: value }),
  (error) => error instanceof VerifierError && error.code === "EXPECTED_NATIVE_IDENTITY_MISMATCH"
    && !error.message.includes(value));
  console.log(JSON.stringify({ case: `native_ignored_${field}`, result: "EXPECTED_NATIVE_IDENTITY_MISMATCH" }));
}
// Check exact transport limits without launching a process or retaining a huge
// serialized fixture. Oversized inputs in every other format still fail above.
assert.equal(MAX_NATIVE_SESSION_INPUT_BYTES, 96 * 1024 * 1024);
for (const [size, expected] of [[MAX_NATIVE_SESSION_INPUT_BYTES, "EXECUTABLE_INVALID"],
  [MAX_NATIVE_SESSION_INPUT_BYTES + 1, "INPUT_TOO_LARGE"]]) {
  await assert.rejects(verifyArtifact(new Uint8Array(size), cases[0].anchor,
    { verifier: "", format: "native-session-forensics" }),
  (error) => error instanceof VerifierError && error.code === expected, `native_transport_boundary_${size}`);
  console.log(JSON.stringify({ case: `native_transport_boundary_${size}`, result: expected }));
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
  "publisher_count_inconsistent", "publisher_unsafe_count", "publisher_bad_digest", "publisher_capsule_not_object",
  "publisher_host_null", "publisher_host_unknown_field", "publisher_host_missing_quotas", "publisher_host_numeric_quota",
  "publisher_host_overflow_quota", "publisher_host_beyond_instruction_quota", "publisher_host_undeclared_quota",
  "publisher_host_noncanonical_quota", "publisher_host_quota_newline", "publisher_host_wildcard", "publisher_host_url",
  "publisher_host_invalid_port", "publisher_host_uppercase", "publisher_host_invalid_ipv6", "publisher_host_duplicate_scope",
  "publisher_host_unsorted_scope", "publisher_host_null_scope", "publisher_host_undeclared_scope", "publisher_host_invalid_env",
  "publisher_host_env_newline", "publisher_host_excessive_scope", "publisher_host_process_undeclared",
  "publisher_host_process_overflow", "publisher_host_process_beyond_instruction"];
for (const mode of publisherControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "publisher-source", signatureHex: "00".repeat(64) }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
const publisherHostPositives = ["publisher_host_valid", "publisher_host_empty", "publisher_host_unspecified",
  "publisher_host_process_maximum", "publisher_host_process_zero"];
for (const mode of publisherHostPositives) {
  const verified = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "publisher-source", signatureHex: "00".repeat(64) });
  const host = verified.facts.runtime_authority.host_io;
  if (mode === "publisher_host_valid") {
    assert.equal(host.max_calls_per_epoch.network_egress, "18446744073709551615");
    assert.equal(host.max_calls_per_epoch.fs_read, "0");
    assert.deepEqual(host.host_ports, ["[2001:db8::1]:443", "api.example.test:443"]);
  } else if (mode === "publisher_host_empty") {
    assert.deepEqual(host, { host_ports: [], env_keys: [], max_calls_per_epoch: {} });
  } else if (mode === "publisher_host_unspecified") {
    assert.deepEqual(host, { max_calls_per_epoch: { fs_read: "0" } });
  } else {
    assert.equal(host.max_calls_per_epoch.process_spawn, mode.endsWith("_zero") ? "0" : "18446744073709551615");
    assert.equal(Object.keys(host.max_calls_per_epoch).length, 6);
  }
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "verified" }));
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
// BEGIN publisher identity protocol controls (no cryptographic proof claims).
const graphWitnessPath = join(mkdtempSync(join(tmpdir(), "franken-graph-witness-")), "private graph; $(ignored).json");
const graphWitnessBytes = Buffer.from("{}\n");
writeFileSync(graphWitnessPath, graphWitnessBytes);
const graphWitnessControls = ["ignored", "null", "wrong_schema", "not_recomputed", "semantic_claim",
  "wrong_graph", "wrong_capsule", "wrong_report_hash", "prefixed_report_hash", "uppercase_report_hash",
  "newline_report_hash", "observation_mismatch", "zero_observations", "too_many_observations",
  "boolean_count", "unsafe_count", "zero_modules", "too_many_targets", "negative_count",
  "nonboolean_resolution", "inconsistent_resolution", "unknown_field", "missing_field", "replaced_file"];
let graphClientCases = 0;
let graphProtocolCases = 0;
for (const trusted of [false, true]) {
  const prefix = trusted ? "publisher_trust_graph_witness_" : "publisher_graph_witness_";
  const options = trusted ? publisherTrustOptions : { format: "publisher-source", signatureHex: "00".repeat(64) };
  for (const path of ["", null, false, 7, [], {}, "private\0report", "\ud800"]) {
    await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
      { verifier: resolve("does-not-exist"), ...options, graphReport: path }),
    (error) => error instanceof VerifierError && error.code === "GRAPH_REPORT_INVALID" && error.exitCode === null);
    graphClientCases += 1;
  }
  const forwarded = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: prefix + "forwarded",
    expected_graph_report_path: graphWitnessPath })),
    cases[0].anchor, { verifier: resolve("fake_verifier"), ...options, graphReport: graphWitnessPath });
  const source = trusted ? forwarded.facts.source : forwarded.facts;
  assert.equal(source.graph_report.graph_hash_recomputed, true);
  assert.equal(source.graph_report.graph_semantics_reconstructed, false);
  assert.equal(source.graph_report.report_sha256, createHash("sha256").update(graphWitnessBytes).digest("hex"));
  assert(source.graph_report.module_count > source.capsule.file_count, "URL identities may share a file");
  graphProtocolCases += 1;
  for (const control of graphWitnessControls) {
    writeFileSync(graphWitnessPath, graphWitnessBytes);
    await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: prefix + control })),
      cases[0].anchor, { verifier: resolve("fake_verifier"), ...options, graphReport: graphWitnessPath }),
    (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID"
      && !error.message.includes(graphWitnessPath), prefix + control);
    graphProtocolCases += 1;
    console.log(JSON.stringify({ case: prefix + control, result: "PROTOCOL_INVALID" }));
  }
  writeFileSync(graphWitnessPath, graphWitnessBytes);
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: prefix + "unsolicited" })),
    cases[0].anchor, { verifier: resolve("fake_verifier"), ...options }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID");
  graphProtocolCases += 1;
}
await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
  { verifier: resolve("does-not-exist"), format: "capsule", graphReport: graphWitnessPath }),
(error) => error instanceof VerifierError && error.code === "INPUT_INVALID" && error.exitCode === null);
graphClientCases += 1;

// These fake-child controls exercise the client contract, never signatures.
const incidentGraphPayload = {
  module_sources: { capsule_base64: "Y2Fwc3VsZQ==", capsule_digest: "sha256:" + "c".repeat(64),
    graph_input_hash: "sha256:" + "d".repeat(64) },
  expected: { terminal_state: "completed" }, host_effect_transcript: [],
};
const incidentGraphRaw = JSON.stringify(incidentGraphPayload);
function incidentGraphInput(action, raw = incidentGraphRaw) {
  return Buffer.from(JSON.stringify({
    protocol_control: "incident_graph_witness_" + action,
    expected_graph_report_path: graphWitnessPath,
    initial_state_snapshot: { native_replay: {
      schema_version: "franken-node/native-replay-capture/v3", payload_json: raw,
      payload_sha256: createHash("sha256").update(raw).digest("hex"),
    } },
  }));
}
const incidentGraphControls = graphWitnessControls.filter((control) => control !== "observation_mismatch");
incidentGraphControls.push("missing_capture", "wrong_capture_hash", "wrong_capture_bytes",
  "wrong_capture_state", "wrong_capture_count", "wrong_scope");
for (const [origins, expectedScope] of [
  [{}, "authenticated_recorded_incident"],
  [{ trustedRunPublicKeyHex: runAnchor }, "authenticated_run_incident"],
  [{ trustedRunPublicKeyHex: runAnchor, trustedRuntimePublicKeyHex: runtimeAnchor }, "authenticated_runtime_incident"],
]) {
  writeFileSync(graphWitnessPath, graphWitnessBytes);
  const verified = await verifyArtifact(incidentGraphInput("forwarded"), cases[0].anchor,
    { verifier: resolve("fake_verifier"), graphReport: graphWitnessPath, ...origins });
  assert.equal(verified.scope, expectedScope);
  assert.equal(verified.facts.graph_report.report_sha256, createHash("sha256").update(graphWitnessBytes).digest("hex"));
  assert.equal(verified.facts.native_capture.captured_terminal_state, "completed");
  assert.equal(Object.hasOwn(verified.facts, "run_origin"), origins.trustedRunPublicKeyHex !== undefined);
  assert.equal(Object.hasOwn(verified.facts, "runtime_origin"), origins.trustedRuntimePublicKeyHex !== undefined);
  graphProtocolCases += 1;
  const controlsForScope = [...incidentGraphControls];
  if (origins.trustedRunPublicKeyHex !== undefined) controlsForScope.push("scope_downgrade", "missing_run_origin", "wrong_run_anchor");
  if (origins.trustedRuntimePublicKeyHex !== undefined) controlsForScope.push("missing_runtime_origin", "wrong_runtime_anchor");
  for (const control of controlsForScope) {
    writeFileSync(graphWitnessPath, graphWitnessBytes);
    await assert.rejects(verifyArtifact(incidentGraphInput(control), cases[0].anchor,
      { verifier: resolve("fake_verifier"), graphReport: graphWitnessPath, ...origins }),
    (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID"
      && !error.message.includes(graphWitnessPath), control);
    graphProtocolCases += 1;
  }
  await assert.rejects(verifyArtifact(incidentGraphInput("unsolicited"), cases[0].anchor,
    { verifier: resolve("fake_verifier"), ...origins }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID");
  graphProtocolCases += 1;
}
writeFileSync(graphWitnessPath, graphWitnessBytes);
for (const raw of [
  "{}",
  incidentGraphRaw.replace('"module_sources":', '"module_sources":{},"module_sources":'),
  incidentGraphRaw.replace('"module_sources":', '"module_sources":{},"module_\\u0073ources":'),
  incidentGraphRaw.replace('"capsule_base64":', '"unsigned_claim":true,"capsule_base64":'),
]) {
  await assert.rejects(verifyArtifact(incidentGraphInput("valid", raw), cases[0].anchor,
    { verifier: resolve("fake_verifier"), graphReport: graphWitnessPath }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID");
  graphProtocolCases += 1;
}
for (const input of [
  Buffer.from(JSON.stringify({ protocol_control: "incident_graph_witness_valid" })),
  Buffer.from(incidentGraphInput("valid").toString().replace('"initial_state_snapshot":',
    '"initial_state_snapshot":{},"initial_state_snapshot":')),
]) {
  await assert.rejects(verifyArtifact(input, cases[0].anchor,
    { verifier: resolve("fake_verifier"), graphReport: graphWitnessPath }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID");
  graphProtocolCases += 1;
}
const mutableGraphInput = incidentGraphInput("valid");
const graphInvocationHash = createHash("sha256").update(mutableGraphInput).digest("hex");
const pendingGraphVerification = verifyArtifact(mutableGraphInput, cases[0].anchor,
  { verifier: resolve("fake_verifier"), graphReport: graphWitnessPath });
mutableGraphInput.fill(0);
assert.equal((await pendingGraphVerification).artifact_sha256, graphInvocationHash);
graphProtocolCases += 1;
for (const path of ["", null, false, 7, [], {}, "private\0report", "\ud800"]) {
  await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
    { verifier: resolve("does-not-exist"), graphReport: path }),
  (error) => error instanceof VerifierError && error.code === "GRAPH_REPORT_INVALID" && error.exitCode === null);
  graphClientCases += 1;
}
const graphFiles = mkdtempSync(join(tmpdir(), "franken-graph-input-"));
const oversizedGraph = join(graphFiles, "PRIVATE-oversized-report.json");
const graphDescriptor = openSync(oversizedGraph, "w");
try {
  ftruncateSync(graphDescriptor, MAX_SOURCE_GRAPH_REPORT_BYTES + 1);
} finally {
  closeSync(graphDescriptor);
}
for (const [path, expected] of [
  [join(graphFiles, "PRIVATE-absent-report.json"), "GRAPH_REPORT_IO"],
  [graphFiles, "GRAPH_REPORT_IO"],
  [oversizedGraph, "INPUT_TOO_LARGE"],
]) {
  await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
    { verifier: resolve("does-not-exist"), graphReport: path }),
  (error) => error instanceof VerifierError && error.code === expected && error.exitCode === null
    && !error.message.includes("PRIVATE-"));
  graphClientCases += 1;
}

const identityPins = {
  expectedManifestSha256: "sha256:" + "a".repeat(64),
  expectedSourceArtifactSha256: "sha256:" + "b".repeat(64),
  expectedGraphInputHash: "sha256:" + "d".repeat(64),
};
const identityInvalidInputs = [
  ["missing_manifest_for_artifact", { expectedManifestSha256: undefined }],
  ["missing_manifest_for_graph", { expectedManifestSha256: undefined, expectedSourceArtifactSha256: undefined }],
  ["empty_manifest", { expectedManifestSha256: "" }],
  ["manifest_without_prefix", { expectedManifestSha256: "a".repeat(64) }],
  ["uppercase_manifest", { expectedManifestSha256: "sha256:" + "A".repeat(64) }],
  ["manifest_newline", { expectedManifestSha256: identityPins.expectedManifestSha256 + "\n" }],
  ["source_artifact_type", { expectedSourceArtifactSha256: [] }],
  ["graph_wrong_length", { expectedGraphInputHash: "sha256:dd" }],
];
let identityClientCases = 0;
let identityProtocolCases = 0;
for (const trusted of [false, true]) {
  const prefix = trusted ? "publisher_trust_identity" : "publisher_identity";
  const options = trusted ? publisherTrustOptions : { format: "publisher-source", signatureHex: "00".repeat(64) };
  for (const [name, overrides] of identityInvalidInputs) {
    await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
      { verifier: resolve("does-not-exist"), ...options, ...identityPins, ...overrides }),
    (error) => error instanceof VerifierError && error.code === "EXPECTED_IDENTITY_INVALID" && error.exitCode === null);
    identityClientCases += 1;
    console.log(JSON.stringify({ case: `${prefix}_${name}`, result: "EXPECTED_IDENTITY_INVALID" }));
  }
  for (const [mode, pins] of [
    [`${prefix}_valid`, { expectedManifestSha256: identityPins.expectedManifestSha256 }],
    [`${prefix}_forwarded`, identityPins],
  ]) {
    const verified = await verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode })), cases[0].anchor,
      { verifier: resolve("fake_verifier"), ...options, ...pins });
    const source = trusted ? verified.facts.source : verified.facts;
    assert.equal(source.manifest_sha256, identityPins.expectedManifestSha256);
    assert.equal(source.capsule.graph_hash_recomputed, false);
    identityProtocolCases += 1;
    console.log(JSON.stringify({ case: mode, result: "verified" }));
  }
  // This child ignores the forwarded pins and reports an otherwise valid success.
  for (const field of Object.keys(identityPins)) {
    await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: `${prefix}_ignore_args` })), cases[0].anchor,
      { verifier: resolve("fake_verifier"), ...options, ...identityPins, [field]: "sha256:" + "e".repeat(64) }),
    (error) => error instanceof VerifierError && error.code === "EXPECTED_IDENTITY_MISMATCH" && !error.message.includes("sha256:"));
    identityProtocolCases += 1;
    console.log(JSON.stringify({ case: `${prefix}_ignored_${field}`, result: "EXPECTED_IDENTITY_MISMATCH" }));
  }
}
await assert.rejects(verifyArtifact(Buffer.from("{}"), cases[0].anchor,
  { verifier: resolve("does-not-exist"), format: "incident-bundle", ...identityPins }),
(error) => error instanceof VerifierError && error.code === "EXPECTED_IDENTITY_INVALID" && error.exitCode === null);
identityClientCases += 1;
// END publisher identity protocol controls.
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
  "ltv_bad_artifact_hash", "ltv_unknown_field", "ltv_missing_policy_hash",
  "ltv_wrong_policy_hash", "ltv_uppercase_policy_hash"];
const ltvProtocol = await verifyArtifact(Buffer.from(JSON.stringify({
  protocol_control: "ltv_policy_bound", witness_anchor_base64: "e30=",
})), cases[0].anchor, { verifier: resolve("fake_verifier"), format: "ltv-evidence" });
assert.equal(ltvProtocol.facts.trust_policy_sha256, createHash("sha256").update("{}").digest("hex"));
for (const mode of ltvControls) {
  await assert.rejects(verifyArtifact(Buffer.from(JSON.stringify({ protocol_control: mode, witness_anchor_base64: "e30=" })), cases[0].anchor,
    { verifier: resolve("fake_verifier"), format: "ltv-evidence" }),
  (error) => error instanceof VerifierError && error.code === "PROTOCOL_INVALID", `protocol_${mode}`);
  console.log(JSON.stringify({ case: `protocol_${mode}`, result: "PROTOCOL_INVALID" }));
}
console.log(JSON.stringify({ consumer: "javascript", matrix_cases: cases.length,
  client_cases: clientControls.length + publisherTrustInputs.length + identityClientCases + graphClientCases + promotionInputs.length,
  protocol_cases: controls.length + runControls.length + runtimeControls.length + resolutionControls.length
    + publisherControls.length + publisherHostPositives.length + publisherTrustControls.length + publisherTrustPositives.length + identityProtocolCases + graphProtocolCases
    + counterfactualControls.length + ltvControls.length + promotionControls.length + 2
    + nativeControls.length + nativePositives.length + 1, passed: true }));
