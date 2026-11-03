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
      trustedRunPublicKeyHex: test.run_anchor });
    assert.equal(test.expected, "verified", test.name);
    assert.equal(result.artifact_sha256, createHash("sha256").update(data).digest("hex"));
    if (test.format === "incident-bundle") {
      if (test.run_anchor !== undefined) {
        assert.equal(result.scope, "authenticated_run_incident");
        assert.equal(result.facts.run_origin.signer_public_key_hex, test.run_anchor.toLowerCase());
        assert.match(result.facts.run_origin.receipt_hash, /^sha256:[0-9a-f]{64}$/u);
        if (test.event_count !== undefined) assert.equal(result.facts.event_count, test.event_count);
      } else {
        assert.equal(result.scope, "authenticated_recorded_incident");
        assert.equal(result.facts.event_count, 3);
        assert.equal(result.facts.signing_identity, "339eefa3a988f613");
        assert.equal(Object.hasOwn(result.facts, "run_origin"), false);
      }
    }
    assert.equal(JSON.stringify(result).includes("PRIVATE-"), false);
    console.log(JSON.stringify({ case: test.name, result: "verified", scope: result.scope }));
  } catch (error) {
    assert(error instanceof VerifierError, `${test.name}: ${error}`);
    assert.equal(error.code, test.expected, test.name);
    console.log(JSON.stringify({ case: test.name, result: error.code }));
  }
}
const clientControls = [
  ["oversize_client_input", new Uint8Array(MAX_INPUT_BYTES + 1), cases[0].anchor, {}, "INPUT_TOO_LARGE"],
  ["bad_key_shape", Buffer.from("{}"), "00", {}, "ANCHOR_INVALID"],
  ["bad_run_key_shape", Buffer.from("{}"), cases[0].anchor, { trustedRunPublicKeyHex: "00" }, "RUN_ANCHOR_INVALID"],
  ["run_key_wrong_format", Buffer.from("{}"), cases[0].anchor, { format: "capsule", trustedRunPublicKeyHex: cases[0].anchor }, "INPUT_INVALID"],
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
console.log(JSON.stringify({ consumer: "javascript", matrix_cases: cases.length, client_cases: clientControls.length,
  protocol_cases: controls.length + runControls.length + 1, passed: true }));
