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
    const result = await verifyArtifact(data, test.anchor, { verifier: executable, format: test.format, signatureHex: test.signature_hex });
    assert.equal(test.expected, "verified", test.name);
    assert.equal(result.artifact_sha256, createHash("sha256").update(data).digest("hex"));
    if (test.format === "incident-bundle") {
      assert.equal(result.facts.event_count, 3);
      assert.equal(result.facts.signing_identity, "339eefa3a988f613");
    }
    assert.equal(JSON.stringify(result).includes("PRIVATE-"), false);
    console.log(JSON.stringify({ case: test.name, result: "verified", scope: result.scope }));
  } catch (error) {
    assert(error instanceof VerifierError, `${test.name}: ${error}`);
    assert.equal(error.code, test.expected, test.name);
    console.log(JSON.stringify({ case: test.name, result: error.code }));
  }
}
for (const [name, data, key, options, expected] of [
  ["oversize_client_input", new Uint8Array(MAX_INPUT_BYTES + 1), cases[0].anchor, {}, "INPUT_TOO_LARGE"],
  ["bad_key_shape", Buffer.from("{}"), "00", {}, "ANCHOR_INVALID"],
  ["invalid_timeout", Buffer.from("{}"), cases[0].anchor, { timeoutMs: 0 }, "TIMEOUT_INVALID"],
  ["missing_executable", Buffer.from("{}"), cases[0].anchor, { verifier: resolve("does-not-exist") }, "PROCESS_UNAVAILABLE"],
]) {
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
console.log(JSON.stringify({ consumer: "javascript", matrix_cases: cases.length, client_cases: 4,
  protocol_cases: controls.length, passed: true }));
