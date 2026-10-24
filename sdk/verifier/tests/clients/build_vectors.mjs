// Independent protocol vectors: Node's crypto and explicit wire encodings.
// This never imports the producer or the Rust SDK. The RFC seed is test-only
// input and is not copied into the verifier distribution/consumer sandbox.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";

const [incidentPath, sdkBundlePath, seedPath, output] = process.argv.slice(2);
const anchor = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const foreign = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const seed = Buffer.from(readFileSync(seedPath, "utf8").trim(), "hex");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
assert.equal(createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex"), anchor);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const u64 = (number) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(number)); return bytes; };
const lp = (text) => { const bytes = Buffer.from(text); return Buffer.concat([u64(bytes.length), bytes]); };
function canonical(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const clone = (value) => structuredClone(value);
const cases = [];
function add(name, format, wire, expected = "verified", options = {}) {
  const bytes = Buffer.isBuffer(wire) ? wire : Buffer.from(wire);
  cases.push({ name, format, input_hex: bytes.toString("hex"), artifact_sha256: hash(bytes), expected, anchor, ...options });
}

const incidentBytes = readFileSync(incidentPath);
assert.equal(hash(incidentBytes), "15471a216f39774c7ea981c19b47fda6b67298a7b6de1edc7b557eb2ff284fec");
const incident = JSON.parse(incidentBytes);
add("genuine_cli_incident", "incident-bundle", incidentBytes);
add("foreign_anchor", "incident-bundle", incidentBytes, "SIGNER_UNTRUSTED", { anchor: foreign });
const badSignature = clone(incident);
badSignature.signature.signature_hex = "00".repeat(64);
add("invalid_signature", "incident-bundle", canonical(badSignature), "SIGNATURE_INVALID");
const truncatedSignature = clone(incident); truncatedSignature.signature.signature_hex = "ab".repeat(63);
add("truncated_incident_signature", "incident-bundle", canonical(truncatedSignature), "SIGNATURE_MALFORMED");
const selfSelected = clone(incident); selfSelected.signature.public_key_hex = foreign;
add("embedded_self_selected_key", "incident-bundle", canonical(selfSelected), "SIGNER_UNTRUSTED");
const unsigned = clone(incident); delete unsigned.signature;
add("absent_signature", "incident-bundle", canonical(unsigned), "EVIDENCE_INVALID");
const tampered = clone(incident); tampered.initial_state_snapshot.epoch += 1;
add("tampered_content", "incident-bundle", canonical(tampered), "INTEGRITY_MISMATCH");
function resealIncident(value, signing = true) {
  value.manifest.decision_sequence_hash = hash(Buffer.concat([Buffer.from("replay_bundle_hash_v1:"), Buffer.from(canonical({ timeline: value.timeline, initial_state_snapshot: value.initial_state_snapshot, policy_version: value.policy_version }))]));
  const unsigned = clone(value); delete unsigned.signature; delete unsigned.integrity_hash;
  value.integrity_hash = hash(Buffer.concat([Buffer.from("replay_bundle_hash_v1:"), Buffer.from(canonical(unsigned))]));
  const payload = Buffer.concat([Buffer.from("replay_bundle_sig_v1:"), lp(value.integrity_hash)]);
  value.signature.signed_payload_sha256 = hash(payload);
  if (signing) value.signature.signature_hex = sign(null, payload, key).toString("hex");
  return canonical(value);
}
add("resealed_without_key", "incident-bundle", resealIncident(clone(tampered), false), "SIGNATURE_INVALID");
const relabeled = clone(incident); relabeled.signature.signing_identity = "attacker-chosen-label";
add("unsigned_label_has_no_authority", "incident-bundle", canonical(relabeled));
const duplicate = incidentBytes.toString().trim();
add("duplicate_top_member", "incident-bundle", `${duplicate.slice(0, -1)},"incident_id":"other"}`, "JSON_INVALID");
add("escaped_duplicate_member", "incident-bundle", `${duplicate.slice(0, -1)},"\\u0069ncident_id":"other"}`, "JSON_INVALID");
const extra = clone(incident); extra.unsigned_operator_claim = "trusted";
add("unknown_unsigned_member", "incident-bundle", canonical(extra), "EVIDENCE_INVALID");
const missingCheckpoint = clone(incident); missingCheckpoint.initial_state_snapshot.run_receipt_id = "run-without-its-checkpoint";
add("missing_run_checkpoint", "incident-bundle", resealIncident(missingCheckpoint), "EVIDENCE_INVALID");

function captured(state) {
  const expected = { terminal_state: state, trace_id: "trace-vector-1", console_output: [] };
  if (state === "completed") Object.assign(expected, { ir4_witness: {}, execution_value: "42", instructions_executed: 7, nondeterminism_trace: {}, lane: "deterministic", exit_code: null, decisions: null });
  if (state === "uncaught_exception") expected.exception_value = "";
  if (state === "engine_failure") Object.assign(expected, { reason: { kind: "instruction_budget_exhausted", budget: 100 }, diagnostic: "PRIVATE-DIAGNOSTIC-SENTINEL" });
  return { package: { extension_id: "test", source: "PRIVATE-SOURCE-SENTINEL", capabilities: ["builtin"] }, orchestrator: {}, runtime: { execution: { deterministic_budget: 100, throughput_budget: 200 } }, ambient_authority: "deny_all", host_io_exception_provenance: "provider_internal", process_argv: ["PRIVATE-ARGV-SENTINEL"], host_effect_transcript: [], expected };
}
function withCapture(raw, changes = {}) {
  const value = clone(incident);
  value.initial_state_snapshot.native_replay = { schema_version: "franken-node/native-replay-capture/v3", payload_json: raw, payload_sha256: hash(raw), ...changes };
  return resealIncident(value);
}
for (const state of ["completed", "uncaught_exception", "engine_failure"]) add(`capture_metadata_${state}`, "incident-bundle", withCapture(canonical(captured(state))));
const rawCapture = canonical(captured("completed"));
add("unsupported_signed_capture", "incident-bundle", withCapture(rawCapture, { schema_version: "franken-node/native-replay-capture/v99" }), "EVIDENCE_INVALID");
add("wrong_signed_capture_digest", "incident-bundle", withCapture(rawCapture, { payload_sha256: "0".repeat(64) }), "EVIDENCE_INVALID");
add("duplicate_inner_capture_member", "incident-bundle", withCapture(`${rawCapture.slice(0, -1)},"package":{}}`), "EVIDENCE_INVALID");
const missingSource = captured("completed"); delete missingSource.package.source;
add("signed_capture_missing_source", "incident-bundle", withCapture(canonical(missingSource)), "EVIDENCE_INVALID");
const missingEffect = captured("completed"); missingEffect.host_effect_transcript = [[{}]];
add("signed_capture_missing_effect_outcome", "incident-bundle", withCapture(canonical(missingEffect)), "EVIDENCE_INVALID");
const ambiguousEffect = captured("completed"); ambiguousEffect.host_effect_transcript = [[{}, { Ok: null, Err: "ambiguous" }]];
add("signed_capture_ambiguous_effect_outcome", "incident-bundle", withCapture(canonical(ambiguousEffect)), "EVIDENCE_INVALID");
const missingSourceBinding = captured("completed"); missingSourceBinding.module_sources = { capsule_base64: "PRIVATE-SOURCE-SENTINEL", graph_input_hash: "claimed-graph" };
add("signed_capture_missing_source_binding", "incident-bundle", withCapture(canonical(missingSourceBinding)), "EVIDENCE_INVALID");
const privacy = clone(incident); privacy.policy_version = "P".repeat(70_000);
add("bounded_verified_response", "incident-bundle", resealIncident(privacy), "RESPONSE_TOO_LARGE");
add("invalid_utf8", "incident-bundle", Buffer.from([0xff]), "JSON_INVALID");
add("nested_json_limit", "incident-bundle", "[".repeat(140) + "0" + "]".repeat(140), "JSON_INVALID");
add("nonfinite_json_number", "incident-bundle", '{"x":1e9999}', "JSON_INVALID");
add("integer_beyond_u64", "incident-bundle", '{"x":18446744073709551616}', "JSON_INVALID");
add("unsupported_format", "guess", incidentBytes, "UNSUPPORTED_FORMAT");

const capsule = {
  manifest: { schema_version: "vsdk-v1.0", capsule_id: "capsule-language-vector-1", description: "independent UTF-8 vector π 😀", claim_type: "content_binding", input_refs: ["answer"], expected_output_hash: "", created_at: "2026-10-24T00:00:00Z", creator_identity: "creator://independent-vector", metadata: { "π": "😀" } },
  payload: "payload-with-unicode-π-and-😀", inputs: { answer: "42" }, signature: "",
};
capsule.manifest.expected_output_hash = hash(Buffer.concat([Buffer.from("verifier_sdk_capsule_replay_v1:"), lp(capsule.payload), u64(1), lp("answer"), lp("42")]));
function signCapsule(value) {
  const m = value.manifest;
  const fields = ["frankenengine-verifier-sdk:ed25519-capsule-signature:v1:", m.schema_version, m.capsule_id, m.description, m.claim_type, m.expected_output_hash, m.created_at, m.creator_identity, value.payload].map(lp);
  fields.push(u64(m.input_refs.length), ...m.input_refs.map(lp));
  for (const entries of [Object.entries(m.metadata), Object.entries(value.inputs)]) {
    entries.sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    fields.push(u64(entries.length), ...entries.flatMap(([k, v]) => [lp(k), lp(v)]));
  }
  value.signature = sign(null, Buffer.concat(fields), key).toString("hex");
  return canonical(value);
}
const capsuleWire = signCapsule(capsule);
add("independently_signed_capsule", "capsule", capsuleWire);
const wrongHash = clone(capsule); wrongHash.manifest.expected_output_hash = "0".repeat(64);
add("signed_capsule_wrong_expected_hash", "capsule", signCapsule(wrongHash), "CAPSULE_REPLAY_MISMATCH");
const wrongSchema = clone(capsule); wrongSchema.manifest.schema_version = "vsdk-unsupported";
add("signed_capsule_wrong_schema", "capsule", signCapsule(wrongSchema), "EVIDENCE_INVALID");
const shortSignature = clone(capsule); shortSignature.signature = "aa";
add("capsule_short_signature", "capsule", canonical(shortSignature), "SIGNATURE_MALFORMED");
add("capsule_foreign_anchor", "capsule", capsuleWire, "SIGNATURE_INVALID", { anchor: foreign });
add("capsule_duplicate_input", "capsule", capsuleWire.replace('"inputs":{"answer":"42"}', '"inputs":{"answer":"42","answer":"42"}'), "JSON_INVALID");
const badField = clone(capsule); badField.manifest.unsigned_claim = "ignored?";
add("capsule_unknown_manifest_field", "capsule", canonical(badField), "EVIDENCE_INVALID");
const wrongInventory = clone(capsule); wrongInventory.manifest.input_refs = ["missing"];
add("signed_capsule_missing_input_binding", "capsule", signCapsule(wrongInventory), "EVIDENCE_INVALID");

const sdk = JSON.parse(readFileSync(sdkBundlePath, "utf8"));
sdk.initial_state_snapshot.wide_integer = 18446744073709551615n;
sdk.initial_state_snapshot["😀"] = "non-BMP-key";
sdk.initial_state_snapshot["\ue000"] = "BMP-key";
const sdkUnsigned = clone(sdk); delete sdkUnsigned.integrity_hash;
sdk.integrity_hash = hash(Buffer.concat([Buffer.from("frankenengine-verifier-sdk:canonical-hash:v1:"), Buffer.from(canonical(sdkUnsigned))]));
const sdkSignature = sign(null, Buffer.concat(["frankenengine-verifier-sdk:ed25519-bundle-signature:v1:", sdk.schema_version, sdk.sdk_version, sdk.bundle_id, sdk.incident_id, sdk.created_at, sdk.integrity_hash].map(lp)), key).toString("hex");
const sdkWire = canonical(sdk);
add("signed_sdk_bundle_wide_integer_unicode_order", "signed-bundle", sdkWire, "verified", { signature_hex: sdkSignature });
add("sdk_foreign_anchor", "signed-bundle", sdkWire, "SIGNATURE_INVALID", { anchor: foreign, signature_hex: sdkSignature });
add("sdk_signature_required", "signed-bundle", sdkWire, "SIGNATURE_MALFORMED");
add("sdk_signature_wrong", "signed-bundle", sdkWire, "SIGNATURE_INVALID", { signature_hex: "00".repeat(64) });
add("sdk_noncanonical_bytes", "signed-bundle", `${sdkWire}\n`, "EVIDENCE_INVALID", { signature_hex: sdkSignature });
writeFileSync(output, JSON.stringify(cases));
console.log(JSON.stringify({ vectors: cases.length, incident_sha256: hash(incidentBytes), capsule_expected_hash: capsule.manifest.expected_output_hash, sdk_integrity: sdk.integrity_hash }));
