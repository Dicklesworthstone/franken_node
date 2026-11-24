// Independent protocol vectors: Node's crypto and explicit wire encodings.
// This never imports the producer or the Rust SDK. The RFC seed is test-only
// input and is not copied into the verifier distribution/consumer sandbox.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const [incidentPath, sdkBundlePath, seedPath, output, originalRunPath, exporterAnchorPath, runAnchorPath, sourceCapsulesPath, fleetObservationsPath, fleetEpochCommitPath] = process.argv.slice(2);
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

// This fixture is emitted by the exact production record/bundle signers and
// effect-receipt implementation under two explicit test authorities. Execution
// metadata is synthetic: it does not claim that a native guest ran. Its producer
// signatures are retained, not recreated by this independent consumer.
const originalRunBytes = readFileSync(originalRunPath);
const originalRun = JSON.parse(originalRunBytes);
const exporterAnchor = readFileSync(exporterAnchorPath, "utf8").trim();
const runAnchor = readFileSync(runAnchorPath, "utf8").trim();
assert.notEqual(exporterAnchor, runAnchor);
assert.equal(originalRun.signature.public_key_hex, exporterAnchor);
const originalRunOptions = { anchor: exporterAnchor, run_anchor: runAnchor, event_count: originalRun.timeline.length };
add("producer_signed_run_origin", "incident-bundle", originalRunBytes, "verified", originalRunOptions);
add("original_run_foreign_authority", "incident-bundle", originalRunBytes, "RUN_ORIGIN_SIGNATURE_INVALID", { ...originalRunOptions, run_anchor: foreign });
add("original_run_bundle_key_is_not_run_authority", "incident-bundle", originalRunBytes, "RUN_ORIGIN_SIGNATURE_INVALID", { ...originalRunOptions, run_anchor: exporterAnchor });
add("original_run_swapped_authorities", "incident-bundle", originalRunBytes, "SIGNER_UNTRUSTED", { anchor: runAnchor, run_anchor: exporterAnchor });
add("original_run_proof_required", "incident-bundle", incidentBytes, "RUN_ORIGIN_MISSING", { run_anchor: runAnchor });

// Re-export under the public RFC test key to model a trusted exporter who can
// change its bundle but cannot produce a new original-run signature.
function reexportOriginal(mutator) {
  const value = clone(originalRun);
  value.signature = clone(incident.signature);
  mutator(value);
  return resealIncident(value);
}
const testExporterOptions = { run_anchor: runAnchor, event_count: originalRun.timeline.length };
add("original_run_reexport_retains_independent_authority", "incident-bundle", reexportOriginal(() => {}), "verified", testExporterOptions);
add("original_run_exporter_cannot_change_policy", "incident-bundle", reexportOriginal((value) => { value.policy_version = "different-policy"; }), "RUN_ORIGIN_INVALID", testExporterOptions);
add("original_run_exporter_cannot_change_identity", "incident-bundle", reexportOriginal((value) => { value.initial_state_snapshot.run_receipt_id = "different-run"; }), "RUN_ORIGIN_INVALID", testExporterOptions);
add("original_run_exporter_cannot_strip_proof", "incident-bundle", reexportOriginal((value) => { delete value.initial_state_snapshot.run_origin; }), "RUN_ORIGIN_MISSING", testExporterOptions);
add("original_run_nested_duplicate", "incident-bundle", reexportOriginal((value) => {
  const origin = value.initial_state_snapshot.run_origin;
  const raw = origin.record_json.trimEnd();
  origin.record_json = `${raw.slice(0, -1)},"\\u0072eceipt_id":"duplicate"}`;
}), "RUN_ORIGIN_INVALID", testExporterOptions);
add("original_run_exporter_cannot_rewrite_signed_metadata", "incident-bundle", reexportOriginal((value) => {
  const origin = value.initial_state_snapshot.run_origin;
  // Keep the complete original string (including difficult float spellings)
  // while changing a signed path that must never be executed by a verifier.
  origin.record_json = origin.record_json.replace(/("receipt_path"\s*:\s*)"(?:[^"\\]|\\.)*"/u, '$1"PRIVATE-substituted-receipt.json"');
}), "RUN_ORIGIN_SIGNATURE_INVALID", testExporterOptions);

// Independently encode all three signature protocols with Node crypto. The
// effect entries originate in the existing producer fixture; the session
// authority is a public test vector, not a claim of native guest execution.
const seedKey = (byte) => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, byte)]), format: "der", type: "pkcs8" });
const publicBytes = (privateKey) => createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
const runtimeKey = seedKey(0x53), sessionKey = seedKey(0x64), originalRunKey = seedKey(0x41);
assert.equal(publicBytes(originalRunKey).toString("hex"), runAnchor);
const runtimeAnchor = publicBytes(runtimeKey).toString("hex");
const u64be = (number) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(number)); return bytes; };
const frame = (domain, bytes) => Buffer.concat([Buffer.from(domain), u64be(bytes.length), bytes]);
function ordered(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return `[${value.map(ordered).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).map((key) => `${JSON.stringify(key)}:${ordered(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const pick = (value, names) => Object.fromEntries(names.map((name) => [name, value[name]]));
const runtimeRecord = JSON.parse(originalRun.initial_state_snapshot.run_origin.record_json);
const ledger = pick(runtimeRecord.host_effect_ledger, ["schema_version", "trace_id", "chain_head_hash", "effect_count", "allowed_count", "denied_count", "failed_count"]);
ledger.entries = runtimeRecord.host_effect_ledger.entries.map((entry) => {
  const result = pick(entry, ["index", "prev_chain_hash", "receipt_hash", "chain_hash"]);
  result.receipt = pick(entry.receipt, ["schema_version", "seq", "trace_id", "effect_kind", "policy_outcome", "pre_state_hash", "args_hash", "result_hash", "post_state_hash", "input_lineage_hash", "output_lineage_hash", "label_set_commitment", "declassification_ref", "flow_policy_verdict", "recorded_at_millis"]);
  result.receipt.policy_outcome = pick(entry.receipt.policy_outcome, ["outcome", ...Object.keys(entry.receipt.policy_outcome).filter((name) => name !== "outcome")]);
  return result;
});
const sessionNonce = "0199abcd-1234-7000-8000-123456789abc";
const identity = {
  producer_id: `franken-node.native-session:ed25519:${runtimeAnchor}:${sessionNonce}`,
  key_provenance: { authority_class: "runtime", key_id: `ed25519:${hash(Buffer.concat([Buffer.from("franken-engine.evidence-signing-key.v1"), publicBytes(sessionKey)]))}`, activation_epoch: 7, rotation_sequence: 1 },
  verification_key: { inner: [...publicBytes(sessionKey)] },
};
const identityCapture = {
  schema_version: "franken-node/runtime-evidence-identity-capture/v1", session_nonce: sessionNonce,
  product_root_key_id: `ed25519:${runtimeAnchor}`, product_root_verification_key_hex: runtimeAnchor,
  evidence_verification_identity: identity,
};
identityCapture.signature_hex = sign(null, frame("franken-node.runtime-evidence-identity-capture.v1", Buffer.from(ordered(identityCapture))), runtimeKey).toString("hex");
const zeroSignature = { lower: Array(32).fill(0), upper: Array(32).fill(0) };
const envelope = { producer_id: identity.producer_id, key_provenance: identity.key_provenance, signed_epoch: 18_446_744_073_709_551_615n, verification_key: identity.verification_key, signature: zeroSignature };
const ledgerBytes = frame("franken-node:host-effect-ledger-signature:v3\0", Buffer.from(ordered(ledger)));
const sessionSignature = sign(null, Buffer.from(ordered(["franken-engine.detached-evidence-signature.v1", [...ledgerBytes], envelope])), sessionKey);
envelope.signature = { lower: [...sessionSignature.subarray(0, 32)], upper: [...sessionSignature.subarray(32)] };
runtimeRecord.host_effect_ledger = { ...ledger, signature: envelope };
function runtimeIncident(mutator = () => {}) {
  const value = clone(originalRun), record = clone(runtimeRecord), capture = clone(identityCapture);
  mutator({ value, record, capture });
  delete record.record_signature;
  record.record_signature = sign(null, Buffer.concat([Buffer.from("franken-node/run-host-effect-ledger-record-signature/v1\0"), Buffer.from(canonical(record))]), originalRunKey).toString("hex");
  value.initial_state_snapshot.run_origin.record_json = canonical(record);
  if (capture !== null) value.initial_state_snapshot.runtime_evidence_identity_capture = capture;
  value.signature = clone(incident.signature);
  return resealIncident(value);
}
const runtimeOptions = { ...testExporterOptions, runtime_anchor: runtimeAnchor };
const runtimeWire = runtimeIncident();
add("independently_signed_runtime_origin", "incident-bundle", runtimeWire, "verified", runtimeOptions);
add("runtime_origin_wrong_root", "incident-bundle", runtimeWire, "RUNTIME_ORIGIN_SIGNER_UNTRUSTED", { ...runtimeOptions, runtime_anchor: foreign });
add("runtime_origin_requires_portable_capture", "incident-bundle", originalRunBytes, "RUNTIME_ORIGIN_MISSING", { ...originalRunOptions, runtime_anchor: runtimeAnchor });
add("runtime_origin_invalid_capture_signature", "incident-bundle", runtimeIncident(({ capture }) => { capture.signature_hex = "00".repeat(64); }), "RUNTIME_ORIGIN_CAPTURE_SIGNATURE_INVALID", runtimeOptions);
add("runtime_origin_invalid_session_signature", "incident-bundle", runtimeIncident(({ record }) => { record.host_effect_ledger.signature.signature = zeroSignature; }), "RUNTIME_ORIGIN_LEDGER_SIGNATURE_INVALID", runtimeOptions);
add("runtime_origin_wrong_session_epoch", "incident-bundle", runtimeIncident(({ record }) => { record.host_effect_ledger.signature.signed_epoch = 6; }), "RUNTIME_ORIGIN_INVALID", runtimeOptions);
add("runtime_origin_wrong_session_identity", "incident-bundle", runtimeIncident(({ record }) => { record.host_effect_ledger.signature.producer_id = "PRIVATE-substitute"; }), "RUNTIME_ORIGIN_INVALID", runtimeOptions);

function nondeterminismTrace() {
  return {
    session_id: "PRIVATE-TRACE-SENTINEL",
    events: [
      { sequence: 0, source: "TimerRead", value: [0, 255], virtual_ts: 10, component: "clock" },
      { sequence: 1, source: "LaneSelectionRandom", value: [], virtual_ts: 12, component: "interpreter" },
    ],
    next_sequence: 2, capture_started_vts: 10, capture_ended_vts: 12,
    deterministic_witness: { event_count: 0, digest: 0xcbf29ce484222325n },
  };
}
function captured(state) {
  const expected = { terminal_state: state, trace_id: "trace-vector-1", console_output: [] };
  if (state === "completed") Object.assign(expected, { ir4_witness: {}, execution_value: "42", instructions_executed: 7, nondeterminism_trace: nondeterminismTrace(), lane: "deterministic", exit_code: null, decisions: null });
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
// Signed transcript structure is independently inspectable even though these
// synthetic captures make no native execution, event-value or IR claim.
for (const state of ["completed", "uncaught_exception", "engine_failure"]) {
  const candidate = captured(state);
  const expected = state === "completed" ? candidate.expected : (candidate.expected.failure_context = {
    ir3_hash: "a".repeat(64), instructions_executed: 7, dropped_console_entries: 0,
    randomness_transcript: nondeterminismTrace(), imported_module_hashes: {},
  });
  const field = state === "completed" ? "nondeterminism_trace" : "randomness_transcript";
  add(`capture_trace_${state}`, "incident-bundle", withCapture(canonical(candidate)));
  for (const [name, mutate] of [
    ["missing_fields", () => ({})],
    ["unfinished", (trace) => { trace.capture_ended_vts = null; return trace; }],
    ["backwards_window", (trace) => { trace.capture_ended_vts = 9; return trace; }],
    ["counter_mismatch", (trace) => { trace.next_sequence = 3; return trace; }],
    ["duplicate_sequence", (trace) => { trace.events[1].sequence = 0; return trace; }],
    ["gapped_sequence", (trace) => { trace.events[1].sequence = 2; return trace; }],
    ["timestamp_regression", (trace) => { trace.events[0].virtual_ts = 12; trace.events[1].virtual_ts = 11; return trace; }],
    ["outside_capture_window", (trace) => { trace.events[1].virtual_ts = 13; return trace; }],
    ["unknown_source", (trace) => { trace.events[0].source = "PRIVATE-UNKNOWN"; return trace; }],
    ["invalid_bytes", (trace) => { trace.events[0].value = [256]; return trace; }],
    ["boolean_sequence", (trace) => { trace.events[0].sequence = false; return trace; }],
    ["empty_witness_digest", (trace) => { trace.deterministic_witness.digest = 0; return trace; }],
  ]) {
    expected[field] = mutate(nondeterminismTrace());
    add(`capture_trace_${state}_${name}`, "incident-bundle", withCapture(canonical(candidate)), "EVIDENCE_INVALID");
  }
}
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
assert(sdkWire.includes('"wide_integer":18446744073709551615'));
add("integer_beyond_u64", "signed-bundle", sdkWire.replace('"wide_integer":18446744073709551615', '"wide_integer":18446744073709551616'), "EVIDENCE_INVALID", { signature_hex: sdkSignature });
add("sdk_foreign_anchor", "signed-bundle", sdkWire, "SIGNATURE_INVALID", { anchor: foreign, signature_hex: sdkSignature });
add("sdk_signature_required", "signed-bundle", sdkWire, "SIGNATURE_MALFORMED");
add("sdk_signature_wrong", "signed-bundle", sdkWire, "SIGNATURE_INVALID", { signature_hex: "00".repeat(64) });
add("sdk_noncanonical_bytes", "signed-bundle", `${sdkWire}\n`, "EVIDENCE_INVALID", { signature_hex: sdkSignature });

// Resolution decisions use the published canonical JSON and domain-separated
// Ed25519 protocol. Sign with Node crypto independently of the Rust verifier.
const candidate = {
  version: "1.2.3", package_path: "PRIVATE-package-path", resolved_url: "https://PRIVATE-registry.invalid/pkg.tgz",
  integrity: `sha256:${hash("package")}`, trust_card_ref: "PRIVATE-trust-card", trust_status: "trusted",
  bpet_risk_ref: "PRIVATE-bpet", bpet_risk: "low", dgis_risk_ref: "PRIVATE-dgis", dgis_risk: "low",
  revocation_freshness_ref: "PRIVATE-revocation", revocation_freshness: "fresh",
  compat_oracle_ref: "PRIVATE-compat", compat_status: "compatible", capability_budget_ref: "PRIVATE-budget",
};
const resolution = {
  schema_version: "resolution-receipt-v1", crypto_suite: "ed25519-v1", receipt_id: "resolution-language-vector-1",
  issued_at_millis: 18446744073709551615n, module_graph_hash: `sha256:${hash("source graph")}`,
  package_name: "demo-package", requested_range: "^1", policy_profile: "strict", capability_budget_mode: "enforced",
  decision: "admit", selected_version: candidate, rejected_alternatives: [],
  evidence_refs: Object.fromEntries(["trust_card_refs", "bpet_risk_refs", "dgis_risk_refs", "revocation_freshness_refs",
    "compat_oracle_refs", "capability_budget_refs", "policy_refs"].map((name) => [name, [`PRIVATE-${name}`]])),
  rationale: "PRIVATE-resolver-rationale", canonical_hash: "",
};
function sealResolution(receipt) {
  const payload = clone(receipt); delete payload.canonical_hash;
  const bytes = Buffer.from(canonical(payload));
  receipt.canonical_hash = `sha256:${hash(Buffer.concat([Buffer.from("franken-node/resolution-receipt/payload-hash/v1:"), u64(bytes.length), bytes]))}`;
  return { receipt, signer_key_id: `sha256:${hash(Buffer.concat([Buffer.from("franken-node/resolution-receipt/signer-key-id/v1:"), Buffer.from(anchor, "hex")]))}`,
    signature_algorithm: "ed25519-v1", signature: sign(null, Buffer.concat([Buffer.from("franken-node/resolution-receipt/signature/v1:"), Buffer.from(canonical(receipt))]), key).toString("hex") };
}
const signedResolution = sealResolution(clone(resolution));
const resolutionWire = canonical(signedResolution);
add("resolution_signed_admission", "resolution-receipt", resolutionWire, "verified", { decision: "admit", graph_hash: resolution.module_graph_hash });
const rejectedResolution = clone(resolution);
rejectedResolution.decision = "reject"; rejectedResolution.selected_version = null;
rejectedResolution.rejected_alternatives = [{ candidate: { ...candidate, trust_status: "quarantined" }, reason: "trust_card_quarantined", rationale: "PRIVATE-quarantined" }];
add("resolution_signed_rejection", "resolution-receipt", canonical(sealResolution(rejectedResolution)), "verified", { decision: "reject", graph_hash: resolution.module_graph_hash });
add("resolution_foreign_anchor", "resolution-receipt", resolutionWire, "SIGNER_UNTRUSTED", { anchor: foreign });
const graphMutation = clone(signedResolution); graphMutation.receipt.module_graph_hash = `sha256:${hash("different graph")}`;
add("resolution_changed_graph", "resolution-receipt", canonical(graphMutation), "INTEGRITY_MISMATCH");
const resealedResolution = sealResolution(graphMutation.receipt); resealedResolution.signature = signedResolution.signature;
add("resolution_rehashed_without_signer", "resolution-receipt", canonical(resealedResolution), "SIGNATURE_INVALID");
const zeroResolutionSignature = clone(signedResolution); zeroResolutionSignature.signature = "00".repeat(64);
add("resolution_invalid_signature", "resolution-receipt", canonical(zeroResolutionSignature), "SIGNATURE_INVALID");
const shortResolutionSignature = clone(signedResolution); shortResolutionSignature.signature = "aa";
add("resolution_short_signature", "resolution-receipt", canonical(shortResolutionSignature), "SIGNATURE_MALFORMED");
const absentCandidate = clone(resolution); absentCandidate.selected_version = null;
add("resolution_admission_requires_candidate", "resolution-receipt", canonical(sealResolution(absentCandidate)), "EVIDENCE_INVALID");
const contradictoryRejection = clone(resolution); contradictoryRejection.decision = "reject";
add("resolution_rejection_cannot_select_candidate", "resolution-receipt", canonical(sealResolution(contradictoryRejection)), "EVIDENCE_INVALID");
const inadmissible = clone(resolution); inadmissible.selected_version.trust_status = "revoked";
add("resolution_signed_revoked_candidate", "resolution-receipt", canonical(sealResolution(inadmissible)), "EVIDENCE_INVALID");
const unknownResolutionField = clone(signedResolution); unknownResolutionField.unsigned_claim = "trusted";
add("resolution_unknown_unsigned_field", "resolution-receipt", canonical(unknownResolutionField), "EVIDENCE_INVALID");
add("resolution_noncanonical_bytes", "resolution-receipt", `${resolutionWire}\n`, "EVIDENCE_INVALID");
add("resolution_duplicate_member", "resolution-receipt", `${resolutionWire.slice(0, -1)},"signature":"00"}`, "JSON_INVALID");
// Sign exact registration bytes independently, retaining each genuine product
// capsule without regeneration. Reading the capsule header below computes
// expected public counts only; no source or module is executed.
const sourceFixtures = JSON.parse(readFileSync(sourceCapsulesPath, "utf8"));
assert.equal(sourceFixtures.execution_performed, false);
assert.equal(sourceFixtures.vectors.length, 3);
const sourceAuthority = {
  schema_version: "franken-node/artifact-runtime-authority/v1", policy_revision: "publisher-policy-1",
  allowed_capabilities: ["console", "heap_allocate", "vm_dispatch"], allow_process_shape: false,
  max_instructions: 18_446_744_073_709_551_615n, max_registers: 65_536,
  max_call_depth: 10_000, max_heap_objects: 4_294_967_295,
  max_total_memory_bytes: 18_446_744_073_709_551_615n, max_console_entries: 4_294_967_295,
  max_parse_source_bytes: 2_097_152, max_parse_tokens: 131_072, max_parse_recursion_depth: 384,
};
function sourceManifest(capsuleBytes, version = 1) {
  const manifest = {
    schema_version: `franken-node/extension-registration-manifest/v${version}`,
    name: "source-vector", publisher_id: "publisher-node-vector",
    initial_version: { version: "1.2.3", parent_version: null, content_hash: hash(capsuleBytes),
      registered_at: "2026-11-10T00:00:00Z", compatible_with: [] },
    tags: ["PRIVATE-publisher-tag"],
  };
  if (version === 2) manifest.runtime_authority = clone(sourceAuthority);
  return manifest;
}
function sourceInput(manifestBytes, capsuleBytes) {
  return JSON.stringify({
    schema_version: "franken-verifier/publisher-source-input/v1",
    manifest_base64: manifestBytes.toString("base64"), capsule_base64: capsuleBytes.toString("base64"),
  });
}
function sourceFacts(manifest, manifestBytes, capsuleBytes) {
  assert.equal(capsuleBytes.subarray(0, 8).toString("ascii"), "FNSGCAP1");
  const headerLength = capsuleBytes.readUInt32LE(8);
  const header = JSON.parse(capsuleBytes.subarray(12, 12 + headerLength));
  const countKind = (kind) => header.inputs.filter((input) => input.content.kind === kind).length;
  const runtimeAuthority = manifest.runtime_authority === undefined ? null
    : Object.fromEntries(Object.entries(manifest.runtime_authority).map(([name, value]) =>
      [name, name.startsWith("max_") ? String(value) : value]));
  if (runtimeAuthority !== null && Object.hasOwn(runtimeAuthority, "host_io")) {
    if (runtimeAuthority.host_io === null) delete runtimeAuthority.host_io;
    else {
      const host = runtimeAuthority.host_io;
      runtimeAuthority.host_io = {
        ...(host.host_ports == null ? {} : { host_ports: [...new Set(host.host_ports)].sort() }),
        ...(host.env_keys == null ? {} : { env_keys: [...new Set(host.env_keys)].sort() }),
        max_calls_per_epoch: Object.fromEntries(Object.entries(host.max_calls_per_epoch ?? {})
          .map(([capability, limit]) => [capability, String(limit)])),
      };
    }
  }
  return {
    registration_schema: manifest.schema_version, package_name: manifest.name, publisher_id: manifest.publisher_id,
    version: manifest.initial_version.version, manifest_sha256: `sha256:${hash(manifestBytes)}`,
    artifact_sha256: `sha256:${hash(capsuleBytes)}`,
    capsule_digest: `sha256:${hash(Buffer.concat([Buffer.from("franken-node/module-source-capsule/v1\0"), u64(capsuleBytes.length), capsuleBytes]))}`,
    signer_key_id: hash(Buffer.concat([Buffer.from("artifact_signing_keyid_v1:"), u64(32), Buffer.from(anchor, "hex")])).slice(0, 16),
    signer_public_key_hex: anchor, runtime_authority: runtimeAuthority,
    capsule: {
      schema_version: header.schema_version, graph_input_hash: header.graph_hash, graph_hash_recomputed: false,
      capsule_bytes: capsuleBytes.length, payload_bytes: capsuleBytes.length - 12 - headerLength,
      input_count: header.inputs.length, file_count: countKind("file"), metadata_file_count: countKind("file_metadata"),
      directory_count: countKind("directory"), missing_count: countKind("missing"), symlink_count: countKind("symlink"),
      symlink_policy: header.options.symlink_policy, condition_count: header.options.conditions?.length ?? null,
      additional_condition_count: header.options.additional_conditions?.length ?? 0,
    },
  };
}
function addSource(name, capsuleBytes, manifest, expected = "verified", options = {}) {
  const manifestBytes = Buffer.from(ordered(manifest));
  add(name, "publisher-source", sourceInput(manifestBytes, capsuleBytes), expected, {
    signature_hex: sign(null, manifestBytes, key).toString("hex"),
    ...(expected === "verified" ? { publisher_facts: sourceFacts(manifest, manifestBytes, capsuleBytes) } : {}),
    ...options,
  });
}
for (const [index, fixture] of sourceFixtures.vectors.entries()) {
  const sourceBytes = Buffer.from(fixture.module_sources.capsule_base64, "base64");
  for (const version of [1, 2]) {
    const manifest = sourceManifest(sourceBytes, version);
    const facts = sourceFacts(manifest, Buffer.from(ordered(manifest)), sourceBytes);
    assert.equal(facts.capsule_digest, fixture.module_sources.capsule_digest);
    assert.equal(facts.capsule.graph_input_hash, fixture.module_sources.graph_input_hash);
    assert.equal(facts.capsule.input_count, fixture.observation_count);
    addSource(`publisher_source_v${version}_fixture_${index}`, sourceBytes, manifest);
  }
}
const sourceBytes = Buffer.from(sourceFixtures.vectors[0].module_sources.capsule_base64, "base64");
const registration = sourceManifest(sourceBytes, 2);
const registrationBytes = Buffer.from(ordered(registration));
const sourceWire = sourceInput(registrationBytes, sourceBytes);
const sourceSignature = sign(null, registrationBytes, key).toString("hex");
assert(registrationBytes.includes(Buffer.from('"max_instructions":18446744073709551615')));
const hostRegistration = clone(registration);
hostRegistration.runtime_authority.allowed_capabilities = [
  "console", "env_read", "fs_read", "heap_allocate", "network_egress", "vm_dispatch",
];
hostRegistration.runtime_authority.host_io = {
  host_ports: ["[2001:db8::1]:443", "api.example.test:443"], env_keys: ["PUBLIC_NAME"],
  max_calls_per_epoch: { env_read: 1, fs_read: 0, network_egress: 18_446_744_073_709_551_615n },
};
addSource("publisher_source_scoped_host_authority", sourceBytes, hostRegistration);
const emptyHostRegistration = clone(hostRegistration);
emptyHostRegistration.runtime_authority.host_io = { host_ports: [], env_keys: [] };
addSource("publisher_source_explicit_empty_host_scopes", sourceBytes, emptyHostRegistration);
const unspecifiedHostRegistration = clone(hostRegistration);
unspecifiedHostRegistration.runtime_authority.host_io = { max_calls_per_epoch: { fs_read: 0 } };
addSource("publisher_source_unspecified_host_scopes", sourceBytes, unspecifiedHostRegistration);
const processRegistration = clone(hostRegistration);
processRegistration.runtime_authority.allowed_capabilities.push("fs_write", "process_spawn", "random_read");
processRegistration.runtime_authority.host_io.max_calls_per_epoch = {
  env_read: 1, fs_read: 0, fs_write: 1, network_egress: 1, random_read: 1,
  process_spawn: 18_446_744_073_709_551_615n,
};
addSource("publisher_source_process_quota_maximum", sourceBytes, processRegistration);
const zeroProcessRegistration = clone(processRegistration);
zeroProcessRegistration.runtime_authority.host_io.max_calls_per_epoch.process_spawn = 0;
addSource("publisher_source_process_quota_zero", sourceBytes, zeroProcessRegistration);
const undeclaredProcessRegistration = clone(processRegistration);
undeclaredProcessRegistration.runtime_authority.allowed_capabilities =
  undeclaredProcessRegistration.runtime_authority.allowed_capabilities.filter((cap) => cap !== "process_spawn");
addSource("publisher_source_undeclared_process_quota", sourceBytes, undeclaredProcessRegistration, "EVIDENCE_INVALID");
const excessiveProcessRegistration = clone(processRegistration);
excessiveProcessRegistration.runtime_authority.max_instructions = 1;
addSource("publisher_source_excessive_process_quota", sourceBytes, excessiveProcessRegistration, "EVIDENCE_INVALID");
const changedProcessRegistration = clone(zeroProcessRegistration);
changedProcessRegistration.runtime_authority.host_io.max_calls_per_epoch.process_spawn = 1;
add("publisher_source_changed_signed_process_quota", "publisher-source",
  sourceInput(Buffer.from(ordered(changedProcessRegistration)), sourceBytes), "SIGNATURE_INVALID", {
    signature_hex: sign(null, Buffer.from(ordered(zeroProcessRegistration)), key).toString("hex"),
  });
for (const [name, scope] of [
  ["wildcard", { host_ports: ["*.example.test:443"] }],
  ["invalid_port", { host_ports: ["api.example.test:65536"] }],
  ["invalid_ipv6", { host_ports: ["[fe80::1%eth0]:443"] }],
  ["undeclared_quota", { max_calls_per_epoch: { fs_write: 1 } }],
  ["numeric_string_quota", { max_calls_per_epoch: { fs_read: "0" } }],
  ["unknown_scope", { path_prefixes: ["/private"] }],
]) {
  const changed = clone(hostRegistration);
  changed.runtime_authority.host_io = scope;
  addSource(`publisher_source_invalid_host_${name}`, sourceBytes, changed, "EVIDENCE_INVALID");
}
const tamperedHost = clone(hostRegistration);
tamperedHost.runtime_authority.host_io.env_keys = ["OTHER_NAME"];
add("publisher_source_changed_signed_host_scope", "publisher-source",
  sourceInput(Buffer.from(ordered(tamperedHost)), sourceBytes), "SIGNATURE_INVALID", {
    signature_hex: sign(null, Buffer.from(ordered(hostRegistration)), key).toString("hex"),
  });
const formattedRegistration = sourceManifest(sourceBytes, 1);
const formattedBytes = Buffer.from(JSON.stringify(formattedRegistration, null, 2) + "\n");
add("publisher_source_exact_formatted_manifest", "publisher-source", sourceInput(formattedBytes, sourceBytes), "verified", {
  signature_hex: sign(null, formattedBytes, key).toString("hex"),
  publisher_facts: sourceFacts(formattedRegistration, formattedBytes, sourceBytes),
});
add("publisher_source_foreign_anchor", "publisher-source", sourceWire, "SIGNATURE_INVALID", { anchor: foreign, signature_hex: sourceSignature });
add("publisher_source_invalid_signature", "publisher-source", sourceWire, "SIGNATURE_INVALID", { signature_hex: "00".repeat(64) });
add("publisher_source_signature_required", "publisher-source", sourceWire, "SIGNATURE_MALFORMED");
add("publisher_source_signature_short", "publisher-source", sourceWire, "SIGNATURE_MALFORMED", { signature_hex: "aa" });
const mutatedManifest = clone(registration); mutatedManifest.name = "other-source";
add("publisher_source_changed_signed_bytes", "publisher-source",
  sourceInput(Buffer.from(ordered(mutatedManifest)), sourceBytes), "SIGNATURE_INVALID", { signature_hex: sourceSignature });
const changedSource = Buffer.from(sourceBytes); changedSource[changedSource.length - 1] ^= 1;
add("publisher_source_changed_capsule", "publisher-source", sourceInput(registrationBytes, changedSource), "INTEGRITY_MISMATCH", { signature_hex: sourceSignature });
const wrongArtifactHash = clone(registration); wrongArtifactHash.initial_version.content_hash = "0".repeat(64);
addSource("publisher_source_signed_wrong_hash", sourceBytes, wrongArtifactHash, "INTEGRITY_MISMATCH");
const unknownRegistration = clone(registration); unknownRegistration.schema_version = "franken-node/extension-registration-manifest/v99";
addSource("publisher_source_signed_unknown_schema", sourceBytes, unknownRegistration, "EVIDENCE_INVALID");
const unknownRegistrationMember = clone(registration); unknownRegistrationMember.execution_authorized = true;
addSource("publisher_source_signed_unknown_member", sourceBytes, unknownRegistrationMember, "EVIDENCE_INVALID");
const v1Authority = clone(registration); v1Authority.schema_version = "franken-node/extension-registration-manifest/v1";
addSource("publisher_source_v1_cannot_smuggle_authority", sourceBytes, v1Authority, "EVIDENCE_INVALID");
const absentAuthority = clone(registration); delete absentAuthority.runtime_authority;
addSource("publisher_source_v2_requires_authority", sourceBytes, absentAuthority, "EVIDENCE_INVALID");
const badCapabilities = clone(registration); badCapabilities.runtime_authority.allowed_capabilities = ["console", "vm_dispatch"];
addSource("publisher_source_missing_required_capability", sourceBytes, badCapabilities, "EVIDENCE_INVALID");
const badCeiling = clone(registration); badCeiling.runtime_authority.max_parse_tokens = 131_073;
addSource("publisher_source_excessive_parser_ceiling", sourceBytes, badCeiling, "EVIDENCE_INVALID");
const numericCeilingString = clone(registration); numericCeilingString.runtime_authority.max_instructions = "18446744073709551615";
addSource("publisher_source_manifest_ceiling_requires_integer", sourceBytes, numericCeilingString, "EVIDENCE_INVALID");
const badCapsule = Buffer.from("PRIVATE-PUBLISHER-SOURCE-SENTINEL");
addSource("publisher_source_signed_malformed_capsule", badCapsule, sourceManifest(badCapsule), "EVIDENCE_INVALID");
addSource("publisher_source_signed_corrupt_file_payload", changedSource, sourceManifest(changedSource), "EVIDENCE_INVALID");
const headerLength = sourceBytes.readUInt32LE(8);
const header = JSON.parse(sourceBytes.subarray(12, 12 + headerLength));
header.graph_hash = "sha256:invalid";
const malformedHeader = Buffer.from(JSON.stringify(header));
const malformedPrefix = Buffer.alloc(12); malformedPrefix.write("FNSGCAP1"); malformedPrefix.writeUInt32LE(malformedHeader.length, 8);
const malformedGraphCapsule = Buffer.concat([malformedPrefix, malformedHeader, sourceBytes.subarray(12 + headerLength)]);
addSource("publisher_source_signed_bad_graph_digest", malformedGraphCapsule, sourceManifest(malformedGraphCapsule), "EVIDENCE_INVALID");
add("publisher_source_transport_duplicate", "publisher-source", sourceWire.slice(0, -1) + ',"capsule_base64":""}',
  "JSON_INVALID", { signature_hex: sourceSignature });
const duplicateRegistration = Buffer.from(ordered(registration).slice(0, -1) + ',"name":"duplicate"}');
add("publisher_source_signed_duplicate_manifest", "publisher-source", sourceInput(duplicateRegistration, sourceBytes),
  "EVIDENCE_INVALID", { signature_hex: sign(null, duplicateRegistration, key).toString("hex") });
const transportUnknown = JSON.parse(sourceWire); transportUnknown.execution_authorized = true;
add("publisher_source_transport_unknown", "publisher-source", JSON.stringify(transportUnknown), "EVIDENCE_INVALID", { signature_hex: sourceSignature });
const transportSchema = JSON.parse(sourceWire); transportSchema.schema_version = "franken-verifier/publisher-source-input/v99";
add("publisher_source_transport_schema", "publisher-source", JSON.stringify(transportSchema), "EVIDENCE_INVALID", { signature_hex: sourceSignature });
const noncanonicalBase64 = JSON.parse(sourceWire); noncanonicalBase64.capsule_base64 += "\n";
add("publisher_source_noncanonical_base64", "publisher-source", JSON.stringify(noncanonicalBase64), "EVIDENCE_INVALID", { signature_hex: sourceSignature });

// Independently signed publisher trust statements. Publisher, revocation, and
// provenance authorities are distinct; only caller metadata carries trust keys,
// evaluation time, and the maximum revocation age.
const sourceRevocationKey = seedKey(0x71), sourceProvenanceKey = seedKey(0x72);
const sourceRevocationAnchor = publicBytes(sourceRevocationKey).toString("hex");
const sourceProvenanceAnchor = publicBytes(sourceProvenanceKey).toString("hex");
assert.equal(new Set([anchor, sourceRevocationAnchor, sourceProvenanceAnchor]).size, 3);
const revocationDomain = "franken-node/publisher-revocation-list/v1:";
const provenanceDomain = "franken-node/publisher-provenance-chain/v1:";
const trustRevocations = {
  schema_version: "franken-node/publisher-revocation-list/v1", issued_at: "2026-11-11T00:00:00Z",
  revoked_publisher_ids: [], revoked_signer_key_ids: [], revoked_package_versions: [],
};
function sourceTrustSignature(domain, bytes, authority) {
  return sign(null, Buffer.concat([Buffer.from(domain), u64(bytes.length), bytes]), authority).toString("hex");
}
function sourceProvenance(manifest, manifestBytes) {
  return {
    schema_version: "franken-node/publisher-provenance-chain/v1",
    package_name: manifest.name, publisher_id: manifest.publisher_id,
    links: [{ version: manifest.initial_version.version, parent_version: manifest.initial_version.parent_version,
      content_hash: manifest.initial_version.content_hash, manifest_sha256: `sha256:${hash(manifestBytes)}`,
      previous_link_sha256: null }],
  };
}
function sourceProvenanceLinkDigest(link) {
  const optional = (value) => value === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), lp(value)]);
  return `sha256:${hash(Buffer.concat([
    Buffer.from("franken-node/publisher-provenance-link/v1:"), lp(link.version), optional(link.parent_version),
    lp(link.content_hash), lp(link.manifest_sha256), optional(link.previous_link_sha256),
  ]))}`;
}
function addSourceTrust(name, expected = "verified", options = {}) {
  const manifest = options.manifest ?? registration;
  const manifestBytes = options.manifestBytes ?? Buffer.from(ordered(manifest));
  const capsuleBytes = options.capsuleBytes ?? sourceBytes;
  const revocations = options.revocations ?? trustRevocations;
  const revocationBytes = options.revocationBytes ?? Buffer.from(ordered(revocations));
  const provenance = options.provenance === null ? null : options.provenance ?? sourceProvenance(manifest, manifestBytes);
  const provenanceBytes = provenance === null ? null : options.provenanceBytes ?? Buffer.from(ordered(provenance));
  const transport = {
    schema_version: "franken-verifier/publisher-source-trust-input/v1",
    manifest_base64: manifestBytes.toString("base64"), capsule_base64: capsuleBytes.toString("base64"),
    revocation_list_base64: revocationBytes.toString("base64"),
    revocation_signature_hex: sourceTrustSignature(revocationDomain, revocationBytes, sourceRevocationKey),
  };
  if (provenanceBytes !== null) transport.provenance = {
    chain_base64: provenanceBytes.toString("base64"),
    signature_hex: sourceTrustSignature(provenanceDomain, provenanceBytes, sourceProvenanceKey),
  };
  options.mutate?.(transport);
  const metadata = {
    signature_hex: sign(null, manifestBytes, key).toString("hex"), revocation_anchor: sourceRevocationAnchor,
    provenance_anchor: provenanceBytes === null ? null : sourceProvenanceAnchor,
    evaluation_time: "2026-11-11T00:30:00Z", max_revocation_age_secs: "3600", ...options.metadata,
  };
  const facts = expected === "verified" ? {
    source: sourceFacts(manifest, manifestBytes, capsuleBytes),
    revocation_list_sha256: `sha256:${hash(revocationBytes)}`,
    revocation_authority_public_key_hex: metadata.revocation_anchor,
    revocation_issued_at: revocations.issued_at,
    revocation_evaluated_at: options.evaluatedAt ?? metadata.evaluation_time,
    max_revocation_age_secs: metadata.max_revocation_age_secs,
    provenance_chain_sha256: provenanceBytes === null ? null : `sha256:${hash(provenanceBytes)}`,
    provenance_authority_public_key_hex: provenanceBytes === null ? null : metadata.provenance_anchor,
    provenance_link_count: provenance === null ? null : provenance.links.length,
  } : null;
  add(name, "publisher-source-trust", options.wire?.(transport) ?? JSON.stringify(transport), expected, {
    ...metadata, ...(facts === null ? {} : { publisher_trust_facts: facts }),
  });
}
// These retained expectations describe the approved release, not whichever
// candidate is later signed. Signatures on substitutions remain genuine.
const approvedSource = sourceFacts(registration, registrationBytes, sourceBytes);
const approvedIdentity = {
  expected_manifest_sha256: approvedSource.manifest_sha256,
  expected_source_artifact_sha256: approvedSource.artifact_sha256,
  expected_graph_input_hash: approvedSource.capsule.graph_input_hash,
};
addSource("publisher_identity_manifest_pin", sourceBytes, registration, "verified", {
  expected_manifest_sha256: approvedIdentity.expected_manifest_sha256,
});
addSource("publisher_identity_all_pins", sourceBytes, registration, "verified", approvedIdentity);
const substitutedVersion = clone(registration);
substitutedVersion.initial_version.version = "8.9.10";
const substitutedAuthority = clone(registration);
substitutedAuthority.runtime_authority.policy_revision = "another-valid-policy";
for (const [name, candidate] of [["version", substitutedVersion], ["authority", substitutedAuthority]]) {
  addSource(`publisher_identity_signed_${name}_substitution`, sourceBytes, candidate,
    "EXPECTED_IDENTITY_MISMATCH", approvedIdentity);
  addSourceTrust(`publisher_trust_identity_signed_${name}_substitution`, "EXPECTED_IDENTITY_MISMATCH", {
    manifest: candidate, metadata: approvedIdentity,
  });
}
add("publisher_identity_signed_manifest_spelling_substitution", "publisher-source",
  sourceInput(formattedBytes, sourceBytes), "EXPECTED_IDENTITY_MISMATCH", {
    signature_hex: sign(null, formattedBytes, key).toString("hex"), ...approvedIdentity,
  });
const otherSourceBytes = Buffer.from(sourceFixtures.vectors[1].module_sources.capsule_base64, "base64");
addSource("publisher_identity_signed_artifact_substitution", otherSourceBytes, sourceManifest(otherSourceBytes, 2),
  "EXPECTED_IDENTITY_MISMATCH", approvedIdentity);
for (const field of Object.keys(approvedIdentity)) {
  const pins = { ...approvedIdentity, [field]: "sha256:" + "0".repeat(64) };
  addSource(`publisher_identity_mismatch_${field}`, sourceBytes, registration, "EXPECTED_IDENTITY_MISMATCH", pins);
  addSourceTrust(`publisher_trust_identity_mismatch_${field}`, "EXPECTED_IDENTITY_MISMATCH", { metadata: pins });
}
addSourceTrust("publisher_trust_identity_all_pins", "verified", { metadata: approvedIdentity });
addSourceTrust("publisher_trust_identity_manifest_pin", "verified", {
  provenance: null, metadata: { expected_manifest_sha256: approvedIdentity.expected_manifest_sha256 },
});
addSourceTrust("publisher_trust_identity_does_not_override_revocation", "PUBLISHER_REVOKED", {
  metadata: approvedIdentity, revocations: { ...trustRevocations, revoked_publisher_ids: [registration.publisher_id] },
});
addSource("publisher_identity_does_not_override_signature", sourceBytes, registration, "SIGNATURE_INVALID", {
  ...approvedIdentity, signature_hex: "00".repeat(64),
});
for (const [name, invalidPin] of [["missing_prefix", "a".repeat(64)], ["uppercase", "sha256:" + "A".repeat(64)],
  ["newline", approvedIdentity.expected_manifest_sha256 + "\n"], ["empty", ""]]) {
  const pins = { ...approvedIdentity, expected_manifest_sha256: invalidPin };
  addSource(`publisher_identity_invalid_${name}`, sourceBytes, registration, "EXPECTED_IDENTITY_INVALID", pins);
  addSourceTrust(`publisher_trust_identity_invalid_${name}`, "EXPECTED_IDENTITY_INVALID", { metadata: pins });
}
addSourceTrust("publisher_trust_fresh_revocation_without_provenance", "verified", { provenance: null });
addSourceTrust("publisher_trust_independent_revocation_and_provenance");
addSourceTrust("publisher_trust_scoped_host_authority", "verified", { manifest: hostRegistration });
const formattedProvenance = sourceProvenance(formattedRegistration, formattedBytes);
addSourceTrust("publisher_trust_exact_formatted_signed_bytes", "verified", {
  manifest: formattedRegistration, manifestBytes: formattedBytes,
  revocationBytes: Buffer.from(JSON.stringify(trustRevocations, null, 2) + "\n"),
  provenance: formattedProvenance, provenanceBytes: Buffer.from(JSON.stringify(formattedProvenance, null, 2) + "\n"),
  wire: (transport) => JSON.stringify(transport, null, 2) + "\n",
});
addSourceTrust("publisher_trust_timezone_normalizes_evaluation", "verified", {
  metadata: { evaluation_time: "2026-11-11t01:30:00.000000000+01:00" }, evaluatedAt: "2026-11-11T00:30:00Z",
});
addSourceTrust("publisher_trust_last_fresh_nanosecond", "verified", {
  metadata: { evaluation_time: "2026-11-11T00:59:59.999999999Z" },
});
addSourceTrust("publisher_trust_u64_max_age_is_lossless", "verified", {
  metadata: { max_revocation_age_secs: "18446744073709551615" },
});

// Two actual source-capsule fixtures anchor a linked history. Node computes
// each parent-link digest independently; no producer/verifier helper is used.
const priorSourceBytes = Buffer.from(sourceFixtures.vectors[1].module_sources.capsule_base64, "base64");
const priorRegistration = sourceManifest(priorSourceBytes, 2); priorRegistration.initial_version.version = "1.0.0";
const priorRegistrationBytes = Buffer.from(ordered(priorRegistration));
const linkedRegistration = clone(registration); linkedRegistration.initial_version.parent_version = "1.0.0";
const linkedRegistrationBytes = Buffer.from(ordered(linkedRegistration));
const genesisLink = sourceProvenance(priorRegistration, priorRegistrationBytes).links[0];
const linkedProvenance = sourceProvenance(linkedRegistration, linkedRegistrationBytes);
linkedProvenance.links[0].previous_link_sha256 = sourceProvenanceLinkDigest(genesisLink);
linkedProvenance.links.unshift(genesisLink);
addSourceTrust("publisher_trust_linked_source_history", "verified", {
  manifest: linkedRegistration, manifestBytes: linkedRegistrationBytes, provenance: linkedProvenance,
});

for (const [name, metadata] of [
  ["publisher", { anchor: foreign }],
  ["revocation", { revocation_anchor: foreign }],
  ["provenance", { provenance_anchor: foreign }],
  ["swapped_authorities", { revocation_anchor: sourceProvenanceAnchor, provenance_anchor: sourceRevocationAnchor }],
]) addSourceTrust(`publisher_trust_foreign_${name}`, "SIGNATURE_INVALID", { metadata });
for (const [name, mutate] of [
  ["manifest", (transport) => { transport.manifest_base64 = Buffer.concat([registrationBytes, Buffer.from("\n")]).toString("base64"); }],
  ["revocations", (transport) => { transport.revocation_list_base64 = Buffer.concat([Buffer.from(transport.revocation_list_base64, "base64"), Buffer.from("\n")]).toString("base64"); }],
  ["provenance", (transport) => { transport.provenance.chain_base64 = Buffer.concat([Buffer.from(transport.provenance.chain_base64, "base64"), Buffer.from("\n")]).toString("base64"); }],
]) addSourceTrust(`publisher_trust_changed_signed_${name}`, "SIGNATURE_INVALID", { mutate });
addSourceTrust("publisher_trust_changed_capsule", "INTEGRITY_MISMATCH", {
  mutate: (transport) => { transport.capsule_base64 = changedSource.toString("base64"); },
});
addSourceTrust("publisher_trust_revocation_signature_domain_is_bound", "SIGNATURE_INVALID", {
  mutate: (transport) => { transport.revocation_signature_hex = sourceTrustSignature(provenanceDomain,
    Buffer.from(transport.revocation_list_base64, "base64"), sourceRevocationKey); },
});
addSourceTrust("publisher_trust_provenance_signature_domain_is_bound", "SIGNATURE_INVALID", {
  mutate: (transport) => { transport.provenance.signature_hex = sourceTrustSignature(revocationDomain,
    Buffer.from(transport.provenance.chain_base64, "base64"), sourceProvenanceKey); },
});

const sourceSignerId = sourceFacts(registration, registrationBytes, sourceBytes).signer_key_id;
for (const [name, changes] of [
  ["publisher", { revoked_publisher_ids: [registration.publisher_id] }],
  ["signer", { revoked_signer_key_ids: [sourceSignerId] }],
  ["package", { revoked_package_versions: [`${registration.name}@1.2.3`] }],
  ["numeric_alias", { revoked_package_versions: [`${registration.name}@01.02.03`] }],
]) addSourceTrust(`publisher_trust_revoked_${name}`, "PUBLISHER_REVOKED", { revocations: { ...trustRevocations, ...changes } });
const aliasRegistration = clone(registration); aliasRegistration.initial_version.version = "01.02.03";
addSourceTrust("publisher_trust_revoked_manifest_numeric_alias", "PUBLISHER_REVOKED", {
  manifest: aliasRegistration, revocations: { ...trustRevocations, revoked_package_versions: [`${registration.name}@1.2.3`] },
});
const scopedRegistration = clone(registration); scopedRegistration.name = "@audit/source-vector";
addSourceTrust("publisher_trust_revoked_scoped_numeric_alias", "PUBLISHER_REVOKED", {
  manifest: scopedRegistration, revocations: { ...trustRevocations, revoked_package_versions: ["@audit/source-vector@01.2.03"] },
});
addSourceTrust("publisher_trust_unrelated_scoped_revocation_does_not_deny", "verified", {
  manifest: scopedRegistration, revocations: { ...trustRevocations, revoked_package_versions: ["@other/source-vector@1.2.3"] },
});

addSourceTrust("publisher_trust_exact_stale_boundary", "REVOCATION_STALE", {
  metadata: { evaluation_time: "2026-11-11T01:00:00Z" },
});
addSourceTrust("publisher_trust_future_revocation_by_one_nanosecond", "REVOCATION_NOT_YET_VALID", {
  revocations: { ...trustRevocations, issued_at: "2026-11-11T00:30:00.000000001Z" },
});
// Sign the invalid timestamp exactly: a valid authority signature cannot make
// an unrepresentable instant safe to truncate or normalize during verification.
for (const [name, issuedAt] of [
  ["sub_nanosecond_future", "2026-11-11T00:30:00.0000000001Z"],
  ["excess_zero_precision", "2026-11-11T00:00:00.0000000000Z"],
  ["leap_second", "2026-11-11T00:00:60Z"],
]) addSourceTrust(`publisher_trust_signed_invalid_issue_time_${name}`, "EVIDENCE_INVALID", {
  revocations: { ...trustRevocations, issued_at: issuedAt },
});
for (const age of ["0", "18446744073709551616"]) addSourceTrust(`publisher_trust_invalid_age_${age}`,
  "REVOCATION_FRESHNESS_POLICY_INVALID", { metadata: { max_revocation_age_secs: age } });
addSourceTrust("publisher_trust_invalid_caller_time", "EVALUATION_TIME_INVALID", {
  metadata: { evaluation_time: "2026-11-11T00:30:60Z" },
});
addSourceTrust("publisher_trust_signed_malformed_revocation_identity", "EVIDENCE_INVALID", {
  revocations: { ...trustRevocations, revoked_package_versions: ["source-vector@1.2"] },
});
const wrongTip = sourceProvenance(registration, registrationBytes);
wrongTip.links[0].manifest_sha256 = `sha256:${hash("different signed registration")}`;
addSourceTrust("publisher_trust_genuine_signature_over_wrong_tip", "EVIDENCE_INVALID", { provenance: wrongTip });
const brokenHistory = clone(linkedProvenance);
brokenHistory.links[1].previous_link_sha256 = `sha256:${hash("different previous link")}`;
addSourceTrust("publisher_trust_genuine_signature_over_broken_history", "EVIDENCE_INVALID", {
  manifest: linkedRegistration, manifestBytes: linkedRegistrationBytes, provenance: brokenHistory,
});
addSourceTrust("publisher_trust_provenance_requires_external_anchor", "EVIDENCE_INVALID", {
  metadata: { provenance_anchor: null },
});
addSourceTrust("publisher_trust_provenance_anchor_requires_evidence", "EVIDENCE_INVALID", {
  provenance: null, metadata: { provenance_anchor: sourceProvenanceAnchor },
});
addSourceTrust("publisher_trust_null_provenance_is_not_absent", "EVIDENCE_INVALID", {
  provenance: null, mutate: (transport) => { transport.provenance = null; },
});
addSourceTrust("publisher_trust_partial_provenance_is_rejected", "EVIDENCE_INVALID", {
  mutate: (transport) => { delete transport.provenance.signature_hex; },
});
for (const [field, value] of [
  ["evaluation_time", "1900-01-01T00:00:00Z"], ["max_revocation_age_secs", "18446744073709551615"],
  ["revocation_authority", sourceRevocationAnchor], ["provenance_authority", sourceProvenanceAnchor],
]) addSourceTrust(`publisher_trust_cannot_inject_${field}`, "EVIDENCE_INVALID", {
  mutate: (transport) => { transport[field] = value; },
});
addSourceTrust("publisher_trust_cannot_inject_nested_anchor", "EVIDENCE_INVALID", {
  mutate: (transport) => { transport.provenance.trusted_key = sourceProvenanceAnchor; },
});
for (const [name, mutate] of [
  ["revocation", (transport) => { transport.revocation_list_base64 += "\n"; }],
  ["provenance", (transport) => { transport.provenance.chain_base64 += "\n"; }],
]) addSourceTrust(`publisher_trust_noncanonical_${name}_encoding`, "EVIDENCE_INVALID", { mutate });
addSourceTrust("publisher_trust_duplicate_transport_member", "JSON_INVALID", {
  wire: (transport) => JSON.stringify(transport).slice(0, -1) + ',"revocation_list_base64":""}',
});
addSourceTrust("publisher_trust_signed_duplicate_revocation_member", "EVIDENCE_INVALID", {
  revocationBytes: Buffer.from(ordered(trustRevocations).slice(0, -1) + ',"issued_at":"2026-11-11T00:00:00Z"}'),
});
addSourceTrust("publisher_trust_short_revocation_signature", "EVIDENCE_INVALID", {
  mutate: (transport) => { transport.revocation_signature_hex = "aa"; },
});
addSourceTrust("publisher_trust_short_provenance_signature", "EVIDENCE_INVALID", {
  mutate: (transport) => { transport.provenance.signature_hex = "aa"; },
});
addSourceTrust("publisher_trust_publisher_signature_required", "SIGNATURE_MALFORMED", {
  metadata: { signature_hex: null },
});

// Counterfactual receipts: detached Ed25519 signature over canonical output JSON,
// bound to a caller-expected baseline_integrity_hash.
const cfBundleHash = hash("counterfactual-baseline-bundle");
const cfSingleOutput = {
  metadata: { bundle_hash: cfBundleHash, policy_id: "strict-v1" },
  summary: { changed_decisions: 1 },
};
const cfSweepOutput = {
  metadata: { bundle_hash: cfBundleHash },
  results: [
    { metadata: { bundle_hash: cfBundleHash }, policy_id: "strict-v1" },
    { metadata: { bundle_hash: cfBundleHash }, policy_id: "balanced-v1" },
  ],
};
function cfWire(output, baselineHash = cfBundleHash, schema = "franken-verifier/counterfactual-receipt-input/v1") {
  return JSON.stringify({
    schema_version: schema,
    baseline_integrity_hash: baselineHash,
    counterfactual_output: output,
  });
}
const cfSingleSig = sign(null, Buffer.from(canonical(cfSingleOutput)), key).toString("hex");
const cfSweepSig = sign(null, Buffer.from(canonical(cfSweepOutput)), key).toString("hex");
add("counterfactual_signed_single", "counterfactual-receipt", cfWire(cfSingleOutput), "verified", {
  signature_hex: cfSingleSig, cf_mode: "single", cf_count: 1, cf_baseline: cfBundleHash,
});
add("counterfactual_signed_sweep", "counterfactual-receipt", cfWire(cfSweepOutput), "verified", {
  signature_hex: cfSweepSig, cf_mode: "sweep", cf_count: 2, cf_baseline: cfBundleHash,
});
add("counterfactual_foreign_anchor", "counterfactual-receipt", cfWire(cfSweepOutput), "SIGNATURE_INVALID", {
  anchor: foreign, signature_hex: cfSweepSig,
});
add("counterfactual_invalid_signature", "counterfactual-receipt", cfWire(cfSweepOutput), "SIGNATURE_INVALID", {
  signature_hex: "00".repeat(64),
});
add("counterfactual_missing_signature", "counterfactual-receipt", cfWire(cfSweepOutput), "SIGNATURE_MALFORMED");
add("counterfactual_wrong_baseline_hash", "counterfactual-receipt", cfWire(cfSweepOutput, hash("other-bundle")), "INTEGRITY_MISMATCH", {
  signature_hex: cfSweepSig,
});
add("counterfactual_unknown_schema", "counterfactual-receipt", cfWire(cfSingleOutput, cfBundleHash, "franken-verifier/counterfactual-receipt-input/v99"), "EVIDENCE_INVALID", {
  signature_hex: cfSingleSig,
});

// Composed counterfactual verification uses an independently retained incident
// pin and separate exporter/receipt authorities. These synthetic assessments
// bind signed evidence; none claims that this independent verifier ran a guest.
const cfIncidentKey = seedKey(0x75);
const cfIncidentAnchor = publicBytes(cfIncidentKey).toString("hex");
assert.notEqual(cfIncidentAnchor, anchor);
function cfIncidentResult(baseline, policy = baseline.policy_version) {
  const outcomes = baseline.timeline.map((event) => ({
    sequence_number: event.sequence_number, event_type: event.event_type,
    decision: "allow", rationale: "Signed assessment; guest not executed", expected_loss: 0,
  }));
  return {
    scenario_id: `${baseline.incident_id}::${policy}`,
    original_outcomes: outcomes, counterfactual_outcomes: clone(outcomes), divergence_points: [],
    summary_statistics: { total_decisions: outcomes.length, changed_decisions: 0, severity_delta: 0 },
    metadata: {
      bundle_hash: baseline.integrity_hash,
      policy_override_diff: policy === baseline.policy_version ? []
        : [{ field: "policy_name", original: baseline.policy_version, counterfactual: policy }],
      replay_timestamp: baseline.created_at, engine_version: "counterfactual-v1",
      invocation_event_codes: ["COUNTERFACTUAL_REPLAY_STARTED", "COUNTERFACTUAL_REPLAY_COMPLETED"],
    },
  };
}
function addCfIncident(name, expected = "verified", options = {}) {
  const bytes = Buffer.from(options.baselineBytes ?? incidentBytes);
  const baseline = JSON.parse(bytes);
  const result = options.output ?? { mode: "single", ...cfIncidentResult(baseline) };
  options.mutateResult?.(result);
  const signature = sign(null, Buffer.from(canonical(result)), cfIncidentKey).toString("hex");
  const transport = {
    schema_version: "franken-verifier/counterfactual-incident-input/v1",
    baseline_bundle_base64: bytes.toString("base64"), counterfactual_output: result,
  };
  options.mutateTransport?.(transport);
  add(name, "counterfactual-incident", options.encode?.(transport) ?? JSON.stringify(transport), expected, {
    anchor: cfIncidentAnchor, incident_anchor: anchor,
    expected_baseline_integrity_hash: baseline.integrity_hash,
    signature_hex: signature, cf_mode: result.mode ?? "single", cf_count: result.results?.length ?? 1,
    cf_baseline: baseline.integrity_hash, cf_output_hash: hash(canonical(result)), ...options.metadata,
  });
}
addCfIncident("counterfactual_incident_separate_authorities");
addCfIncident("counterfactual_incident_direct_result", "verified", { output: cfIncidentResult(incident, "strict") });
addCfIncident("counterfactual_incident_sweep", "verified", { output: {
  mode: "sweep", parameter: "quarantine_threshold",
  results: [cfIncidentResult(incident, "strict"), cfIncidentResult(incident, "balanced")],
} });
addCfIncident("counterfactual_incident_original_run", "verified", {
  baselineBytes: originalRunBytes, metadata: { incident_anchor: exporterAnchor, run_anchor: runAnchor },
});
addCfIncident("counterfactual_incident_runtime_origin", "verified", {
  baselineBytes: runtimeWire, metadata: { run_anchor: runAnchor, runtime_anchor: runtimeAnchor },
});
addCfIncident("counterfactual_incident_foreign_receipt_authority", "COUNTERFACTUAL_RECEIPT_INVALID", {
  metadata: { anchor: foreign },
});
addCfIncident("counterfactual_incident_foreign_exporter", "COUNTERFACTUAL_BASELINE_INVALID", {
  metadata: { incident_anchor: foreign },
});
addCfIncident("counterfactual_incident_receipt_key_cannot_export", "COUNTERFACTUAL_BASELINE_INVALID", {
  metadata: { incident_anchor: cfIncidentAnchor },
});
addCfIncident("counterfactual_incident_invalid_receipt_signature", "COUNTERFACTUAL_RECEIPT_INVALID", {
  metadata: { signature_hex: "00".repeat(64) },
});
addCfIncident("counterfactual_incident_untrusted_baseline_bytes", "COUNTERFACTUAL_BASELINE_INVALID", {
  baselineBytes: canonical(tampered),
});
addCfIncident("counterfactual_incident_independent_pin", "COUNTERFACTUAL_BASELINE_PIN_MISMATCH", {
  metadata: { expected_baseline_integrity_hash: hash("another independently selected incident") },
});
const substitutedBaseline = clone(incident);
substitutedBaseline.initial_state_snapshot.epoch += 1;
addCfIncident("counterfactual_incident_validly_signed_substitute", "COUNTERFACTUAL_BASELINE_PIN_MISMATCH", {
  baselineBytes: resealIncident(substitutedBaseline),
  metadata: { expected_baseline_integrity_hash: incident.integrity_hash },
});
addCfIncident("counterfactual_incident_signed_foreign_hash", "COUNTERFACTUAL_RECEIPT_INVALID", {
  mutateResult: (result) => { result.metadata.bundle_hash = cfBundleHash; },
});
for (const [name, mutateResult] of [
  ["scenario", (result) => { result.scenario_id = "PRIVATE-substituted-incident::strict"; }],
  ["capture_time", (result) => { result.metadata.replay_timestamp = "2026-11-23T12:00:00Z"; }],
  ["original_policy", (result) => { result.metadata.policy_override_diff = [
    { field: "policy_name", original: "PRIVATE-substituted-policy", counterfactual: "strict" },
  ]; }],
  ["event_order", (result) => { result.original_outcomes.reverse(); }],
  ["event_type", (result) => { result.counterfactual_outcomes[0].event_type = "PRIVATE-invented-event"; }],
  ["omitted_event", (result) => { result.original_outcomes.pop(); }],
  ["invented_event", (result) => { result.counterfactual_outcomes.push(clone(result.counterfactual_outcomes[0])); }],
  ["population_count", (result) => { result.summary_statistics.total_decisions += 1; }],
]) addCfIncident(`counterfactual_incident_signed_${name}`, "COUNTERFACTUAL_CONTEXT_MISMATCH", { mutateResult });
addCfIncident("counterfactual_incident_sweep_member_substitution", "COUNTERFACTUAL_CONTEXT_MISMATCH", {
  output: { mode: "sweep", parameter: "observe_threshold",
    results: [cfIncidentResult(incident), cfIncidentResult(incident, "strict")] },
  mutateResult: (result) => { result.results[1].original_outcomes[0].sequence_number += 1; },
});
for (const [name, metadata, baselineBytes = incidentBytes] of [
  ["run_proof_required", { run_anchor: runAnchor }],
  ["wrong_run_authority", { incident_anchor: exporterAnchor, run_anchor: foreign }, originalRunBytes],
  ["runtime_proof_required", { incident_anchor: exporterAnchor, run_anchor: runAnchor, runtime_anchor: runtimeAnchor }, originalRunBytes],
  ["wrong_runtime_authority", { run_anchor: runAnchor, runtime_anchor: foreign }, runtimeWire],
]) addCfIncident(`counterfactual_incident_${name}`, "COUNTERFACTUAL_BASELINE_INVALID", { metadata, baselineBytes });
addCfIncident("counterfactual_incident_noncanonical_base64", "EVIDENCE_INVALID", {
  mutateTransport: (transport) => { transport.baseline_bundle_base64 += "\n"; },
});
addCfIncident("counterfactual_incident_transport_cannot_select_trust", "EVIDENCE_INVALID", {
  mutateTransport: (transport) => { transport.trusted_incident_key = anchor; },
});
addCfIncident("counterfactual_incident_duplicate_member", "JSON_INVALID", {
  encode: (transport) => JSON.stringify(transport).slice(0, -1) + ',"baseline_bundle_base64":""}',
});


// Authenticate the EXISTING incident-counterfactual-report/v2 promotion
// protocol. Independent Node crypto signs the same three receipt wire formats;
// these synthetic assessments establish protocol conformance, not guest work.
const promotionKey = seedKey(0x76);
const promotionAnchor = publicBytes(promotionKey).toString("hex");
const promotionOperator = "operator://independent-counterfactual-fixture";
const promotionTimestamp = "2026-11-23T12:00:00Z";
const promotionRules = [
  "INV-LAB-SIGNED-ROLLOUT", "INV-LAB-ROLLBACK-CONTRACT", "INV-LAB-LOSS-DELTA-POSITIVE",
];
const promotionTrigger = "operator_abort_or_expected_loss_delta_non_positive";
const promotionDigest = (value) => "sha256:" + hash(canonical(value));
function promotionResult(baseline, loss = 40n, policy = "strict") {
  const result = cfIncidentResult(baseline, policy);
  assert(result.original_outcomes.length > 0);
  result.original_outcomes[0].expected_loss = loss + 5n;
  result.counterfactual_outcomes[0].expected_loss = 5n;
  result.counterfactual_outcomes[0].decision = "quarantine";
  result.divergence_points = [{
    sequence_number: result.original_outcomes[0].sequence_number,
    original_decision: "allow", counterfactual_decision: "quarantine",
    original_rationale: result.original_outcomes[0].rationale,
    counterfactual_rationale: result.counterfactual_outcomes[0].rationale,
    impact_estimate: "high",
  }];
  result.summary_statistics.changed_decisions = 1;
  result.summary_statistics.severity_delta = -loss;
  return result;
}
function sealPromotionReceipt(receipt, signingKey = promotionKey) {
  const unsigned = clone(receipt);
  delete unsigned.signer_key_id;
  delete unsigned.chain_hash;
  delete unsigned.signature;
  const payload = Buffer.from(canonical(unsigned));
  const prior = unsigned.previous_receipt_hash ?? "GENESIS";
  return {
    ...unsigned,
    signer_key_id: hash(Buffer.concat([Buffer.from("artifact_signing_keyid_v1:"), publicBytes(signingKey)])).slice(0, 16),
    chain_hash: hash(Buffer.concat([Buffer.from("decision_receipt_chain_v1:"), lp(prior), u64(payload.length), payload])),
    signature: sign(null, payload, signingKey).toString("base64"),
  };
}
function promotionReceipt(action, report, outputHash, expectedLossDelta, rollbackCommand) {
  const actionName = "incident.counterfactual." + action;
  return sealPromotionReceipt({
    receipt_id: actionName + ":" + outputHash.slice("sha256:".length, "sha256:".length + 16),
    action_name: actionName, actor_identity: promotionOperator, timestamp: report.timestamp,
    signature_version: "ed25519-v1", crypto_suite: "ed25519-v1",
    nonce: ({ rollout: "a", rollback: "b", promote: "c" })[action].repeat(32),
    audience: "franken-node", input_hash: report.counterfactual_digest, output_hash: outputHash,
    decision: "approved",
    rationale: "signed counterfactual promotion contract for policy " + report.policy
      + "; expected_loss_delta=" + expectedLossDelta,
    evidence_refs: report.evidence_refs, policy_rule_chain: promotionRules,
    confidence: 4607182418800017408n, rollback_command: rollbackCommand,
    previous_receipt_hash: null,
  });
}
function promotedReport(baseline, options = {}) {
  const output = options.output ?? {
    mode: "single", ...promotionResult(baseline, options.loss ?? 40n),
  };
  const results = output.results ?? [output];
  const total = results.reduce((n, result) => n + result.summary_statistics.total_decisions, 0);
  const changed = results.reduce((n, result) => n + result.summary_statistics.changed_decisions, 0);
  const severity = results.reduce((n, result) => n + BigInt(result.summary_statistics.severity_delta), 0n);
  const executor = options.executor ?? "synthetic";
  const policy = options.policy ?? "strict";
  const report = {
    schema_version: "franken-node/incident-counterfactual-report/v2",
    timestamp: promotionTimestamp, bundle_id: baseline.bundle_id, incident_id: baseline.incident_id,
    bundle_created_at: baseline.created_at, bundle_integrity_hash: baseline.integrity_hash,
    policy, original_policy: baseline.policy_version, counterfactual_policy: policy, executor,
    evidence_refs: baseline.evidence_refs ?? [], total_decisions: total, changed_decisions: changed,
    severity_delta: severity, decision_deltas: output.divergence_points ?? [],
    counterfactual_digest: "sha256:" + hash("incident-counterfactual-report/v2\nexecutor=" + executor + "\n" + canonical(output)),
    counterfactual: output,
  };
  const mitigationId = baseline.incident_id + ":" + policy + ":" + report.counterfactual_digest.slice(7, 23);
  const rollout = {
    mitigation_id: mitigationId,
    policy_diff: output.metadata?.policy_override_diff
      ?? [{ field: "policy", original: baseline.policy_version, counterfactual: policy }],
    expected_loss_delta: -severity, operator_id: promotionOperator,
    valid_from_epoch_ms: options.validFrom ?? BigInt(Date.parse(promotionTimestamp)) + 1n,
    valid_until_epoch_ms: options.validUntil ?? BigInt(Date.parse(promotionTimestamp)) + 86_400_001n,
  };
  const rollback = {
    mitigation_id: mitigationId, rollback_trigger: promotionTrigger,
    rollback_policy: baseline.policy_version, operator_id: promotionOperator,
  };
  const rollbackCommand = "restore_policy_version:" + baseline.policy_version;
  rollout.signature = promotionReceipt("rollout", report, promotionDigest(rollout), -severity, promotionTrigger);
  rollback.signature = promotionReceipt("rollback", report, promotionDigest(rollback), -severity, rollbackCommand);
  report.promotion_contract = { mitigation_id: mitigationId, rollout, rollback };
  report.promotion_contract_digest = promotionDigest(report.promotion_contract);
  report.promotion_signature = promotionReceipt("promote", report, report.promotion_contract_digest, -severity, rollbackCommand);
  return report;
}
// An outer trusted signature cannot repair a foreign or mismatched inner
// contract. Re-signing the outer envelope isolates each nested control.
function resealPromotionEnvelope(report) {
  report.promotion_contract_digest = promotionDigest(report.promotion_contract);
  report.promotion_signature.output_hash = report.promotion_contract_digest;
  report.promotion_signature.receipt_id = "incident.counterfactual.promote:" + report.promotion_contract_digest.slice(7, 23);
  report.promotion_signature = sealPromotionReceipt(report.promotion_signature);
}
function addPromotion(name, expected = "verified", options = {}) {
  const baselineBytes = Buffer.from(options.baselineBytes ?? incidentBytes);
  const baseline = JSON.parse(baselineBytes);
  const report = promotedReport(baseline, options);
  options.mutateReport?.(report);
  const reportBytes = Buffer.from(options.encodeReport?.(report) ?? canonical(report));
  const transport = {
    schema_version: "franken-verifier/counterfactual-promotion-input/v1",
    baseline_bundle_base64: baselineBytes.toString("base64"),
    report_base64: reportBytes.toString("base64"),
  };
  options.mutateTransport?.(transport);
  const rollout = report.promotion_contract?.rollout;
  add(name, "counterfactual-promotion", options.encodeTransport?.(transport) ?? JSON.stringify(transport), expected, {
    anchor: promotionAnchor, incident_anchor: anchor,
    expected_baseline_integrity_hash: baseline.integrity_hash,
    cf_mode: report.counterfactual?.mode, cf_count: report.counterfactual?.results?.length ?? 1,
    cf_baseline: baseline.integrity_hash, cf_output_hash: hash(canonical(report.counterfactual)),
    ...(expected === "verified" ? { promotion_expected: {
      baseline_integrity_hash: baseline.integrity_hash, signer_public_key_hex: promotionAnchor,
      operator_id: promotionOperator, report_sha256: hash(reportBytes),
      counterfactual_digest: report.counterfactual_digest,
      counterfactual_output_sha256: hash(canonical(report.counterfactual)),
      promotion_contract_digest: report.promotion_contract_digest,
      mitigation_id: report.promotion_contract.mitigation_id, executor: report.executor,
      mode: report.counterfactual.mode, result_count: report.counterfactual.results?.length ?? 1,
      expected_loss_delta: String(rollout.expected_loss_delta),
      valid_from_epoch_ms: String(rollout.valid_from_epoch_ms),
      valid_until_epoch_ms: String(rollout.valid_until_epoch_ms),
      guest_execution_verified: false, rollout_authorized: false,
    } } : {}),
    ...options.metadata,
  });
}
addPromotion("counterfactual_promotion_synthetic");
addPromotion("counterfactual_promotion_production", "verified", { executor: "production" });
addPromotion("counterfactual_promotion_sweep", "verified", {
  policy: "sweep:quarantine_threshold=70,80",
  output: { mode: "sweep", parameter: "quarantine_threshold",
    results: [promotionResult(incident, 30n), promotionResult(incident, 50n)] },
});
addPromotion("counterfactual_promotion_original_run", "verified", {
  baselineBytes: originalRunBytes, metadata: { incident_anchor: exporterAnchor, run_anchor: runAnchor },
});
addPromotion("counterfactual_promotion_runtime_origin", "verified", {
  baselineBytes: runtimeWire, metadata: { run_anchor: runAnchor, runtime_anchor: runtimeAnchor },
});
addPromotion("counterfactual_promotion_exact_i64_loss", "verified", { loss: 9_223_372_036_854_775_807n });
addPromotion("counterfactual_promotion_exact_i64_window", "verified", {
  validFrom: 9_223_372_036_768_375_807n, validUntil: 9_223_372_036_854_775_807n,
});
addPromotion("counterfactual_promotion_negative_epoch", "verified", { validFrom: -86_400_000n, validUntil: -1n });
addPromotion("counterfactual_promotion_beyond_number_precision", "verified", {
  loss: 9_007_199_254_740_993n, validFrom: 9_007_199_254_740_993n, validUntil: 9_007_199_254_741_993n,
});
addPromotion("counterfactual_promotion_foreign_operator", "COUNTERFACTUAL_PROMOTION_SIGNATURE_INVALID", { metadata: { anchor: foreign } });
addPromotion("counterfactual_promotion_foreign_exporter", "COUNTERFACTUAL_BASELINE_INVALID", { metadata: { incident_anchor: foreign } });
addPromotion("counterfactual_promotion_baseline_pin", "COUNTERFACTUAL_BASELINE_PIN_MISMATCH", {
  metadata: { expected_baseline_integrity_hash: hash("different expected incident") },
});
addPromotion("counterfactual_promotion_signed_other_incident", "COUNTERFACTUAL_BASELINE_PIN_MISMATCH", {
  baselineBytes: resealIncident(clone(substitutedBaseline)),
  metadata: { expected_baseline_integrity_hash: incident.integrity_hash },
});
addPromotion("counterfactual_promotion_tampered_baseline", "COUNTERFACTUAL_BASELINE_INVALID", { baselineBytes: canonical(tampered) });
for (const [name, mutateReport] of [
  ["bundle_id", (report) => { report.bundle_id = "PRIVATE-other-bundle"; }],
  ["incident_id", (report) => { report.incident_id = "PRIVATE-other-incident"; }],
  ["bundle_time", (report) => { report.bundle_created_at = promotionTimestamp; }],
  ["original_policy", (report) => { report.original_policy = "PRIVATE-other-policy"; }],
  ["evidence_population", (report) => { report.evidence_refs = []; }],
  ["total", (report) => { report.total_decisions += 1; }],
  ["changed", (report) => { report.changed_decisions += 1; }],
  ["loss", (report) => { report.severity_delta -= 1n; }],
  ["decision_deltas", (report) => { report.decision_deltas = []; }],
  ["executor", (report) => { report.executor = "production"; }],
  ["policy", (report) => { report.policy = "permissive"; }],
  ["counterfactual_policy", (report) => { report.counterfactual_policy = "permissive"; }],
  ["report_time", (report) => { report.timestamp = "2026-11-23T12:00:01Z"; }],
]) addPromotion("counterfactual_promotion_changed_" + name, "COUNTERFACTUAL_PROMOTION_CONTEXT_MISMATCH", { mutateReport });
for (const which of ["rollout", "rollback", "promotion"]) {
  addPromotion("counterfactual_promotion_bad_" + which + "_signature", "COUNTERFACTUAL_PROMOTION_SIGNATURE_INVALID", {
    mutateReport: (report) => {
      const receipt = which === "promotion" ? report.promotion_signature : report.promotion_contract[which].signature;
      receipt.signature = Buffer.alloc(64).toString("base64");
      if (which !== "promotion") resealPromotionEnvelope(report);
    },
  });
}
for (const [name, mutateReceipt] of [
  ["audience", (receipt) => { receipt.audience = "other-product"; }],
  ["action", (receipt) => { receipt.action_name = "incident.counterfactual.rollback"; }],
  ["actor", (receipt) => { receipt.actor_identity = "operator://other"; }],
  ["output", (receipt) => { receipt.output_hash = "sha256:" + hash("other rollout"); }],
  ["input", (receipt) => { receipt.input_hash = "sha256:" + hash("other simulation"); }],
  ["rules", (receipt) => { receipt.policy_rule_chain = []; }],
  ["rollback_command", (receipt) => { receipt.rollback_command = "PRIVATE-unrelated-action"; }],
  ["chain", (receipt) => { receipt.previous_receipt_hash = "a".repeat(64); }],
]) addPromotion("counterfactual_promotion_resigned_" + name, "COUNTERFACTUAL_PROMOTION_RECEIPT_INVALID", {
  mutateReport: (report) => {
    const receipt = report.promotion_contract.rollout.signature;
    mutateReceipt(receipt);
    report.promotion_contract.rollout.signature = sealPromotionReceipt(receipt);
    resealPromotionEnvelope(report);
  },
});
addPromotion("counterfactual_promotion_foreign_nested_operator", "COUNTERFACTUAL_PROMOTION_SIGNATURE_INVALID", {
  mutateReport: (report) => {
    report.promotion_contract.rollback.signature = sealPromotionReceipt(report.promotion_contract.rollback.signature, seedKey(0x77));
    resealPromotionEnvelope(report);
  },
});
for (const [name, mutateReport] of [
  ["nonpromoted", (report) => { report.promotion_contract = null; report.promotion_contract_digest = null; report.promotion_signature = null; }],
  ["missing_rollout", (report) => { delete report.promotion_contract.rollout.signature; resealPromotionEnvelope(report); }],
  ["missing_rollback", (report) => { delete report.promotion_contract.rollback.signature; resealPromotionEnvelope(report); }],
  ["native_report", (report) => { report.schema_version = "franken-node/incident-native-counterfactual/v1"; }],
  ["unknown_executor", (report) => { report.executor = "native"; }],
  ["unknown_field", (report) => { report.replay_certified = true; }],
]) addPromotion("counterfactual_promotion_" + name, "COUNTERFACTUAL_PROMOTION_REPORT_INVALID", { mutateReport });
for (const [name, validFrom, validUntil] of [
  ["empty_window", 100n, 100n], ["inverted_window", 101n, 100n],
]) addPromotion("counterfactual_promotion_" + name, "COUNTERFACTUAL_PROMOTION_CONTEXT_MISMATCH", { validFrom, validUntil });
addPromotion("counterfactual_promotion_missing_run", "COUNTERFACTUAL_BASELINE_INVALID", { metadata: { run_anchor: runAnchor } });
addPromotion("counterfactual_promotion_wrong_runtime", "COUNTERFACTUAL_BASELINE_INVALID", {
  baselineBytes: runtimeWire, metadata: { run_anchor: runAnchor, runtime_anchor: foreign },
});
addPromotion("counterfactual_promotion_duplicate_report_field", "COUNTERFACTUAL_PROMOTION_REPORT_INVALID", {
  encodeReport: (report) => canonical(report).slice(0, -1) + ',"executor":"production"}',
});
addPromotion("counterfactual_promotion_noncanonical_report_encoding", "EVIDENCE_INVALID", {
  mutateTransport: (transport) => { transport.report_base64 += "\n"; },
});
addPromotion("counterfactual_promotion_unknown_transport_field", "EVIDENCE_INVALID", {
  mutateTransport: (transport) => { transport.trusted_key = promotionAnchor; },
});
addPromotion("counterfactual_promotion_duplicate_transport_field", "JSON_INVALID", {
  encodeTransport: (transport) => JSON.stringify(transport).slice(0, -1) + ',"report_base64":""}',
});

// Native-session receipt and durable-journal protocols are encoded independently
// with Node crypto. These signed fixtures model supervisor observations; they
// do not claim that the test guest ran, that history is complete, or cleanup.
function nativeFixture(epoch = 7n, projectRoot = "/captured/project", capsuleBytes = undefined) {
  const source = capsuleBytes === undefined ? undefined : sourceFacts(
    sourceManifest(capsuleBytes), Buffer.from(ordered(sourceManifest(capsuleBytes))), capsuleBytes);
  const sourceHeader = capsuleBytes === undefined ? undefined
    : JSON.parse(capsuleBytes.subarray(12, 12 + capsuleBytes.readUInt32LE(8)));
  const admission = {
    session_nonce: sessionNonce, product_root_key_id: "ed25519:" + anchor,
    identity_capture_path: "/evidence/session-identity.json", security_epoch: epoch,
    admitted_at: "2026-11-14T12:00:00Z", project_root: projectRoot,
    entrypoint: projectRoot + "/" + (sourceHeader?.entrypoint ?? "main.mjs"), dependency_ids: ["PRIVATE-dependency"],
    configured_node_id: null, fleet_zone_id: null, fleet_policy_sha256: null,
    process_spawn_authority_granted: false, control_scopes: [],
    ...(source === undefined ? {} : { source_capsule: {
      capsule_digest: source.capsule_digest, graph_input_hash: source.capsule.graph_input_hash,
      capsule_bytes: capsuleBytes.length,
    } }),
  };
  const admissionJson = ordered(admission);
  const receipt = {
    schema_version: "franken-node/native-session-admission-receipt/v1",
    session_nonce: sessionNonce, product_root_key_id: admission.product_root_key_id,
    admission_sha256: hash(frame("franken-node/native-session-admission/v1\0", Buffer.from(admissionJson))),
  };
  receipt.signature_hex = sign(null, frame("franken-node/native-session-admission-signature/v1\0",
    Buffer.from(ordered(receipt))), key).toString("hex");
  const bundle = {
    schema_version: `franken-node/native-session-forensics/v${source === undefined ? 1 : 3}`,
    admission_json: admissionJson, admission_receipt: receipt, outcome: null,
    ...(source === undefined ? {} : { source_capsule_base64: capsuleBytes.toString("base64") }),
  };
  const facts = {
    schema_version: bundle.schema_version, scope: "authenticated_supervisor_observations",
    session_nonce: sessionNonce, product_root_key_id: admission.product_root_key_id,
    admission_sha256: receipt.admission_sha256, project_root: admission.project_root,
    entrypoint: admission.entrypoint, security_epoch: epoch.toString(), admitted_at: admission.admitted_at,
    observed_at: null, outcome_kind: "pending", process_observation: null, effect_observation: null,
    containment_empty_observed: null, completed_provider_calls: null, indeterminate_provider_calls: null,
    final_ledger_effect_count: null, failed_effect_count: null, journal_complete: null, durable_journal: null,
    replay_certified: false, quiescence_certified: false, historical_completeness: false,
    ...(source === undefined ? {} : { source_capsule: source.capsule }),
  };
  return { bundle, facts };
}
function nativeOutcome(fixture, outcome, counts = {}) {
  const receipt = fixture.bundle.admission_receipt;
  const payload = {
    schema_version: "franken-node/native-session-outcome-receipt/v1",
    session_nonce: receipt.session_nonce, product_root_key_id: receipt.product_root_key_id,
    admission_sha256: receipt.admission_sha256, outcome,
  };
  const payloadJson = ordered(payload);
  fixture.bundle.outcome = { payload_json: payloadJson,
    signature_hex: sign(null, frame("franken-node/native-session-outcome-signature/v1\0",
      Buffer.from(payloadJson)), key).toString("hex") };
  Object.assign(fixture.facts, { observed_at: outcome.observed_at, outcome_kind: outcome.kind,
    process_observation: outcome.process, effect_observation: outcome.effects.kind,
    containment_empty_observed: outcome.containment_empty_observed, ...counts });
  return fixture;
}
const nativeWal = (sequence, state) => ({ sequence, effect_kind: "fs.readFile",
  request_hash: "sha256:" + String(sequence + 1).repeat(64), state });
function nativeInterrupted(complete = true) {
  const evidence = {
    schema_version: "franken-node/native-effect-interruption-evidence/v1",
    session_nonce: sessionNonce, terminal_state: "worker_exit_indeterminate", replay_certified: false,
    journal_complete: complete, journal_event_cap: 2048,
    completed_effect_count: complete ? 1 : 0, interrupted_effect_count: 1,
    entries: complete ? [nativeWal(0, "provider_returned"), nativeWal(1, "interrupted_indeterminate")]
      : [nativeWal(0, "interrupted_indeterminate")],
  };
  if (!complete) evidence.protocol_error = "PRIVATE-response-drain-failed";
  return { observed_at: "2026-11-14T12:00:01Z", kind: "interrupted", process: "worker_reaped",
    containment_empty_observed: false, effects: { kind: "interrupted", evidence } };
}
function nativeJournal(fixture, events, torn = false) {
  const receipt = fixture.bundle.admission_receipt;
  const journalEvents = [{ kind: "header", scope: "host_io_provider_calls",
    event_cap: 2048, byte_cap: 4 * 1024 * 1024 }, ...events];
  let previous = "0".repeat(64), admitted = 0, returned = 0;
  const records = journalEvents.map((event, index) => {
    const payloadJson = ordered({
      schema_version: "franken-node/native-effect-journal-record/v1",
      session_nonce: receipt.session_nonce, product_root_key_id: receipt.product_root_key_id,
      admission_sha256: receipt.admission_sha256, event_index: index,
      previous_record_sha256: previous, event,
    });
    const raw = ordered({ payload_json: payloadJson,
      signature_hex: sign(null, frame("franken-node/native-effect-journal-signature/v1\0",
        Buffer.from(payloadJson)), key).toString("hex") });
    previous = hash(frame("franken-node/native-effect-journal-record/v1\0", Buffer.from(raw)));
    if (event.kind === "admitted") admitted += 1;
    if (event.kind === "provider_returned") returned += 1;
    return raw + "\n";
  });
  fixture.bundle.schema_version = Object.hasOwn(fixture.bundle, "source_capsule_base64")
    ? "franken-node/native-session-forensics/v3" : "franken-node/native-session-forensics/v2";
  fixture.bundle.journal_jsonl = records.join("") + (torn ? '{"payload_json":"torn' : "");
  fixture.facts.schema_version = fixture.bundle.schema_version;
  fixture.facts.durable_journal = {
    schema_version: "franken-node/native-effect-journal-record/v1", scope: "host_io_provider_calls",
    session_nonce: receipt.session_nonce, product_root_key_id: receipt.product_root_key_id,
    admission_sha256: receipt.admission_sha256, record_count: records.length, event_count: events.length,
    admitted_provider_calls: admitted, returned_provider_calls: returned,
    indeterminate_provider_calls: admitted - returned, head_record_sha256: previous,
    trailing_partial_record: torn, replay_certified: false, quiescence_certified: false,
    historical_completeness: false,
  };
  return fixture;
}
const nativeAdmit = (sequence) => ({ kind: "admitted", sequence, effect_kind: "fs.readFile",
  request_hash: nativeWal(sequence, "interrupted_indeterminate").request_hash });
const nativeReturn = (sequence) => ({ kind: "provider_returned", sequence });
function addNative(name, fixture, expected = "verified", options = {}) {
  add(name, "native-session-forensics", ordered(fixture.bundle), expected,
    { native_facts: fixture.facts, ...options });
}
const nativePending = nativeFixture(18_446_744_073_709_551_615n);
addNative("native_pending_max_epoch", nativePending);
addNative("native_pending_zero_epoch", nativeFixture(0n));
addNative("native_pending_long_path", nativeFixture(7n, "/captured/" + "p".repeat(5000)));
const nativeComplete = nativeOutcome(nativeFixture(), nativeInterrupted(), {
  completed_provider_calls: 1, indeterminate_provider_calls: 1, journal_complete: true,
});
addNative("native_interrupted_complete", nativeComplete);
const nativeDurable = nativeJournal(clone(nativeComplete),
  [nativeAdmit(0), nativeReturn(0), nativeAdmit(1)]);
addNative("native_v2_interrupted_complete", nativeDurable);
const nativeIncomplete = nativeOutcome(nativeFixture(), nativeInterrupted(false), {
  completed_provider_calls: 0, indeterminate_provider_calls: 1, journal_complete: false,
});
nativeJournal(nativeIncomplete, [nativeAdmit(0), nativeReturn(0), nativeAdmit(1), nativeReturn(1)]);
addNative("native_v2_incomplete_outcome_later_journal", nativeIncomplete);
const panicMessage = "PRIVATE-native-panic";
const nativePanicOutcome = { observed_at: "2026-11-14T12:00:01Z", kind: "panicked",
  process: "worker_reaped", containment_empty_observed: true, effects: { kind: "unknown" },
  panic_evidence: { panic_message: panicMessage, panic_message_bytes: Buffer.byteLength(panicMessage),
    panic_message_sha256: hash(panicMessage), panic_message_truncated: false, cleanup_successful: true,
    host_effect_wal: [nativeWal(0, "provider_returned")] } };
const nativePanic = nativeOutcome(nativeFixture(), nativePanicOutcome, {
  completed_provider_calls: 1, indeterminate_provider_calls: 0, journal_complete: true,
});
addNative("native_panic_retained", nativePanic);
addNative("native_panic_no_effects", nativeOutcome(nativeFixture(), {
  observed_at: "2026-11-14T12:00:01Z", kind: "panicked", process: "worker_reaped",
  containment_empty_observed: true, effects: { kind: "no_admitted_host_effects" },
}, { completed_provider_calls: 0, indeterminate_provider_calls: 0 }));
for (const kind of ["completed", "execution_failed", "control_stopped"]) {
  addNative("native_" + kind + "_final_ledger", nativeOutcome(nativeFixture(), {
    observed_at: "2026-11-14T12:00:01Z", kind, process: "worker_reaped",
    containment_empty_observed: true, effects: { kind: "final_ledger_observed", effect_count: 3,
      allowed_count: 2, denied_count: 0, failed_count: 1, chain_head_hash: "sha256:" + "a".repeat(64),
      ledger_sha256: "b".repeat(64) },
  }, { final_ledger_effect_count: 3, failed_effect_count: 1 }));
}
addNative("native_telemetry_failed_unknown", nativeOutcome(nativeFixture(), {
  observed_at: "2026-11-14T12:00:01Z", kind: "telemetry_failed", process: "worker_reaped",
  containment_empty_observed: false, effects: { kind: "unknown" },
}));
addNative("native_supervision_not_spawned", nativeOutcome(nativeFixture(), {
  observed_at: "2026-11-14T12:00:01Z", kind: "supervision_incomplete", process: "not_spawned",
  containment_empty_observed: false, effects: { kind: "not_started" },
}));
addNative("native_v2_pending_torn_journal", nativeJournal(nativeFixture(), [nativeAdmit(0)], true));
addNative("native_v2_header_only_pending", nativeJournal(nativeFixture(), []));
for (const [index, fixture] of sourceFixtures.vectors.entries()) {
  addNative(`native_v3_source_fixture_${index}`, nativeFixture(7n, "/removed/project",
    Buffer.from(fixture.module_sources.capsule_base64, "base64")));
}
const nativeSourcePending = nativeFixture(7n, "/removed/project", sourceBytes);
const nativeSourceInterrupted = nativeJournal(nativeOutcome(
  nativeFixture(7n, "/removed/project", sourceBytes), nativeInterrupted(), {
    completed_provider_calls: 1, indeterminate_provider_calls: 1, journal_complete: true,
  }), [nativeAdmit(0), nativeReturn(0), nativeAdmit(1)], true);
addNative("native_v3_source_with_interrupted_journal", nativeSourceInterrupted);
addNative("native_v3_source_pending_header_only", nativeJournal(clone(nativeSourcePending), []));
addNative("native_foreign_anchor", nativePending, "SIGNER_UNTRUSTED", { anchor: foreign });
function mutateNative(name, fixture, mutate, expected) {
  const changed = clone(fixture);
  mutate(changed.bundle);
  addNative(name, changed, expected);
}
mutateNative("native_tampered_admission", nativePending,
  (bundle) => { bundle.admission_json = bundle.admission_json.replace("/captured/project/main.mjs", "/captured/project/other.mjs"); },
  "INTEGRITY_MISMATCH");
mutateNative("native_invalid_admission_signature", nativePending,
  (bundle) => { bundle.admission_receipt.signature_hex = "00".repeat(64); }, "SIGNATURE_INVALID");
mutateNative("native_invalid_outcome_signature", nativeComplete,
  (bundle) => { bundle.outcome.signature_hex = "00".repeat(64); }, "SIGNATURE_INVALID");
mutateNative("native_v3_source_bytes_tampered", nativeSourcePending, (bundle) => {
  const bytes = Buffer.from(bundle.source_capsule_base64, "base64");
  bytes[bytes.length - 1] ^= 1;
  bundle.source_capsule_base64 = bytes.toString("base64");
}, "SOURCE_CAPSULE_INVALID");
mutateNative("native_v3_source_missing", nativeSourcePending,
  (bundle) => { delete bundle.source_capsule_base64; }, "SCHEMA_UNSUPPORTED");
mutateNative("native_v3_source_downgrade_and_strip", nativeSourcePending, (bundle) => {
  bundle.schema_version = "franken-node/native-session-forensics/v1";
  delete bundle.source_capsule_base64;
}, "SOURCE_CAPSULE_INVALID");
mutateNative("native_v3_source_downgrade_keeps_body", nativeSourcePending,
  (bundle) => { bundle.schema_version = "franken-node/native-session-forensics/v1"; }, "SCHEMA_UNSUPPORTED");
mutateNative("native_v3_source_null", nativeSourcePending,
  (bundle) => { bundle.source_capsule_base64 = null; }, "JSON_INVALID");
mutateNative("native_v3_source_noncanonical_base64", nativeSourcePending,
  (bundle) => { bundle.source_capsule_base64 += "\n"; }, "SOURCE_CAPSULE_INVALID");
mutateNative("native_v3_source_other_signed_session_journal", nativeSourceInterrupted,
  (bundle) => { bundle.journal_jsonl = nativeDurable.bundle.journal_jsonl; }, "IDENTITY_INVALID");
function resignNativeAdmission(fixture, mutate) {
  const admission = JSON.parse(fixture.bundle.admission_json);
  mutate(admission);
  fixture.bundle.admission_json = ordered(admission);
  const receipt = fixture.bundle.admission_receipt;
  receipt.admission_sha256 = hash(frame("franken-node/native-session-admission/v1\0",
    Buffer.from(fixture.bundle.admission_json)));
  const payload = { schema_version: receipt.schema_version, session_nonce: receipt.session_nonce,
    product_root_key_id: receipt.product_root_key_id, admission_sha256: receipt.admission_sha256 };
  receipt.signature_hex = sign(null, frame("franken-node/native-session-admission-signature/v1\0",
    Buffer.from(ordered(payload))), key).toString("hex");
  return fixture;
}
for (const [name, mutate] of [
  ["digest", (admission) => { admission.source_capsule.capsule_digest = "sha256:" + "0".repeat(64); }],
  ["graph", (admission) => { admission.source_capsule.graph_input_hash = "sha256:" + "0".repeat(64); }],
  ["length", (admission) => { admission.source_capsule.capsule_bytes += 1; }],
  ["entry", (admission) => { admission.entrypoint = "/removed/project/other.mjs"; }],
  ["missing_binding", (admission) => { delete admission.source_capsule; }],
]) {
  addNative(`native_v3_source_signed_wrong_${name}`,
    resignNativeAdmission(clone(nativeSourcePending), mutate), "SOURCE_CAPSULE_INVALID");
}
addNative("native_v3_source_signed_null_binding", resignNativeAdmission(clone(nativeSourcePending),
  (admission) => { admission.source_capsule = null; }), "JSON_INVALID");
mutateNative("native_missing_outcome_field", nativePending,
  (bundle) => { delete bundle.outcome; }, "JSON_INVALID");
mutateNative("native_unknown_transport_field", nativePending,
  (bundle) => { bundle.execution_authorized = true; }, "JSON_INVALID");
mutateNative("native_duplicate_admission_member", nativePending,
  (bundle) => { bundle.admission_json = bundle.admission_json.slice(0, -1) + ',"security_epoch":7}'; }, "JSON_INVALID");
mutateNative("native_v2_missing_journal", nativeDurable,
  (bundle) => { delete bundle.journal_jsonl; }, "SCHEMA_UNSUPPORTED");
mutateNative("native_v1_cannot_attach_journal", nativeDurable,
  (bundle) => { bundle.schema_version = "franken-node/native-session-forensics/v1"; }, "SCHEMA_UNSUPPORTED");
mutateNative("native_journal_null_is_not_absent", nativeDurable,
  (bundle) => { bundle.journal_jsonl = null; }, "JSON_INVALID");
mutateNative("native_outcome_bound_to_another_session", nativeComplete,
  (bundle) => { bundle.outcome.payload_json = bundle.outcome.payload_json.replace(sessionNonce, "0199abcd-1234-7000-8000-123456789abd"); },
  "IDENTITY_INVALID");
const nativeBadCounts = nativeInterrupted();
nativeBadCounts.effects.evidence.completed_effect_count = 99;
addNative("native_signed_impossible_counts", nativeOutcome(nativeFixture(), nativeBadCounts), "OBSERVATION_INVALID");
const nativeBadPanic = clone(nativePanicOutcome);
nativeBadPanic.panic_evidence.panic_message_sha256 = "0".repeat(64);
addNative("native_signed_bad_panic_digest", nativeOutcome(nativeFixture(), nativeBadPanic), "OBSERVATION_INVALID");
const nativeNullPanic = clone(nativePanicOutcome);
nativeNullPanic.panic_evidence = null;
addNative("native_signed_null_panic", nativeOutcome(nativeFixture(), nativeNullPanic), "JSON_INVALID");
mutateNative("native_journal_terminated_corruption", nativeDurable,
  (bundle) => { bundle.journal_jsonl += '{"broken":true}\n'; }, "JSON_INVALID");
mutateNative("native_journal_invalid_signature", nativeDurable, (bundle) => {
  const lines = bundle.journal_jsonl.trimEnd().split("\n");
  const last = JSON.parse(lines.at(-1));
  last.signature_hex = "00".repeat(64);
  lines[lines.length - 1] = ordered(last);
  bundle.journal_jsonl = lines.join("\n") + "\n";
}, "SIGNATURE_INVALID");
mutateNative("native_journal_omitted_middle_record", nativeDurable, (bundle) => {
  const lines = bundle.journal_jsonl.trimEnd().split("\n");
  lines.splice(1, 1);
  bundle.journal_jsonl = lines.join("\n") + "\n";
}, "JOURNAL_INVALID");
addNative("native_journal_return_without_admission", nativeJournal(nativeFixture(), [nativeReturn(0)]), "JOURNAL_INVALID");
const nativeContradiction = nativeOutcome(nativeFixture(), nativeInterrupted(false), {
  completed_provider_calls: 0, indeterminate_provider_calls: 1, journal_complete: true,
});
const contradictoryOutcome = nativeInterrupted(false);
contradictoryOutcome.effects.evidence.journal_complete = true;
delete contradictoryOutcome.effects.evidence.protocol_error;
nativeOutcome(nativeContradiction, contradictoryOutcome, {
  completed_provider_calls: 0, indeterminate_provider_calls: 1, journal_complete: true,
});
nativeJournal(nativeContradiction, [nativeAdmit(0), nativeReturn(0)]);
addNative("native_complete_outcome_contradicts_durable_return", nativeContradiction, "JOURNAL_INVALID");

// Public-key session attestations, produced independently of the Rust SDK.
// The test signer chooses canonical opaque step tags; the public transcript
// authenticates those statements, without claiming to reconstruct private HMACs.
const sessionDomain = "frankenengine-verifier-sdk:signed-session:v1:";
function sealSession(session) {
  // Rust's TranscriptHashView and SessionStep serialize in declaration order.
  // Do not use sorted canonical JSON for the transcript's hash preimage.
  const payload = {
    schema_version: session.schema_version,
    session_id: session.session_id,
    verifier_identity: session.verifier_identity,
    created_at: session.created_at,
    final_verdict: session.final_verdict,
    steps: session.steps.map((step) => ({
      step_index: step.step_index,
      operation: step.operation,
      verdict: step.verdict,
      artifact_binding_hash: step.artifact_binding_hash,
      timestamp: step.timestamp,
      step_signature: step.step_signature,
    })),
    signer_public_key_hex: session.signer_public_key_hex,
  };
  session.transcript_hash = hash(Buffer.concat([
    Buffer.from("frankenengine-verifier-sdk:canonical-hash:v1:"),
    lp(sessionDomain), lp(JSON.stringify(payload)),
  ]));
  session.ed25519_signature_hex = sign(null,
    Buffer.concat([lp(sessionDomain), lp(session.transcript_hash)]), key).toString("hex");
  return session;
}
function sessionFixture(verdict) {
  const steps = verdict === "inconclusive" ? [] : ["pass", verdict].map((stepVerdict, index) => ({
    step_index: index,
    operation: "trust_state",
    verdict: stepVerdict,
    artifact_binding_hash: hash(Buffer.from("session-test-artifact-" + index)),
    timestamp: "2026-11-16T00:00:01Z",
    step_signature: hash(Buffer.from("opaque-test-attestation-tag-" + index)),
  }));
  return sealSession({
    schema_version: "vsdk-signed-session-v1.0",
    session_id: "independent-session-" + verdict,
    verifier_identity: "verifier://independent-auditor",
    created_at: "2026-11-16T00:00:00.123456789Z",
    final_verdict: verdict,
    steps,
    signer_public_key_hex: anchor,
  });
}
function sessionFacts(session) {
  return {
    session_id: session.session_id, verifier_identity: session.verifier_identity,
    created_at: session.created_at, final_verdict: session.final_verdict,
    step_count: session.steps.length, transcript_hash: session.transcript_hash,
    signer_public_key_hex: anchor,
  };
}
for (const verdict of ["pass", "fail", "inconclusive"]) {
  const transcript = sessionFixture(verdict);
  add("signed_session_" + verdict, "signed-session", JSON.stringify(transcript),
    "verified", { session_facts: sessionFacts(transcript) });
}
const sessionPass = sessionFixture("pass");
add("signed_session_reordered_json", "signed-session", canonical(sessionPass),
  "verified", { session_facts: sessionFacts(sessionPass) });
add("signed_session_foreign_anchor", "signed-session", JSON.stringify(sessionPass),
  "SIGNER_UNTRUSTED", { anchor: foreign });
const sessionForged = clone(sessionPass);
sessionForged.ed25519_signature_hex = "00".repeat(64);
add("signed_session_invalid_signature", "signed-session", JSON.stringify(sessionForged), "SIGNATURE_INVALID");
const sessionShortSignature = clone(sessionPass);
sessionShortSignature.ed25519_signature_hex = "00".repeat(63);
add("signed_session_short_signature", "signed-session", JSON.stringify(sessionShortSignature), "SIGNATURE_MALFORMED");
const sessionUpperSignature = clone(sessionPass);
sessionUpperSignature.ed25519_signature_hex = sessionPass.ed25519_signature_hex.toUpperCase();
assert.notEqual(sessionUpperSignature.ed25519_signature_hex, sessionPass.ed25519_signature_hex);
add("signed_session_uppercase_signature", "signed-session", JSON.stringify(sessionUpperSignature), "SIGNATURE_MALFORMED");
const sessionSpliced = clone(sessionPass);
sessionSpliced.steps[1] = sessionFixture("fail").steps[1];
add("signed_session_spliced_step", "signed-session", JSON.stringify(sessionSpliced), "EVIDENCE_INVALID");
const sessionRehashed = clone(sessionPass);
sessionRehashed.steps[0].artifact_binding_hash = "00".repeat(32);
sealSession(sessionRehashed);
sessionRehashed.ed25519_signature_hex = sessionPass.ed25519_signature_hex;
add("signed_session_rehashed_without_resigning", "signed-session", JSON.stringify(sessionRehashed), "SIGNATURE_INVALID");
const sessionTruncated = clone(sessionPass);
sessionTruncated.steps.pop();
add("signed_session_truncated", "signed-session", JSON.stringify(sessionTruncated), "EVIDENCE_INVALID");
const sessionWrongHash = clone(sessionPass);
sessionWrongHash.transcript_hash = "00".repeat(32);
add("signed_session_wrong_hash", "signed-session", JSON.stringify(sessionWrongHash), "EVIDENCE_INVALID");
const sessionUnknown = clone(sessionPass);
sessionUnknown.execution_authorized = true;
add("signed_session_unsigned_claim", "signed-session", JSON.stringify(sessionUnknown), "EVIDENCE_INVALID");
const sessionStepUnknown = clone(sessionPass);
sessionStepUnknown.steps[0].private_evidence = "PRIVATE-SESSION-UNSIGNED";
add("signed_session_unsigned_step_claim", "signed-session", JSON.stringify(sessionStepUnknown), "EVIDENCE_INVALID");
for (const [name, mutate] of [
  ["signed_session_signed_wrong_schema", (value) => { value.schema_version = "vsdk-signed-session-v0.0"; }],
  ["signed_session_signed_reordered_steps", (value) => { value.steps.reverse(); }],
  ["signed_session_signed_bad_identity", (value) => { value.verifier_identity = "internal://self"; }],
  ["signed_session_signed_long_identity", (value) => { value.verifier_identity = "verifier://" + "a".repeat(256); }],
  ["signed_session_signed_long_id", (value) => { value.session_id = "a".repeat(256); }],
  ["signed_session_signed_excessive_steps", (value) => {
    value.steps = Array.from({ length: 1025 }, (_, index) => ({ ...value.steps[0], step_index: index }));
  }],
  ["signed_session_signed_bad_time", (value) => { value.created_at = "2026-02-30T00:00:00Z"; }],
  ["signed_session_signed_noncanonical_tag", (value) => { value.steps[0].step_signature = "A".repeat(64); }],
  ["signed_session_signed_contradictory_verdict", (value) => { value.final_verdict = "inconclusive"; }],
  ["signed_session_signed_empty_pass", (value) => { value.steps = []; }],
]) {
  const candidate = clone(sessionPass);
  mutate(candidate);
  add(name, "signed-session", JSON.stringify(sealSession(candidate)), "EVIDENCE_INVALID");
}
const sessionCompact = JSON.stringify(sessionPass);
add("signed_session_duplicate_member", "signed-session",
  sessionCompact.replace('"session_id":', '"session_id":"duplicate","session_id":'), "JSON_INVALID");
add("signed_session_escaped_duplicate", "signed-session",
  sessionCompact.replace('"session_id":', '"session\\u005fid":"duplicate","session_id":'), "JSON_INVALID");
add("signed_session_duplicate_step", "signed-session",
  sessionCompact.replace('"step_index":0', '"step_index":0,"step_index":0'), "JSON_INVALID");
add("signed_session_trailing_json", "signed-session", sessionCompact + "{}", "JSON_INVALID");

// LTV policy is an independent authority input. These fixtures implement the
// public length-prefixed hashes and Ed25519 messages directly; neither the
// producer nor the Rust evidence builder participates in constructing them.
const ltvWitnessKeys = [seedKey(0x71), seedKey(0x72)];
const ltvDigest = (domain, ...parts) => hash(Buffer.concat([Buffer.from(domain), ...parts]));
const ltvRootBytes = (root) => Buffer.concat([u64(root.tree_size), lp(root.root_hash)]);
function ltvFixture({ claimed = 1000n, observed = 1700n, asOf = 1900n,
  compromised = 2100n, suite = "ed25519-v1" } = {}) {
  const artifact = {
    artifact_id: "independent-ltv-artifact", artifact_hash: hash(Buffer.from("retained artifact bytes")),
    crypto_suite: suite, claimed_at_unix_seconds: claimed,
  };
  artifact.marker_hash = ltvDigest("frankenengine-verifier-sdk:ltv-artifact-marker:v1:",
    lp(artifact.artifact_id), lp(artifact.artifact_hash), lp(suite), u64(claimed));
  const leaf = ltvDigest("mmr_proofs_leaf_v1:", lp(artifact.marker_hash));
  const appended = ltvDigest("mmr_proofs_leaf_v1:", lp(hash(Buffer.from("later log leaf"))));
  const origin = { tree_size: 1, root_hash: leaf };
  const newest = { tree_size: 2, root_hash: ltvDigest("mmr_proofs_node_v1:", lp(leaf), lp(appended)) };
  const prefix = { prefix_size: 1, super_tree_size: 2, prefix_root_hash: leaf,
    super_root_hash: newest.root_hash, prefix_root_from_super: leaf, super_leaf_hashes: [leaf, appended] };
  const link = { schema_version: "mmr-root-reattestation-v1", previous_root: origin,
    attested_root: newest, prefix_proof: prefix, issued_at_unix_seconds: claimed + 1n, crypto_suite: suite };
  link.attestation_hash = ltvDigest("mmr_root_reattestation_v1:", lp(link.schema_version),
    ltvRootBytes(origin), ltvRootBytes(newest), u64(1), u64(2), lp(leaf), lp(newest.root_hash),
    lp(leaf), u64(2), lp(leaf), lp(appended), u64(link.issued_at_unix_seconds), lp(suite));
  const statement = { schema_version: "mmr-root-witness-v1", root: newest,
    observed_at_unix_seconds: observed, witness_group_id: "independent-witnesses",
    witness_policy_id: "independent-policy-2of2" };
  statement.content_hash = ltvDigest("mmr_root_witness_v1:", lp(statement.schema_version),
    ltvRootBytes(newest), u64(observed), lp(statement.witness_group_id), lp(statement.witness_policy_id));
  const witnessMessage = Buffer.concat([Buffer.from("threshold_sig_verify_v2:"),
    lp("mmr-root-witness"), lp("franken-node-root-witness"), lp(statement.content_hash)]);
  const policy = [{ crypto_suite: suite, valid_from_unix_seconds: claimed - 100n,
    compromised_at_unix_seconds: compromised }];
  const threshold = { threshold: 2, total_signers: 2, signer_keys: ltvWitnessKeys.map((signing, index) => ({
    key_id: `independent-${index}`, public_key_hex: publicBytes(signing).toString("hex"),
  })) };
  const trusted = { witness_group_id: statement.witness_group_id, witness_policy_id: statement.witness_policy_id,
    threshold_config: clone(threshold), suite_records: clone(policy) };
  const evidence = { schema_version: "vsdk-ltv-evidence-v1.0", as_of_unix_seconds: asOf,
    artifact, suite_records: clone(policy), inclusion_proof: { leaf_index: 0, tree_size: 1, leaf_hash: leaf, audit_path: [] },
    reattestation_chain: { origin_root: origin, attestations: [link] }, witness_receipt: {
      statement, threshold_config: threshold, witness_artifact: { artifact_id: "mmr-root-witness",
        connector_id: "franken-node-root-witness", content_hash: statement.content_hash,
        signatures: ltvWitnessKeys.map((signing, index) => ({ signer_id: `independent-${index}`,
          key_id: `independent-${index}`, signature_hex: sign(null, witnessMessage, signing).toString("hex") })) },
      trace_id: "independent-ltv-conformance", timestamp: "2026-11-22T00:00:00Z",
    } };
  return { evidence, trusted };
}
function ltvEnvelope({ evidence, trusted }) {
  const policyBytes = Buffer.from(canonical(trusted));
  const message = Buffer.concat([Buffer.from("franken-verifier/ltv-witness-anchor/v1:"), u64(policyBytes.length), policyBytes]);
  return { schema_version: "franken-verifier/ltv-evidence-input/v1", evidence: clone(evidence),
    witness_anchor_base64: policyBytes.toString("base64"), witness_anchor_signature_hex: sign(null, message, key).toString("hex") };
}
function addLtv(name, envelope, expected = "verified", options = {}) {
  const evidence = envelope.evidence;
  const statement = evidence.witness_receipt.statement;
  const facts = { artifact_id: evidence.artifact.artifact_id, artifact_hash: evidence.artifact.artifact_hash,
    crypto_suite: evidence.artifact.crypto_suite, as_of_unix_seconds: evidence.as_of_unix_seconds.toString(),
    claimed_at_unix_seconds: evidence.artifact.claimed_at_unix_seconds.toString(),
    witness_group_id: statement.witness_group_id, witness_policy_id: statement.witness_policy_id,
    trust_policy_sha256: hash(Buffer.from(envelope.witness_anchor_base64, "base64")),
    reattestation_count: evidence.reattestation_chain.attestations.length,
    hybrid_survived_algo_death: evidence.artifact.crypto_suite.includes("hybrid"), signer_public_key_hex: anchor };
  add(name, "ltv-evidence", canonical(envelope), expected, { ltv_facts: facts, ...options });
}
const ltvGood = ltvEnvelope(ltvFixture());
addLtv("ltv_independent_precompromise", ltvGood);
addLtv("ltv_valid_historical_witness_after_compromise", ltvEnvelope(ltvFixture({ asOf: 2500n })));
addLtv("ltv_lossless_u64_timestamps", ltvEnvelope(ltvFixture({ claimed: 18446744073709551215n,
  observed: 18446744073709551614n, asOf: 18446744073709551615n, compromised: 18446744073709551615n })));
const ltvHybrid = ltvFixture({ suite: "ed25519-pq-hybrid-v1" });
const deadClassical = { crypto_suite: "ed25519-v1", valid_from_unix_seconds: 900n,
  valid_until_unix_seconds: 1200n, compromised_at_unix_seconds: 1600n };
ltvHybrid.trusted.suite_records.push(clone(deadClassical));
ltvHybrid.evidence.suite_records.push(clone(deadClassical));
addLtv("ltv_approved_hybrid_survives_classical_compromise", ltvEnvelope(ltvHybrid));
const ltvCompromised = ltvEnvelope(ltvFixture({ compromised: 1600n }));
addLtv("ltv_trusted_compromise_precedes_witness", ltvCompromised, "LTV_ANTERIORITY_REJECTED");
addLtv("ltv_witness_at_compromise_boundary", ltvEnvelope(ltvFixture({ compromised: 1700n })), "LTV_ANTERIORITY_REJECTED");
for (const [name, mutate] of [
  ["ltv_erased_trusted_compromise", (value) => { delete value.evidence.suite_records[0].compromised_at_unix_seconds; }],
  ["ltv_shifted_trusted_compromise", (value) => { value.evidence.suite_records[0].compromised_at_unix_seconds = 3000n; }],
]) {
  const candidate = clone(ltvCompromised);
  mutate(candidate);
  assert.deepEqual(candidate.evidence.witness_receipt, ltvCompromised.evidence.witness_receipt);
  assert.equal(candidate.witness_anchor_signature_hex, ltvCompromised.witness_anchor_signature_hex);
  addLtv(name, candidate, "LTV_ANTERIORITY_REJECTED");
}
for (const [name, mutate] of [
  ["ltv_changed_policy_valid_from", (value) => { value.evidence.suite_records[0].valid_from_unix_seconds = 0n; }],
  ["ltv_changed_policy_valid_until", (value) => { value.evidence.suite_records[0].valid_until_unix_seconds = 3000n; }],
  ["ltv_empty_candidate_policy", (value) => { value.evidence.suite_records = []; }],
  ["ltv_appended_unapproved_suite", (value) => { value.evidence.suite_records.push(clone(deadClassical)); }],
  ["ltv_below_witness_threshold", (value) => { value.evidence.witness_receipt.witness_artifact.signatures.pop(); }],
  ["ltv_duplicate_witness_signature", (value) => { value.evidence.witness_receipt.witness_artifact.signatures[1] = clone(value.evidence.witness_receipt.witness_artifact.signatures[0]); }],
  ["ltv_forged_witness_signature", (value) => { value.evidence.witness_receipt.witness_artifact.signatures[0].signature_hex = "00".repeat(64); }],
  ["ltv_observation_after_as_of", (value) => { value.evidence.as_of_unix_seconds = 1699n; }],
]) {
  const candidate = clone(ltvGood);
  mutate(candidate);
  addLtv(name, candidate, "LTV_ANTERIORITY_REJECTED");
}
const ltvDropped = ltvEnvelope(ltvHybrid);
ltvDropped.evidence.suite_records.pop();
addLtv("ltv_dropped_trusted_suite_record", ltvDropped, "LTV_ANTERIORITY_REJECTED");
for (const [name, mutate, expected] of [
  ["ltv_legacy_anchor_missing_suite_policy", (value) => { delete value.trusted.suite_records; }, "EVIDENCE_INVALID"],
  ["ltv_unknown_trusted_policy_field", (value) => { value.trusted.suite_records[0].compromised_at_unix_second = 1600n; }, "EVIDENCE_INVALID"],
  ["ltv_malformed_trailing_trusted_interval", (value) => {
    const invalid = { crypto_suite: "another-suite", valid_from_unix_seconds: 900n, valid_until_unix_seconds: 899n };
    value.trusted.suite_records.push(clone(invalid)); value.evidence.suite_records.push(clone(invalid));
  }, "LTV_ANTERIORITY_REJECTED"],
  ["ltv_empty_trusted_policy", (value) => { value.trusted.suite_records = []; value.evidence.suite_records = []; }, "LTV_ANTERIORITY_REJECTED"],
  ["ltv_excessive_trusted_policy", (value) => {
    value.trusted.suite_records = Array.from({ length: 129 }, () => clone(value.trusted.suite_records[0]));
    value.evidence.suite_records = clone(value.trusted.suite_records);
  }, "LTV_ANTERIORITY_REJECTED"],
]) {
  const fixture = ltvFixture();
  mutate(fixture);
  addLtv(name, ltvEnvelope(fixture), expected);
}
const ltvUnsignedPolicy = clone(ltvGood);
const changedAuthority = ltvFixture().trusted;
delete changedAuthority.suite_records[0].compromised_at_unix_seconds;
ltvUnsignedPolicy.witness_anchor_base64 = Buffer.from(canonical(changedAuthority)).toString("base64");
addLtv("ltv_changed_anchor_without_authority_signature", ltvUnsignedPolicy, "SIGNATURE_INVALID");
addLtv("ltv_foreign_policy_authority", ltvGood, "SIGNATURE_INVALID", { anchor: foreign });

// The two supervisor signatures in this fixture were produced independently by
// Python cryptography. Keep those original bytes for the HTTP and CLI controls;
// Node signs only adversarial changes and exact-u64 protocol boundary vectors.
const fleetFixture = JSON.parse(readFileSync(fleetObservationsPath, "utf8"));
assert.equal(fleetFixture.live_execution_performed, false);
const fleetPolicy = fleetFixture.policy;
const fleetResponse = fleetFixture.http_response;
const fleetKeys = [seedKey(41), seedKey(42)];
for (let index = 0; index < fleetKeys.length; index += 1) {
  assert.equal(publicBytes(fleetKeys[index]).toString("hex"), fleetPolicy.participants[index].supervisor_public_key_hex);
}
function fleetPayload(domain, value) {
  const bytes = Buffer.from(canonical(value));
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([Buffer.from(domain), length, bytes]);
}
function resignFleet(value, index, privateKey = fleetKeys[index]) {
  const drain = value.evidence.nodes[index].native_session_drain;
  const checkpoint = clone(drain);
  delete checkpoint.supervisor_attestation;
  const attestation = drain.supervisor_attestation;
  attestation.checkpoint_sha256 = hash(fleetPayload("franken-node/native-session-drain-checkpoint/v1\0", checkpoint));
  value.certificate.participants[index].checkpoint_sha256 = attestation.checkpoint_sha256;
  const unsigned = clone(attestation);
  delete unsigned.signature_hex;
  attestation.signature_hex = sign(null, fleetPayload("franken-node/native-session-drain-signature/v1\0", unsigned), privateKey).toString("hex");
}
const fleetEncodingControl = clone(fleetResponse);
resignFleet(fleetEncodingControl, 0);
resignFleet(fleetEncodingControl, 1);
assert.deepEqual(fleetEncodingControl, fleetResponse, "independent fleet wire encodings must agree");
function addFleet(name, value, expected = "verified", policy = fleetPolicy, compactPolicy = false) {
  const wire = typeof value === "string" ? value : canonical(value);
  const bytes = Buffer.from(wire);
  const policyBytes = Buffer.from(compactPolicy ? canonical(policy) : `${JSON.stringify(policy, null, 2)}\n`);
  const policyPath = `${name}.policy.json`;
  writeFileSync(join(dirname(output), policyPath), policyBytes);
  const options = { anchor: null, fleet_policy_path: policyPath };
  if (expected === "verified") {
    const total = (field) => value.evidence.nodes.reduce((sum, node) => sum + BigInt(node.native_session_drain[field]), 0n).toString();
    options.fleet_facts = {
      schema_version: "franken-verifier/fleet-quiescence-observations/v1",
      evidence_sha256: hash(bytes),
      trust_policy_sha256: hash(Buffer.from(canonical(policy))),
      trusted_policy_input_sha256: hash(policyBytes),
      evaluation_time: policy.evaluation_time,
      observed_at: value.evidence.observed_at,
      participant_count: policy.participants.length,
      admitted_sessions: total("admitted_sessions"),
      terminal_sessions: total("terminal_sessions"),
      supervisor_signatures_verified: true,
      expected_population_complete: true,
      expected_action_context_matched: true,
      epoch_commit_authenticated: false,
      current_quiescence_proven: false,
    };
  }
  add(name, "fleet-quiescence-observations", bytes, expected, options);
}
addFleet("fleet_independent_http_observations", fleetResponse);
addFleet("fleet_same_policy_different_raw_bytes", fleetResponse, "verified", fleetPolicy, true);
const fleetCli = {
  schema_version: "franken-node/fleet-quiescence-cli/v1",
  command: "fleet.certify-quiescence", ok: true, transport: "http", live_control_plane: true,
  control_plane_url: "https://coordinator.invalid/", evidence: clone(fleetResponse.evidence),
  certificate: clone(fleetResponse.certificate),
};
addFleet("fleet_independent_cli_observations", fleetCli);
const fleetBeforeExpiry = clone(fleetPolicy);
fleetBeforeExpiry.evaluation_time = "2026-11-23T01:00:32.999999999Z";
addFleet("fleet_last_nanosecond_before_signature_expiry", fleetResponse, "verified", fleetBeforeExpiry);
const fleetExpiredPolicy = clone(fleetPolicy);
fleetExpiredPolicy.evaluation_time = "2026-11-23T01:00:33Z";
addFleet("fleet_exact_signature_expiry", fleetResponse, "FLEET_OBSERVATION_STALE", fleetExpiredPolicy);
const fleetFuturePolicy = clone(fleetPolicy);
fleetFuturePolicy.evaluation_time = "2026-11-23T01:00:04Z";
addFleet("fleet_future_observation", fleetResponse, "FLEET_OBSERVATION_STALE", fleetFuturePolicy);
const fleetRedated = clone(fleetResponse);
fleetRedated.evidence.observed_at = fleetExpiredPolicy.evaluation_time;
fleetRedated.certificate.certified_at = fleetExpiredPolicy.evaluation_time;
for (const node of fleetRedated.evidence.nodes) node.last_seen = fleetExpiredPolicy.evaluation_time;
addFleet("fleet_fresh_heartbeats_cannot_renew_old_signatures", fleetRedated, "FLEET_OBSERVATION_STALE", fleetExpiredPolicy);

for (const [name, mutate, expected] of [
  ["fleet_missing_enrolled_node", (value) => { value.evidence.nodes.pop(); value.certificate.participants.pop(); }, "FLEET_POPULATION_MISMATCH"],
  ["fleet_extra_node", (value) => { value.evidence.nodes.push(clone(value.evidence.nodes[0])); }, "FLEET_POPULATION_MISMATCH"],
  ["fleet_duplicated_node", (value) => { value.evidence.nodes[1] = clone(value.evidence.nodes[0]); value.certificate.participants[1] = clone(value.certificate.participants[0]); }, "FLEET_POPULATION_MISMATCH"],
  ["fleet_reordered_population", (value) => { value.evidence.nodes.reverse(); value.certificate.participants.reverse(); }, "FLEET_POPULATION_MISMATCH"],
  ["fleet_uncovered_zone", (value) => { value.evidence.uncovered_zones = ["east"]; }, "FLEET_POPULATION_MISMATCH"],
  ["fleet_wrong_reviewed_actions", (value) => { value.certificate.action_log_checkpoint.actions_sha256 = "99".repeat(32); }, "FLEET_CONTEXT_MISMATCH"],
  ["fleet_wrong_node_actions", (value) => { value.evidence.nodes[0].expected_actions.actions_sha256 = "99".repeat(32); }, "FLEET_CONTEXT_MISMATCH"],
  ["fleet_foreign_hold_owner", (value) => { value.certificate.participants[0].active_hold_ids = ["foreign-hold"]; }, "FLEET_CONTEXT_MISMATCH"],
  ["fleet_wrong_trace", (value) => { value.certificate.trace_id = "another-trace"; }, "FLEET_CONTEXT_MISMATCH"],
  ["fleet_wrong_epoch", (value) => { value.certificate.pre_epoch += 1; value.certificate.committed_epoch += 1; }, "FLEET_CONTEXT_MISMATCH"],
  ["fleet_unsigned_checkpoint_tamper", (value) => { value.evidence.nodes[0].native_session_drain.session_set_sha256 = "99".repeat(32); value.certificate.participants[0].session_set_sha256 = "99".repeat(32); }, "FLEET_OBSERVATION_INVALID"],
  ["fleet_invalid_signature", (value) => { value.evidence.nodes[0].native_session_drain.supervisor_attestation.signature_hex = "00".repeat(64); }, "FLEET_SIGNATURE_INVALID"],
  ["fleet_absent_supervisor_signature", (value) => { value.evidence.nodes[0].native_session_drain.supervisor_attestation = null; }, "FLEET_OBSERVATION_INVALID"],
  ["fleet_unknown_unsigned_claim", (value) => { value.evidence.nodes[0].native_session_drain.extra_claim = true; }, "FLEET_OBSERVATION_INVALID"],
  ["fleet_unsupported_wire_schema", (value) => { value.evidence.schema_version = "franken-node/fleet-native-drain-evidence/v999"; }, "FLEET_SCHEMA_UNSUPPORTED"],
]) {
  const value = clone(fleetResponse);
  mutate(value);
  addFleet(name, value, expected);
}
for (const [name, mutate, expected] of [
  ["fleet_signed_foreign_project", (value) => { value.evidence.nodes[0].native_session_drain.supervisor_attestation.project_root_sha256 = "99".repeat(32); }, "FLEET_SIGNER_UNTRUSTED"],
  ["fleet_signed_cross_node_binding", (value) => { value.evidence.nodes[0].native_session_drain.supervisor_attestation.node_id = "node-b"; }, "FLEET_SIGNER_UNTRUSTED"],
  ["fleet_signed_generation_rollback", (value) => { value.evidence.nodes[0].native_session_drain.supervisor_attestation.generation = 6; value.certificate.participants[0].generation = 6; }, "FLEET_OBSERVATION_INVALID"],
  ["fleet_signed_pending_session", (value) => { value.evidence.nodes[0].native_session_drain.pending_sessions = 1; }, "FLEET_OBSERVATION_INVALID"],
  ["fleet_signed_indeterminate_session", (value) => { value.evidence.nodes[0].native_session_drain.indeterminate_sessions = 1; }, "FLEET_OBSERVATION_INVALID"],
  ["fleet_signed_released_fence", (value) => { value.evidence.nodes[0].native_session_drain.fence_held = false; }, "FLEET_OBSERVATION_INVALID"],
]) {
  const value = clone(fleetResponse);
  mutate(value);
  resignFleet(value, 0);
  addFleet(name, value, expected);
}
const fleetForeignSigner = clone(fleetResponse);
const fleetForeignKey = seedKey(43);
const fleetForeignKeyId = `ed25519:${publicBytes(fleetForeignKey).toString("hex")}`;
fleetForeignSigner.evidence.nodes[0].native_session_drain.supervisor_attestation.product_root_key_id = fleetForeignKeyId;
fleetForeignSigner.certificate.participants[0].supervisor_key_id = fleetForeignKeyId;
resignFleet(fleetForeignSigner, 0, fleetForeignKey);
addFleet("fleet_valid_signature_from_unenrolled_key", fleetForeignSigner, "FLEET_SIGNER_UNTRUSTED");
const fleetForgedCheckpoint = clone(fleetResponse);
fleetForgedCheckpoint.evidence.nodes[0].native_session_drain.session_set_sha256 = "99".repeat(32);
fleetForgedCheckpoint.certificate.participants[0].session_set_sha256 = "99".repeat(32);
resignFleet(fleetForgedCheckpoint, 0);
fleetForgedCheckpoint.evidence.nodes[0].native_session_drain.supervisor_attestation.signature_hex = fleetResponse.evidence.nodes[0].native_session_drain.supervisor_attestation.signature_hex;
addFleet("fleet_rehashed_checkpoint_without_signature", fleetForgedCheckpoint, "FLEET_SIGNATURE_INVALID");
const fleetDuplicate = canonical(fleetResponse).replace('"complete":true', '"complete":false,"complete":true');
assert.notEqual(fleetDuplicate, canonical(fleetResponse));
addFleet("fleet_duplicate_json_member", fleetDuplicate, "FLEET_JSON_INVALID");
const fleetFailedCli = clone(fleetCli);
fleetFailedCli.ok = false;
addFleet("fleet_failed_cli_command", fleetFailedCli, "FLEET_OBSERVATION_INVALID");
const fleetEmptyPolicy = clone(fleetPolicy);
fleetEmptyPolicy.participants = [];
addFleet("fleet_empty_enrollment_policy", fleetResponse, "FLEET_POLICY_INVALID", fleetEmptyPolicy);
const fleetWeakPolicy = clone(fleetPolicy);
fleetWeakPolicy.participants[0].supervisor_public_key_hex = "00".repeat(32);
addFleet("fleet_weak_enrollment_key", fleetResponse, "FLEET_POLICY_INVALID", fleetWeakPolicy);
const fleetLeapSecondPolicy = clone(fleetPolicy);
fleetLeapSecondPolicy.evaluation_time = "2026-11-23T01:00:60Z";
fleetLeapSecondPolicy.max_observation_age_secs = 120;
addFleet("fleet_leap_second_policy", fleetResponse, "FLEET_POLICY_INVALID", fleetLeapSecondPolicy);

function fleetCounts(value, index, count) {
  const drain = value.evidence.nodes[index].native_session_drain;
  drain.admitted_sessions = count;
  drain.terminal_sessions = count;
  value.certificate.participants[index].admitted_sessions = count;
  value.certificate.participants[index].terminal_sessions = count;
  resignFleet(value, index);
}
const fleetMaximum = clone(fleetResponse);
fleetCounts(fleetMaximum, 0, (1n << 64n) - 4n);
addFleet("fleet_exact_u64_maximum_aggregate", fleetMaximum);
const fleetOverflow = clone(fleetResponse);
fleetCounts(fleetOverflow, 0, (1n << 64n) - 1n);
addFleet("fleet_signed_aggregate_overflow", fleetOverflow, "FLEET_COUNT_OVERFLOW");

// Historical epoch commits require two independently anchored coordinator
// signatures over the exact supervisor evidence/certificate manifest. Neither
// a durable-looking envelope nor a prepare authorization proves a commit.
const epochFixture = JSON.parse(readFileSync(fleetEpochCommitPath, "utf8"));
assert.equal(epochFixture.live_execution_performed, false);
assert.deepEqual(epochFixture.policy, fleetPolicy);
const epochResponse = epochFixture.http_response;
const epochTrust = epochFixture.coordinator_trust;
const epochKey = seedKey(43);
assert.equal(publicBytes(epochKey).toString("hex"), epochTrust.coordinator_public_key_hex);
const epochAuthorizationDomain = "franken-node/fleet-epoch-authorization-signature/v1\0";
const epochCommitDomain = "franken-node/fleet-epoch-commit-signature/v1\0";
function resignEpoch(value, privateKey = epochKey) {
  const proof = value.commit_proof;
  proof.statement.evidence_certificate_sha256 = hash(fleetPayload(
    "franken-node/fleet-epoch-quiescence-manifest/v1\0", [value.evidence, value.certificate]));
  for (const field of ["pre_epoch", "committed_epoch", "transition_id", "trace_id"]) {
    proof.statement[field] = value.certificate[field];
  }
  proof.authorization_signature_hex = sign(null, fleetPayload(epochAuthorizationDomain, proof.statement), privateKey).toString("hex");
  proof.commit_signature_hex = sign(null, fleetPayload(epochCommitDomain, proof.statement), privateKey).toString("hex");
}
const epochEncodingControl = clone(epochResponse);
resignEpoch(epochEncodingControl);
assert.deepEqual(epochEncodingControl, epochResponse, "coordinator domain and canonical encodings must agree");
assert.equal(epochResponse.commit_proof.statement.evidence_certificate_sha256, epochFixture.expected.manifest_sha256);
assert.equal(hash(Buffer.from(canonical(epochResponse.commit_proof.statement))), epochFixture.expected.statement_sha256);
function addEpoch(name, value, expected = "verified", policy = fleetPolicy, trust = epochTrust, compactPolicy = false, rawPolicy) {
  const bytes = Buffer.from(typeof value === "string" ? value : canonical(value));
  // Whitespace changes the retained input commitment without rounding u64s.
  const policyBytes = Buffer.from(rawPolicy ?? canonical(policy) + (compactPolicy ? "" : "\n"));
  const policyPath = `${name}.policy.json`;
  writeFileSync(join(dirname(output), policyPath), policyBytes);
  const options = { anchor: null, fleet_policy_path: policyPath,
    coordinator_id: trust.coordinator_id, coordinator_key_hex: trust.coordinator_public_key_hex };
  if (expected === "verified") {
    const total = (field) => value.evidence.nodes.reduce((sum, node) => sum + BigInt(node.native_session_drain[field]), 0n).toString();
    const statement = value.commit_proof.statement;
    options.epoch_facts = {
      schema_version: "franken-verifier/fleet-epoch-commit/v1",
      evidence_sha256: hash(bytes), trust_policy_sha256: hash(Buffer.from(canonical(policy))),
      trusted_policy_input_sha256: hash(policyBytes), evaluation_time: policy.evaluation_time,
      observed_at: value.evidence.observed_at, participant_count: policy.participants.length,
      admitted_sessions: total("admitted_sessions"), terminal_sessions: total("terminal_sessions"),
      supervisor_signatures_verified: true, expected_population_complete: true,
      expected_action_context_matched: true, epoch_commit_authenticated: true,
      current_quiescence_proven: false, coordinator_id: trust.coordinator_id,
      coordinator_key_id: `ed25519:${trust.coordinator_public_key_hex}`,
      committed_epoch: BigInt(statement.committed_epoch).toString(),
      transition_id: statement.transition_id, statement_sha256: hash(Buffer.from(canonical(statement))),
    };
  }
  add(name, "fleet-epoch-commit", bytes, expected, options);
}
addEpoch("epoch_independent_http_commit", epochResponse);
addEpoch("epoch_same_policy_different_raw_bytes", epochResponse, "verified", fleetPolicy, epochTrust, true);
addFleet("fleet_signed_commit_does_not_upgrade_observation_api", epochResponse);
const epochCli = { ...clone(fleetCli), schema_version: "franken-node/fleet-quiescence-cli/v2",
  commit_proof: clone(epochResponse.commit_proof) };
addEpoch("epoch_independent_cli_commit", epochCli);
addEpoch("epoch_durable_export_commit", { ...clone(epochCli), command: "fleet.export-epoch" });
addEpoch("epoch_legacy_http_cannot_upgrade", fleetResponse, "FLEET_EPOCH_PROOF_MISSING");
addEpoch("epoch_legacy_cli_cannot_upgrade", fleetCli, "FLEET_EPOCH_PROOF_MISSING");
addEpoch("epoch_wrong_enrolled_coordinator", epochResponse, "FLEET_COORDINATOR_UNTRUSTED", fleetPolicy,
  { ...epochTrust, coordinator_id: "coordinator-other" });
addEpoch("epoch_wrong_enrolled_key", epochResponse, "FLEET_COORDINATOR_UNTRUSTED", fleetPolicy,
  { ...epochTrust, coordinator_public_key_hex: foreign });
addEpoch("epoch_weak_coordinator_key", epochResponse, "FLEET_COORDINATOR_TRUST_INVALID", fleetPolicy,
  { ...epochTrust, coordinator_public_key_hex: "00".repeat(32) });
for (const [name, mutate, expected] of [
  ["epoch_missing_proof", (value) => { delete value.commit_proof; }, "FLEET_EPOCH_PROOF_MISSING"],
  ["epoch_null_proof", (value) => { value.commit_proof = null; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_authorization_without_commit", (value) => { delete value.commit_proof.commit_signature_hex; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_commit_without_authorization", (value) => { delete value.commit_proof.authorization_signature_hex; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_prepare_signature_is_not_commit", (value) => { value.commit_proof.commit_signature_hex = value.commit_proof.authorization_signature_hex; }, "FLEET_EPOCH_SIGNATURE_INVALID"],
  ["epoch_commit_signature_is_not_prepare", (value) => { value.commit_proof.authorization_signature_hex = value.commit_proof.commit_signature_hex; }, "FLEET_EPOCH_SIGNATURE_INVALID"],
  ["epoch_invalid_commit_signature", (value) => { value.commit_proof.commit_signature_hex = "00".repeat(64); }, "FLEET_EPOCH_SIGNATURE_INVALID"],
  ["epoch_invalid_authorization_signature", (value) => { value.commit_proof.authorization_signature_hex = "00".repeat(64); }, "FLEET_EPOCH_SIGNATURE_INVALID"],
  ["epoch_truncated_commit_signature", (value) => { value.commit_proof.commit_signature_hex = "ab".repeat(63); }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_uppercase_commit_signature", (value) => { value.commit_proof.commit_signature_hex = value.commit_proof.commit_signature_hex.toUpperCase(); }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_unknown_proof_claim", (value) => { value.commit_proof.current_quiescence_proven = true; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_unknown_statement_claim", (value) => { value.commit_proof.statement.execution_authorized = true; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_wrong_proof_schema", (value) => { value.commit_proof.schema_version += "/other"; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_changed_manifest", (value) => { value.commit_proof.statement.evidence_certificate_sha256 = "99".repeat(32); }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_changed_epoch", (value) => { value.commit_proof.statement.committed_epoch += 1; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_changed_transition", (value) => { value.commit_proof.statement.transition_id = "other-transition"; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_changed_trace", (value) => { value.commit_proof.statement.trace_id = "other-trace"; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_changed_evidence", (value) => { value.evidence.nodes[0].reason = "another observation"; }, "FLEET_EPOCH_PROOF_INVALID"],
  ["epoch_reformatted_timestamp_without_signature", (value) => { value.evidence.observed_at = "2026-11-23T01:00:05+00:00"; }, "FLEET_EPOCH_PROOF_INVALID"],
]) {
  const value = clone(epochResponse);
  mutate(value);
  addEpoch(name, value, expected);
}
const epochForeignSigner = clone(epochResponse);
const epochForeignKey = seedKey(44);
epochForeignSigner.commit_proof.statement.coordinator_key_id = `ed25519:${publicBytes(epochForeignKey).toString("hex")}`;
resignEpoch(epochForeignSigner, epochForeignKey);
addEpoch("epoch_self_selected_coordinator_key", epochForeignSigner, "FLEET_COORDINATOR_UNTRUSTED");
const epochDisguisedSigner = clone(epochResponse);
resignEpoch(epochDisguisedSigner, epochForeignKey);
addEpoch("epoch_foreign_signature_disguised_as_enrolled", epochDisguisedSigner, "FLEET_EPOCH_SIGNATURE_INVALID");
for (const [name, mutate, expected] of [
  ["epoch_signed_missing_supervisor", (value) => { value.evidence.nodes.pop(); value.certificate.participants.pop(); }, "FLEET_POPULATION_MISMATCH"],
  ["epoch_coordinator_cannot_replace_supervisor_signature", (value) => { value.evidence.nodes[0].native_session_drain.supervisor_attestation.signature_hex = "00".repeat(64); }, "FLEET_SIGNATURE_INVALID"],
  ["epoch_signed_unreviewed_actions", (value) => { value.certificate.action_log_checkpoint.actions_sha256 = "99".repeat(32); }, "FLEET_CONTEXT_MISMATCH"],
  ["epoch_signed_wrong_trace", (value) => { value.certificate.trace_id = "other-trace"; }, "FLEET_CONTEXT_MISMATCH"],
  ["epoch_signed_skipped_epoch", (value) => { value.certificate.committed_epoch += 1; }, "FLEET_CONTEXT_MISMATCH"],
]) {
  const value = clone(epochResponse);
  mutate(value);
  resignEpoch(value);
  addEpoch(name, value, expected);
}
addEpoch("epoch_commit_does_not_refresh_observations", epochResponse, "FLEET_OBSERVATION_STALE", fleetExpiredPolicy);
const epochMaximum = clone(epochResponse);
const epochMaximumPolicy = clone(fleetPolicy);
epochMaximumPolicy.expected_pre_epoch = (1n << 64n) - 2n;
epochMaximum.certificate.pre_epoch = epochMaximumPolicy.expected_pre_epoch;
epochMaximum.certificate.committed_epoch = (1n << 64n) - 1n;
resignEpoch(epochMaximum);
addEpoch("epoch_exact_u64_maximum_commit", epochMaximum, "verified", epochMaximumPolicy);
const escapedEpochPolicy = canonical(epochMaximumPolicy).replace('"expected_pre_epoch":', '"\\u0065xpected_pre_epoch":');
assert.notEqual(escapedEpochPolicy, canonical(epochMaximumPolicy));
addEpoch("epoch_exact_u64_escaped_policy_key", epochMaximum, "verified", epochMaximumPolicy, epochTrust, false, escapedEpochPolicy);
const epochDecoyPolicy = clone(fleetPolicy);
epochDecoyPolicy.expected_trace_id = 'trace with a quoted "expected_pre_epoch":99999999999999999999 decoy';
const epochDecoy = clone(epochResponse);
epochDecoy.certificate.trace_id = epochDecoyPolicy.expected_trace_id;
resignEpoch(epochDecoy);
addEpoch("epoch_policy_string_cannot_supply_epoch", epochDecoy, "verified", epochDecoyPolicy);
const duplicateEpochPolicy = canonical(fleetPolicy).replace('"expected_pre_epoch":7', '"expected_pre_epoch":7,"\\u0065xpected_pre_epoch":8');
assert.notEqual(duplicateEpochPolicy, canonical(fleetPolicy));
addEpoch("epoch_escaped_duplicate_policy_epoch", epochResponse, "FLEET_JSON_INVALID", fleetPolicy, epochTrust, false, duplicateEpochPolicy);
const missingEpochPolicy = clone(epochDecoyPolicy);
delete missingEpochPolicy.expected_pre_epoch;
addEpoch("epoch_missing_policy_epoch_with_string_decoy", epochResponse, "FLEET_POLICY_INVALID", missingEpochPolicy);
const epochMaximumCounts = clone(epochResponse);
fleetCounts(epochMaximumCounts, 0, (1n << 64n) - 4n);
resignEpoch(epochMaximumCounts);
addEpoch("epoch_exact_u64_maximum_session_count", epochMaximumCounts);
const epochOverflow = clone(epochResponse);
fleetCounts(epochOverflow, 0, (1n << 64n) - 1n);
resignEpoch(epochOverflow);
addEpoch("epoch_signed_session_count_overflow", epochOverflow, "FLEET_COUNT_OVERFLOW");
const epochDuplicate = canonical(epochResponse).replace('"committed_epoch":8', '"committed_epoch":8,"committed_epoch":9');
assert.notEqual(epochDuplicate, canonical(epochResponse));
addEpoch("epoch_duplicate_committed_epoch", epochDuplicate, "FLEET_JSON_INVALID");

writeFileSync(output, JSON.stringify(cases));
console.log(JSON.stringify({ vectors: cases.length, incident_sha256: hash(incidentBytes), capsule_expected_hash: capsule.manifest.expected_output_hash, sdk_integrity: sdk.integrity_hash }));
