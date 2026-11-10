// Independent protocol vectors: Node's crypto and explicit wire encodings.
// This never imports the producer or the Rust SDK. The RFC seed is test-only
// input and is not copied into the verifier distribution/consumer sandbox.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";

const [incidentPath, sdkBundlePath, seedPath, output, originalRunPath, exporterAnchorPath, runAnchorPath] = process.argv.slice(2);
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
writeFileSync(output, JSON.stringify(cases));
console.log(JSON.stringify({ vectors: cases.length, incident_sha256: hash(incidentBytes), capsule_expected_hash: capsule.manifest.expected_output_hash, sdk_integrity: sdk.integrity_hash }));
