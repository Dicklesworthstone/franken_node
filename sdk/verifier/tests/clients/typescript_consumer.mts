import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { verifyArtifact, VerifierError } from "./franken_verifier.mjs";
import type { Verification, EvidenceFormat, PublisherSourceTrustFacts, NativeSessionForensicsFacts, SignedSessionFacts, LtvEvidenceFacts, FleetQuiescenceFacts } from "./franken_verifier.mjs";

type KeyCase = { name: string; input_hex: string; anchor: string; format: Exclude<EvidenceFormat, "fleet-quiescence-observations">;
  signature_hex?: string; run_anchor?: string; runtime_anchor?: string; event_count?: number;
  revocation_anchor?: string; provenance_anchor?: string | null; evaluation_time?: string;
  max_revocation_age_secs?: string; publisher_trust_facts?: PublisherSourceTrustFacts;
  expected_manifest_sha256?: string; expected_source_artifact_sha256?: string; expected_graph_input_hash?: string;
  native_facts?: NativeSessionForensicsFacts;
  session_facts?: SignedSessionFacts;
  ltv_facts?: LtvEvidenceFacts;
  expected: string; artifact_sha256: string };
type FleetCase = { name: string; input_hex: string; anchor: null; format: "fleet-quiescence-observations";
  fleet_policy_path: string; fleet_facts?: FleetQuiescenceFacts; expected: string; artifact_sha256: string };
const allCases: Array<KeyCase | FleetCase> =
  JSON.parse(readFileSync("vectors.json", "utf8"));
const cases = allCases.filter((item): item is KeyCase => item.format !== "fleet-quiescence-observations");
const positive = cases.find((item) => item.name === "genuine_cli_incident")!;
const result: Verification = await verifyArtifact(Buffer.from(positive.input_hex, "hex"), positive.anchor,
  { verifier: resolve("verifier"), format: positive.format });
if (result.format !== "incident-bundle" || result.facts.event_count !== 3
    || result.scope !== "authenticated_recorded_incident"
    || result.artifact_sha256 !== positive.artifact_sha256) throw new Error("TypeScript consumer mismatch");
try {
  await verifyArtifact(Buffer.from(positive.input_hex, "hex"),
    cases.find((item) => item.name === "foreign_anchor")!.anchor,
    { verifier: resolve("verifier") });
  throw new Error("foreign anchor accepted");
} catch (error: unknown) {
  if (!(error instanceof VerifierError) || error.code !== "SIGNER_UNTRUSTED") throw error;
}
const original = cases.find((item) => item.name === "producer_signed_run_origin")!;
const strong: Verification = await verifyArtifact(Buffer.from(original.input_hex, "hex"), original.anchor,
  { verifier: resolve("verifier"), trustedRunPublicKeyHex: original.run_anchor });
if (strong.scope !== "authenticated_run_incident" || strong.format !== "incident-bundle"
    || strong.facts.run_origin.signer_public_key_hex !== original.run_anchor
    || strong.facts.event_count !== original.event_count) throw new Error("TypeScript original-run scope mismatch");
const missingOrigin = cases.find((item) => item.name === "original_run_proof_required")!;
try {
  await verifyArtifact(Buffer.from(missingOrigin.input_hex, "hex"), missingOrigin.anchor,
    { verifier: resolve("verifier"), trustedRunPublicKeyHex: missingOrigin.run_anchor });
  throw new Error("missing original-run proof accepted");
} catch (error: unknown) {
  if (!(error instanceof VerifierError) || error.code !== "RUN_ORIGIN_MISSING") throw error;
}
const runtime = cases.find((item) => item.name === "independently_signed_runtime_origin")!;
const runtimeVerified: Verification = await verifyArtifact(Buffer.from(runtime.input_hex, "hex"), runtime.anchor,
  { verifier: resolve("verifier"), trustedRunPublicKeyHex: runtime.run_anchor, trustedRuntimePublicKeyHex: runtime.runtime_anchor });
if (runtimeVerified.scope !== "authenticated_runtime_incident"
    || runtimeVerified.facts.runtime_origin.product_root_key_id !== `ed25519:${runtime.runtime_anchor}`
    || runtimeVerified.facts.runtime_origin.signed_epoch !== "18446744073709551615") throw new Error("TypeScript runtime-origin mismatch");
for (const name of ["resolution_signed_admission", "resolution_signed_rejection"]) {
  const receipt = cases.find((item) => item.name === name)!;
  const verified = await verifyArtifact(Buffer.from(receipt.input_hex, "hex"), receipt.anchor,
    { verifier: resolve("verifier"), format: "resolution-receipt" });
  if (verified.format !== "resolution-receipt" || verified.scope !== "authenticated_resolution_decision"
      || !verified.facts.module_graph_hash.startsWith("sha256:")) throw new Error("TypeScript resolution scope mismatch");
  if (name === "resolution_signed_admission"
      ? verified.facts.decision !== "admit" || verified.facts.selected_version !== "1.2.3"
      : verified.facts.decision !== "reject" || verified.facts.selected_version !== null) throw new Error("TypeScript resolution decision mismatch");
}
for (const name of ["publisher_source_v1_fixture_2", "publisher_source_v2_fixture_2"]) {
  const source = cases.find((item) => item.name === name)!;
  const verified = await verifyArtifact(Buffer.from(source.input_hex, "hex"), source.anchor,
    { verifier: resolve("verifier"), format: "publisher-source", signatureHex: source.signature_hex });
  if (verified.format !== "publisher-source" || verified.scope !== "authenticated_publisher_source_content"
      || verified.facts.capsule.graph_hash_recomputed !== false || verified.facts.capsule.symlink_count !== 1
      || !verified.facts.artifact_sha256.startsWith("sha256:")) throw new Error("TypeScript publisher source mismatch");
  if (verified.facts.registration_schema === "franken-node/extension-registration-manifest/v1") {
    const absent: null = verified.facts.runtime_authority;
    if (absent !== null) throw new Error("TypeScript v1 source grants authority");
  } else if (verified.facts.runtime_authority.max_instructions !== "18446744073709551615"
      || verified.facts.runtime_authority.max_total_memory_bytes !== "18446744073709551615"
      || verified.facts.runtime_authority.max_heap_objects !== "4294967295") {
    throw new Error("TypeScript publisher ceilings lost precision");
  }
}
for (const name of ["publisher_source_scoped_host_authority", "publisher_source_explicit_empty_host_scopes",
  "publisher_source_unspecified_host_scopes", "publisher_source_process_quota_maximum", "publisher_source_process_quota_zero"]) {
  const source = cases.find((item) => item.name === name)!;
  const verified = await verifyArtifact(Buffer.from(source.input_hex, "hex"), source.anchor,
    { verifier: resolve("verifier"), format: "publisher-source", signatureHex: source.signature_hex });
  if (verified.format !== "publisher-source"
      || verified.facts.registration_schema !== "franken-node/extension-registration-manifest/v2") {
    throw new Error("TypeScript scoped publisher source required");
  }
  const host = verified.facts.runtime_authority.host_io;
  if (host === undefined) throw new Error("TypeScript publisher host restrictions lost");
  if (name === "publisher_source_scoped_host_authority") {
    const maximum: string | undefined = host.max_calls_per_epoch.network_egress;
    assert.equal(maximum, "18446744073709551615");
    assert.equal(host.max_calls_per_epoch.fs_read, "0");
    assert.deepEqual(host.host_ports, ["[2001:db8::1]:443", "api.example.test:443"]);
  } else if (name === "publisher_source_explicit_empty_host_scopes") {
    assert.deepEqual(host, { host_ports: [], env_keys: [], max_calls_per_epoch: {} });
  } else if (name === "publisher_source_unspecified_host_scopes") {
    assert.deepEqual(host, { max_calls_per_epoch: { fs_read: "0" } });
  } else {
    const processCalls: string | undefined = host.max_calls_per_epoch.process_spawn;
    assert.equal(processCalls, name.endsWith("_zero") ? "0" : "18446744073709551615");
    assert.equal(Object.keys(host.max_calls_per_epoch).length, 6);
  }
}
const cfSweep = cases.find((item) => item.name === "counterfactual_signed_sweep")!;
const cfVerified = await verifyArtifact(Buffer.from(cfSweep.input_hex, "hex"), cfSweep.anchor,
  { verifier: resolve("verifier"), format: "counterfactual-receipt", signatureHex: cfSweep.signature_hex });
if (cfVerified.format !== "counterfactual-receipt"
    || cfVerified.scope !== "authenticated_counterfactual_receipt"
    || cfVerified.facts.mode !== "sweep"
    || cfVerified.facts.result_count !== 2) {
  throw new Error("TypeScript counterfactual receipt mismatch");
}
let identityPositive = 0;
let identityNegative = 0;
for (const source of cases.filter((item) => item.format === "publisher-source" && item.expected_manifest_sha256 !== undefined)) {
  try {
    const verified = await verifyArtifact(Buffer.from(source.input_hex, "hex"), source.anchor, {
      verifier: resolve("verifier"), format: "publisher-source", signatureHex: source.signature_hex,
      expectedManifestSha256: source.expected_manifest_sha256,
      expectedSourceArtifactSha256: source.expected_source_artifact_sha256,
      expectedGraphInputHash: source.expected_graph_input_hash,
    });
    if (source.expected !== "verified" || verified.format !== "publisher-source") {
      throw new Error("TypeScript expected publisher release mismatch: " + source.name);
    }
    assert.equal(verified.facts.manifest_sha256, source.expected_manifest_sha256);
    const reconstructed: false = verified.facts.capsule.graph_hash_recomputed;
    assert.equal(reconstructed, false);
    identityPositive += 1;
  } catch (error: unknown) {
    if (source.expected === "verified" || !(error instanceof VerifierError)
        || error.code !== source.expected) throw error;
    identityNegative += 1;
  }
}
if (identityPositive === 0 || identityNegative === 0) throw new Error("publisher identity matrix is missing");
let trustPositive = 0;
let trustNegative = 0;
for (const source of cases.filter((item) => item.format === "publisher-source-trust")) {
  try {
    const verified = await verifyArtifact(Buffer.from(source.input_hex, "hex"), source.anchor, {
      verifier: resolve("verifier"), format: "publisher-source-trust", signatureHex: source.signature_hex,
      trustedRevocationPublicKeyHex: source.revocation_anchor,
      trustedProvenancePublicKeyHex: source.provenance_anchor ?? undefined,
      evaluationTime: source.evaluation_time, maxRevocationAgeSecs: source.max_revocation_age_secs,
      expectedManifestSha256: source.expected_manifest_sha256,
      expectedSourceArtifactSha256: source.expected_source_artifact_sha256,
      expectedGraphInputHash: source.expected_graph_input_hash,
    });
    if (source.expected !== "verified" || verified.format !== "publisher-source-trust"
        || verified.scope !== "authenticated_publisher_source_trust") {
      throw new Error("TypeScript publisher trust scope mismatch: " + source.name);
    }
    assert.deepEqual(verified.facts, source.publisher_trust_facts, source.name);
    const exactWindow: string = verified.facts.max_revocation_age_secs;
    if (exactWindow !== source.max_revocation_age_secs
        || verified.facts.source.capsule.graph_hash_recomputed !== false) {
      throw new Error("TypeScript publisher trust precision mismatch: " + source.name);
    }
    trustPositive += 1;
  } catch (error: unknown) {
    if (source.expected === "verified" || !(error instanceof VerifierError)
        || error.code !== source.expected) throw error;
    trustNegative += 1;
  }
}
if (trustPositive === 0 || trustNegative === 0) throw new Error("publisher trust matrix is missing");
let nativePositive = 0;
let nativeNegative = 0;
for (const observation of cases.filter((item) => item.format === "native-session-forensics")) {
  try {
    const verified = await verifyArtifact(Buffer.from(observation.input_hex, "hex"), observation.anchor,
      { verifier: resolve("verifier"), format: "native-session-forensics" });
    if (observation.expected !== "verified" || verified.format !== "native-session-forensics"
        || verified.scope !== "authenticated_supervisor_observations") throw new Error("native-session scope mismatch");
    assert.deepEqual(verified.facts, observation.native_facts, observation.name);
    const epoch: string = verified.facts.security_epoch;
    const replay: false = verified.facts.replay_certified;
    const cleanup: false = verified.facts.quiescence_certified;
    const history: false = verified.facts.historical_completeness;
    if (epoch.length === 0 || replay || cleanup || history) throw new Error("forensic claim exceeds its scope");
    if (verified.facts.outcome_kind === "pending") {
      const unknown: null = verified.facts.completed_provider_calls;
      const observed: null = verified.facts.observed_at;
      assert.equal(unknown, null);
      assert.equal(observed, null);
    }
    if (verified.facts.schema_version === "franken-node/native-session-forensics/v2") {
      const retained: number = verified.facts.durable_journal.record_count;
      const complete: false = verified.facts.durable_journal.historical_completeness;
      if (retained < 1 || complete) throw new Error("invalid retained prefix");
    } else if (verified.facts.schema_version === "franken-node/native-session-forensics/v1") {
      const absent: null = verified.facts.durable_journal;
      assert.equal(absent, null);
      const noSource: undefined = verified.facts.source_capsule;
      assert.equal(noSource, undefined);
    } else {
      const source = verified.facts.source_capsule;
      const reconstructed: false = source.graph_hash_recomputed;
      const inputCount: number = source.input_count;
      assert.equal(reconstructed, false);
      assert(inputCount > 0);
      if (verified.facts.durable_journal !== null) {
        const retained: number = verified.facts.durable_journal.record_count;
        assert(retained > 0);
      }
    }
    nativePositive += 1;
  } catch (error: unknown) {
    if (observation.expected === "verified" || !(error instanceof VerifierError)
        || error.code !== observation.expected) throw error;
    nativeNegative += 1;
  }
}
if (nativePositive === 0 || nativeNegative === 0) throw new Error("native-session matrix is missing");
let sessionPositive = 0;
let sessionNegative = 0;
const sessionVerdicts = new Set<string>();
for (const session of cases.filter((item) => item.format === "signed-session")) {
  try {
    const verified = await verifyArtifact(Buffer.from(session.input_hex, "hex"), session.anchor,
      { verifier: resolve("verifier"), format: "signed-session" });
    if (session.expected !== "verified" || verified.format !== "signed-session"
        || verified.scope !== "authenticated_verification_session") {
      throw new Error("signed-session scope mismatch: " + session.name);
    }
    assert.deepEqual(verified.facts, session.session_facts, session.name);
    const decision: "pass" | "fail" | "inconclusive" = verified.facts.final_verdict;
    const steps: number = verified.facts.step_count;
    assert.equal(steps === 0, decision === "inconclusive");
    sessionVerdicts.add(decision);
    sessionPositive += 1;
  } catch (error: unknown) {
    if (session.expected === "verified" || !(error instanceof VerifierError)
        || error.code !== session.expected) throw error;
    sessionNegative += 1;
  }
}
assert.deepEqual([...sessionVerdicts].sort(), ["fail", "inconclusive", "pass"]);
if (sessionNegative === 0) throw new Error("signed-session negative matrix is missing");
let ltvPositive = 0, ltvNegative = 0;
for (const candidate of cases.filter((item) => item.format === "ltv-evidence")) {
  try {
    const verified = await verifyArtifact(Buffer.from(candidate.input_hex, "hex"), candidate.anchor,
      { verifier: resolve("verifier"), format: "ltv-evidence" });
    if (candidate.expected !== "verified" || verified.format !== "ltv-evidence"
        || verified.scope !== "authenticated_ltv_anteriority") throw new Error("LTV policy scope mismatch");
    const policyHash: string = verified.facts.trust_policy_sha256;
    assert.equal(policyHash, candidate.ltv_facts!.trust_policy_sha256);
    assert.deepEqual(verified.facts, candidate.ltv_facts, candidate.name);
    ltvPositive += 1;
  } catch (error: unknown) {
    if (candidate.expected === "verified" || !(error instanceof VerifierError)
        || error.code !== candidate.expected) throw error;
    ltvNegative += 1;
  }
}
assert(ltvPositive >= 4 && ltvNegative >= 16, "LTV authority policy controls must execute");
let fleetPositive = 0;
let fleetNegative = 0;
for (const candidate of allCases.filter((item): item is FleetCase => item.format === "fleet-quiescence-observations")) {
  try {
    const verified = await verifyArtifact(Buffer.from(candidate.input_hex, "hex"), candidate.anchor, {
      verifier: resolve("verifier"), format: "fleet-quiescence-observations",
      trustedFleetPolicy: candidate.fleet_policy_path,
    });
    if (candidate.expected !== "verified" || verified.format !== "fleet-quiescence-observations"
        || verified.scope !== "authenticated_fleet_supervisor_observations") throw new Error("fleet observation scope mismatch");
    assert.equal(verified.artifact_sha256, candidate.artifact_sha256);
    assert.deepEqual(verified.facts, candidate.fleet_facts, candidate.name);
    const admitted: string = verified.facts.admitted_sessions;
    const terminal: string = verified.facts.terminal_sessions;
    const committed: false = verified.facts.epoch_commit_authenticated;
    const current: false = verified.facts.current_quiescence_proven;
    if (admitted !== terminal || committed || current) throw new Error("fleet observation claim exceeds its scope");
    fleetPositive += 1;
  } catch (error: unknown) {
    if (candidate.expected === "verified" || !(error instanceof VerifierError)
        || error.code !== candidate.expected) throw error;
    fleetNegative += 1;
  }
}
assert(fleetPositive >= 5 && fleetNegative >= 25, "fleet authority and observation controls must execute");
console.log(JSON.stringify({ consumer: "typescript", positive: 8 + trustPositive + nativePositive + sessionPositive + identityPositive + ltvPositive + fleetPositive,
  negative: 2 + trustNegative + nativeNegative + sessionNegative + identityNegative + ltvNegative + fleetNegative, publisher_trust_cases: trustPositive + trustNegative,
  publisher_identity_cases: identityPositive + identityNegative,
  native_session_cases: nativePositive + nativeNegative, signed_session_cases: sessionPositive + sessionNegative,
  ltv_policy_cases: ltvPositive + ltvNegative,
  fleet_observation_cases: fleetPositive + fleetNegative,
  passed: true }));
