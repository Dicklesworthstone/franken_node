import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyArtifact, VerifierError } from "./franken_verifier.mjs";
import type { Verification, EvidenceFormat } from "./franken_verifier.mjs";

const cases: Array<{ name: string; input_hex: string; anchor: string; format: EvidenceFormat;
  signature_hex?: string; run_anchor?: string; runtime_anchor?: string; event_count?: number; expected: string; artifact_sha256: string }> =
  JSON.parse(readFileSync("vectors.json", "utf8"));
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
const cfSweep = cases.find((item) => item.name === "counterfactual_signed_sweep")!;
const cfVerified = await verifyArtifact(Buffer.from(cfSweep.input_hex, "hex"), cfSweep.anchor,
  { verifier: resolve("verifier"), format: "counterfactual-receipt", signatureHex: cfSweep.signature_hex });
if (cfVerified.format !== "counterfactual-receipt"
    || cfVerified.scope !== "authenticated_counterfactual_receipt"
    || cfVerified.facts.mode !== "sweep"
    || cfVerified.facts.result_count !== 2) {
  throw new Error("TypeScript counterfactual receipt mismatch");
}
console.log(JSON.stringify({ consumer: "typescript", positive: 8, negative: 2, passed: true }));
