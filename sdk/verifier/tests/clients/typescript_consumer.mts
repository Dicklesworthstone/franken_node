import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyArtifact, VerifierError } from "./franken_verifier.mjs";
import type { Verification, EvidenceFormat } from "./franken_verifier.mjs";

const cases: Array<{ name: string; input_hex: string; anchor: string; format: EvidenceFormat;
  signature_hex?: string; run_anchor?: string; event_count?: number; expected: string; artifact_sha256: string }> =
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
console.log(JSON.stringify({ consumer: "typescript", positive: 2, negative: 2, passed: true }));
