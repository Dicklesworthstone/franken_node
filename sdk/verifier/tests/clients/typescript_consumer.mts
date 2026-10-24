import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyArtifact, VerifierError } from "./franken_verifier.mjs";
import type { Verification, EvidenceFormat } from "./franken_verifier.mjs";

const cases: Array<{ name: string; input_hex: string; anchor: string; format: EvidenceFormat;
  signature_hex?: string; expected: string; artifact_sha256: string }> =
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
console.log(JSON.stringify({ consumer: "typescript", positive: 1, negative: 1, passed: true }));
