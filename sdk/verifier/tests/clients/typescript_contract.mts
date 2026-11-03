// Static consumer of the distributed declarations; only standard TS types.
import { verifyArtifact, VerifierError } from "../../bindings/javascript/franken_verifier.mjs";
import type { Verification } from "../../bindings/javascript/franken_verifier.mjs";

export async function audit(data: Uint8Array, anchor: string, executable: string): Promise<string> {
  try {
    const verified: Verification = await verifyArtifact(data, anchor, { verifier: executable });
    if (verified.format === "incident-bundle") return verified.facts.incident_id;
    if (verified.format === "capsule") return verified.facts.capsule_id;
    return verified.facts.bundle_id;
  } catch (error: unknown) {
    if (error instanceof VerifierError) return error.code;
    throw error;
  }
}

export async function auditOriginalRun(
  data: Uint8Array, exporterAnchor: string, runAnchor: string, executable: string,
): Promise<string> {
  const verified: Verification = await verifyArtifact(data, exporterAnchor, {
    verifier: executable, format: "incident-bundle", trustedRunPublicKeyHex: runAnchor,
  });
  if (verified.scope !== "authenticated_run_incident") throw new Error("original-run proof required");
  return `${verified.facts.run_origin.receipt_id}:${verified.facts.run_origin.record_sha256}`;
}
