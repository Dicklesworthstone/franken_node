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
