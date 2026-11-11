// Static consumer of the distributed declarations; only standard TS types.
import { verifyArtifact, VerifierError } from "../../bindings/javascript/franken_verifier.mjs";
import type { Verification } from "../../bindings/javascript/franken_verifier.mjs";

export async function audit(data: Uint8Array, anchor: string, executable: string): Promise<string> {
  try {
    const verified: Verification = await verifyArtifact(data, anchor, { verifier: executable });
    if (verified.format === "incident-bundle") return verified.facts.incident_id;
    if (verified.format === "capsule") return verified.facts.capsule_id;
    if (verified.format === "resolution-receipt") return verified.facts.receipt_id;
    if (verified.format === "publisher-source") return verified.facts.package_name;
    if (verified.format === "counterfactual-receipt") return verified.facts.baseline_integrity_hash;
    if (verified.format === "ltv-evidence") return verified.facts.artifact_id;
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

export async function auditRuntimeOrigin(
  data: Uint8Array, exporterAnchor: string, runAnchor: string, runtimeAnchor: string, executable: string,
): Promise<string> {
  const verified: Verification = await verifyArtifact(data, exporterAnchor, {
    verifier: executable, trustedRunPublicKeyHex: runAnchor, trustedRuntimePublicKeyHex: runtimeAnchor,
  });
  if (verified.scope !== "authenticated_runtime_incident") throw new Error("runtime-origin proof required");
  return `${verified.facts.runtime_origin.session_nonce}:${verified.facts.runtime_origin.signed_epoch}`;
}

export async function auditPublisherSource(
  data: Uint8Array, anchor: string, signature: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, anchor, {
    verifier: executable, format: "publisher-source", signatureHex: signature,
  });
  if (verified.format !== "publisher-source") throw new Error("publisher source content required");
  const reconstructed: false = verified.facts.capsule.graph_hash_recomputed;
  if (reconstructed) throw new Error("source content cannot establish graph reconstruction");
  if (verified.facts.registration_schema === "franken-node/extension-registration-manifest/v1") {
    const absent: null = verified.facts.runtime_authority;
    return `${verified.facts.artifact_sha256}:${absent}`;
  }
  const instructionCeiling: string = verified.facts.runtime_authority.max_instructions;
  return `${verified.facts.artifact_sha256}:${instructionCeiling}`;
}

export async function auditResolution(data: Uint8Array, anchor: string, executable: string): Promise<string | null> {
  const verified = await verifyArtifact(data, anchor, { verifier: executable, format: "resolution-receipt" });
  if (verified.format !== "resolution-receipt") throw new Error("resolution decision required");
  if (verified.facts.decision === "reject") return verified.facts.selected_version;
  return `${verified.facts.module_graph_hash}:${verified.facts.selected_version}`;
}
