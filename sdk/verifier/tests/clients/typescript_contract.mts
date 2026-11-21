// Static consumer of the distributed declarations; only standard TS types.
import { verifyArtifact, VerifierError } from "../../bindings/javascript/franken_verifier.mjs";
import type { Verification } from "../../bindings/javascript/franken_verifier.mjs";

export async function audit(data: Uint8Array, anchor: string, executable: string): Promise<string> {
  try {
    const verified: Verification = await verifyArtifact(data, anchor, { verifier: executable });
    if (verified.format === "incident-bundle") return verified.facts.incident_id;
    if (verified.format === "native-session-forensics") return verified.facts.session_nonce;
    if (verified.format === "capsule") return verified.facts.capsule_id;
    if (verified.format === "signed-session") return verified.facts.session_id;
    if (verified.format === "resolution-receipt") return verified.facts.receipt_id;
    if (verified.format === "publisher-source") return verified.facts.package_name;
    if (verified.format === "publisher-source-trust") return verified.facts.source.package_name;
    if (verified.format === "counterfactual-receipt") return verified.facts.baseline_integrity_hash;
    if (verified.format === "ltv-evidence") return verified.facts.artifact_id;
    return verified.facts.bundle_id;
  } catch (error: unknown) {
    if (error instanceof VerifierError) return error.code;
    throw error;
  }
}

export async function auditSignedSession(
  data: Uint8Array, anchor: string, executable: string,
): Promise<"pass" | "fail" | "inconclusive"> {
  const verified = await verifyArtifact(data, anchor, {
    verifier: executable, format: "signed-session",
  });
  if (verified.format !== "signed-session"
      || verified.scope !== "authenticated_verification_session") {
    throw new Error("signed session proof required");
  }
  const steps: number = verified.facts.step_count;
  if (steps === 0 && verified.facts.final_verdict !== "inconclusive") {
    throw new Error("empty session cannot pass");
  }
  return verified.facts.final_verdict;
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
  const host = verified.facts.runtime_authority.host_io;
  const endpoints: string[] | undefined = host?.host_ports;
  const networkCalls: string | undefined = host?.max_calls_per_epoch.network_egress;
  const processCalls: string | undefined = host?.max_calls_per_epoch.process_spawn;
  return `${verified.facts.artifact_sha256}:${instructionCeiling}:${endpoints?.join(",")}:${networkCalls}:${processCalls}`;
}

/** Require a separately retained release identity, even for a trusted publisher. */
export async function auditExpectedPublisherRelease(
  data: Uint8Array, anchor: string, signature: string, executable: string,
  manifestSha256: string, sourceArtifactSha256?: string, graphInputHash?: string,
): Promise<string> {
  const verified = await verifyArtifact(data, anchor, {
    verifier: executable, format: "publisher-source", signatureHex: signature,
    expectedManifestSha256: manifestSha256,
    expectedSourceArtifactSha256: sourceArtifactSha256,
    expectedGraphInputHash: graphInputHash,
  });
  if (verified.format !== "publisher-source") throw new Error("publisher source required");
  const reconstructed: false = verified.facts.capsule.graph_hash_recomputed;
  if (reconstructed) throw new Error("identity matching cannot reconstruct a graph");
  return verified.facts.manifest_sha256;
}

export async function auditResolution(data: Uint8Array, anchor: string, executable: string): Promise<string | null> {
  const verified = await verifyArtifact(data, anchor, { verifier: executable, format: "resolution-receipt" });
  if (verified.format !== "resolution-receipt") throw new Error("resolution decision required");
  if (verified.facts.decision === "reject") return verified.facts.selected_version;
  return `${verified.facts.module_graph_hash}:${verified.facts.selected_version}`;
}

export async function auditPublisherSourceTrust(
  data: Uint8Array, publisherAnchor: string, signature: string, revocationAnchor: string,
  provenanceAnchor: string | undefined, evaluationTime: string, maxAgeSecs: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, publisherAnchor, {
    verifier: executable, format: "publisher-source-trust", signatureHex: signature,
    trustedRevocationPublicKeyHex: revocationAnchor, trustedProvenancePublicKeyHex: provenanceAnchor,
    evaluationTime, maxRevocationAgeSecs: maxAgeSecs,
  });
  if (verified.format !== "publisher-source-trust"
      || verified.scope !== "authenticated_publisher_source_trust") throw new Error("publisher trust required");
  const exactWindow: string = verified.facts.max_revocation_age_secs;
  if (verified.facts.provenance_authority_public_key_hex === null) {
    const absent: null = verified.facts.provenance_link_count;
    return verified.facts.source.artifact_sha256 + ":" + exactWindow + ":" + absent;
  }
  const linkCount: number = verified.facts.provenance_link_count;
  return verified.facts.provenance_chain_sha256 + ":" + exactWindow + ":" + linkCount;
}

export async function auditNativeSession(
  data: Uint8Array, productRootAnchor: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, productRootAnchor, {
    verifier: executable, format: "native-session-forensics",
  });
  if (verified.format !== "native-session-forensics"
      || verified.scope !== "authenticated_supervisor_observations") throw new Error("supervisor observation required");
  const epoch: string = verified.facts.security_epoch;
  const replay: false = verified.facts.replay_certified;
  const cleanup: false = verified.facts.quiescence_certified;
  const history: false = verified.facts.historical_completeness;
  if (replay || cleanup || history) throw new Error("forensic observations cannot certify execution");
  if (verified.facts.schema_version === "franken-node/native-session-forensics/v2") {
    const retained: number = verified.facts.durable_journal.record_count;
    const complete: false = verified.facts.durable_journal.historical_completeness;
    if (complete || retained < 1) throw new Error("a journal must be a retained signed prefix");
  } else {
    const absent: null = verified.facts.durable_journal;
    if (absent !== null) throw new Error("v1 carries no durable journal");
  }
  if (verified.facts.outcome_kind === "pending") {
    const unknown: null = verified.facts.completed_provider_calls;
    const observed: null = verified.facts.observed_at;
    return epoch + ":" + unknown + ":" + observed;
  }
  const observed: string = verified.facts.observed_at;
  return epoch + ":" + observed + ":" + verified.facts.outcome_kind;
}
