// Static consumer of the distributed declarations; only standard TS types.
import { verifyArtifact, VerifierError } from "../../bindings/javascript/franken_verifier.mjs";
import type { Verification } from "../../bindings/javascript/franken_verifier.mjs";

export async function audit(data: Uint8Array, anchor: string, executable: string): Promise<string> {
  try {
    const verified: Verification = await verifyArtifact(data, anchor, { verifier: executable });
    if (verified.format === "incident-bundle") return verified.facts.incident_id;
    if (verified.format === "native-session-forensics") return verified.facts.session_nonce;
    if (verified.format === "native-session-cold-archive") return verified.facts.merkle_root_sha256;
    if (verified.format === "fleet-quiescence-observations") return verified.facts.evidence_sha256;
    if (verified.format === "fleet-epoch-commit") return verified.facts.statement_sha256;
    if (verified.format === "capsule") return verified.facts.capsule_id;
    if (verified.format === "signed-session") return verified.facts.session_id;
    if (verified.format === "resolution-receipt") return verified.facts.receipt_id;
    if (verified.format === "publisher-source") return verified.facts.package_name;
    if (verified.format === "publisher-source-trust") return verified.facts.source.package_name;
    if (verified.format === "counterfactual-receipt") return verified.facts.baseline_integrity_hash;
    if (verified.format === "counterfactual-incident") return verified.facts.baseline.incident_id;
    if (verified.format === "counterfactual-promotion") return verified.facts.mitigation_id;
    if (verified.format === "ltv-evidence") return verified.facts.artifact_id;
    return verified.facts.bundle_id;
  } catch (error: unknown) {
    if (error instanceof VerifierError) return error.code;
    throw error;
  }
}

export async function auditFleetObservations(
  data: Uint8Array, policyPath: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, null, {
    verifier: executable, format: "fleet-quiescence-observations", trustedFleetPolicy: policyPath,
  });
  if (verified.format !== "fleet-quiescence-observations"
      || verified.scope !== "authenticated_fleet_supervisor_observations") {
    throw new Error("authenticated fleet supervisor observations required");
  }
  const admitted: string = verified.facts.admitted_sessions;
  const terminal: string = verified.facts.terminal_sessions;
  const committed: false = verified.facts.epoch_commit_authenticated;
  const current: false = verified.facts.current_quiescence_proven;
  if (admitted !== terminal || committed || current) throw new Error("fleet observations cannot certify a current epoch");
  return `${verified.facts.trusted_policy_input_sha256}:${admitted}:${terminal}`;
}

export async function auditFleetEpochCommit(
  data: Uint8Array, policyPath: string, coordinatorId: string, coordinatorKey: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, null, {
    verifier: executable, format: "fleet-epoch-commit", trustedFleetPolicy: policyPath,
    trustedCoordinatorId: coordinatorId, trustedCoordinatorPublicKeyHex: coordinatorKey,
  });
  if (verified.format !== "fleet-epoch-commit" || verified.scope !== "authenticated_fleet_epoch_commit") {
    throw new Error("independently anchored historical epoch commit required");
  }
  const epoch: string = verified.facts.committed_epoch;
  const committed: true = verified.facts.epoch_commit_authenticated;
  const current: false = verified.facts.current_quiescence_proven;
  if (!committed || current) throw new Error("historical commit cannot prove current quiescence");
  return `${verified.facts.coordinator_id}:${epoch}:${verified.facts.statement_sha256}`;
}

// Invalid trust models must fail at the public declaration boundary too. This
// function is type-checked, never executed by the consumer distribution.
export async function refuseFleetTrustSubstitutions(data: Uint8Array, anchor: string, policyPath: string, executable: string): Promise<void> {
  // @ts-expect-error Fleet verification requires an independent fleet policy.
  await verifyArtifact(data, null, { verifier: executable, format: "fleet-quiescence-observations" });
  // @ts-expect-error A single signing key cannot substitute for fleet enrollment.
  await verifyArtifact(data, anchor, { verifier: executable, format: "fleet-quiescence-observations", trustedFleetPolicy: policyPath });
  // @ts-expect-error Non-fleet formats still require their signing authority.
  await verifyArtifact(data, null, { verifier: executable, format: "incident-bundle" });
  // @ts-expect-error A supervisor policy alone cannot authenticate coordinator commits.
  await verifyArtifact(data, null, { verifier: executable, format: "fleet-epoch-commit", trustedFleetPolicy: policyPath });
  // @ts-expect-error Coordinator authority also requires an independently retained identifier.
  await verifyArtifact(data, null, { verifier: executable, format: "fleet-epoch-commit", trustedFleetPolicy: policyPath, trustedCoordinatorPublicKeyHex: anchor });
  // @ts-expect-error Coordinator authority also requires an independently retained key.
  await verifyArtifact(data, null, { verifier: executable, format: "fleet-epoch-commit", trustedFleetPolicy: policyPath, trustedCoordinatorId: "coordinator" });
  // @ts-expect-error Coordinator enrollment cannot substitute for the complete supervisor policy.
  await verifyArtifact(data, null, { verifier: executable, format: "fleet-epoch-commit", trustedCoordinatorId: "coordinator", trustedCoordinatorPublicKeyHex: anchor });
  // @ts-expect-error Strong fleet verification never uses the single-artifact signing-key overload.
  await verifyArtifact(data, anchor, { verifier: executable, format: "fleet-epoch-commit", trustedFleetPolicy: policyPath, trustedCoordinatorId: "coordinator", trustedCoordinatorPublicKeyHex: anchor });
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

export async function auditIncidentGraph(
  data: Uint8Array, exporterAnchor: string, runAnchor: string, runtimeAnchor: string,
  reportPath: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, exporterAnchor, {
    verifier: executable, format: "incident-bundle", graphReport: reportPath,
    trustedRunPublicKeyHex: runAnchor, trustedRuntimePublicKeyHex: runtimeAnchor,
  });
  if (verified.format !== "incident-bundle" || verified.scope !== "authenticated_runtime_incident"
      || verified.facts.graph_report === undefined) {
    throw new Error("requested incident graph and runtime origin required");
  }
  const recomputed: true = verified.facts.graph_report.graph_hash_recomputed;
  const semantics: false = verified.facts.graph_report.graph_semantics_reconstructed;
  if (!recomputed || semantics) throw new Error("graph commitment cannot certify resolver execution");
  return verified.facts.graph_report.report_sha256;
}

export async function auditCounterfactualIncident(
  data: Uint8Array, receiptAnchor: string, incidentAnchor: string, expectedBaseline: string,
  signature: string, runAnchor: string, runtimeAnchor: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, receiptAnchor, {
    verifier: executable, format: "counterfactual-incident", signatureHex: signature,
    trustedIncidentPublicKeyHex: incidentAnchor, expectedBaselineIntegrityHash: expectedBaseline,
    trustedRunPublicKeyHex: runAnchor, trustedRuntimePublicKeyHex: runtimeAnchor,
  });
  if (verified.format !== "counterfactual-incident"
      || verified.facts.baseline_scope !== "authenticated_runtime_incident") {
    throw new Error("counterfactual result bound to a runtime-authenticated incident required");
  }
  const executed: false = verified.facts.guest_execution_verified;
  const epoch: string = verified.facts.baseline.runtime_origin.signed_epoch;
  return `${verified.facts.baseline.run_origin.receipt_id}:${epoch}:${executed}`;
}

export async function refuseCounterfactualTrustOmissions(data: Uint8Array, anchor: string): Promise<void> {
  // @ts-expect-error An authenticated incident requires its independent exporter and retained pin.
  await verifyArtifact(data, anchor, { format: "counterfactual-incident", signatureHex: "signature" });
  // @ts-expect-error A receipt signature and exporter cannot select the expected incident identity.
  await verifyArtifact(data, anchor, { format: "counterfactual-incident", signatureHex: "signature", trustedIncidentPublicKeyHex: anchor });
  // @ts-expect-error The independently trusted exporter cannot be supplied by the artifact itself.
  await verifyArtifact(data, anchor, { format: "counterfactual-incident", signatureHex: "signature", expectedBaselineIntegrityHash: "hash" });
}

export async function auditCounterfactualPromotion(
  data: Uint8Array, operatorAnchor: string, incidentAnchor: string, expectedBaseline: string,
  runAnchor: string, runtimeAnchor: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, operatorAnchor, {
    verifier: executable, format: "counterfactual-promotion",
    trustedIncidentPublicKeyHex: incidentAnchor, expectedBaselineIntegrityHash: expectedBaseline,
    trustedRunPublicKeyHex: runAnchor, trustedRuntimePublicKeyHex: runtimeAnchor,
  });
  if (verified.format !== "counterfactual-promotion"
      || verified.facts.baseline_scope !== "authenticated_runtime_incident") {
    throw new Error("promotion contracts bound to a runtime-authenticated incident required");
  }
  const executed: false = verified.facts.guest_execution_verified;
  const authorized: false = verified.facts.rollout_authorized;
  const delta: string = verified.facts.expected_loss_delta;
  const from: string = verified.facts.valid_from_epoch_ms;
  const until: string = verified.facts.valid_until_epoch_ms;
  const executor: "synthetic" | "production" = verified.facts.executor;
  const epoch: string = verified.facts.baseline.runtime_origin.signed_epoch;
  // @ts-expect-error Signed i64 fields must never be exposed as imprecise numbers.
  const roundedDelta: number = verified.facts.expected_loss_delta;
  // @ts-expect-error Authentic historical contracts cannot authorize a rollout.
  const rolloutGrant: true = verified.facts.rollout_authorized;
  void roundedDelta; void rolloutGrant;
  return `${verified.facts.mitigation_id}:${executor}:${delta}:${from}:${until}:${epoch}:${executed}:${authorized}`;
}

export async function refuseCounterfactualPromotionTrustOmissions(
  data: Uint8Array, anchor: string, executable: string,
): Promise<void> {
  // @ts-expect-error Embedded promotion signatures still need an independent incident exporter and pin.
  await verifyArtifact(data, anchor, { verifier: executable, format: "counterfactual-promotion" });
  // @ts-expect-error An exporter authority cannot choose the expected incident identity.
  await verifyArtifact(data, anchor, { verifier: executable, format: "counterfactual-promotion", trustedIncidentPublicKeyHex: anchor });
  // @ts-expect-error A baseline pin does not authenticate its exporting authority.
  await verifyArtifact(data, anchor, { verifier: executable, format: "counterfactual-promotion", expectedBaselineIntegrityHash: "hash" });
  // @ts-expect-error The operator key is required independently of the exporter authority.
  await verifyArtifact(data, null, { verifier: executable, format: "counterfactual-promotion", trustedIncidentPublicKeyHex: anchor, expectedBaselineIntegrityHash: "hash" });
  // @ts-expect-error Product promotion contracts contain their signatures and cannot accept a detached replacement.
  await verifyArtifact(data, anchor, { verifier: executable, format: "counterfactual-promotion", trustedIncidentPublicKeyHex: anchor, expectedBaselineIntegrityHash: "hash", signatureHex: "signature" });
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

/** Independently verify the committed graph witness without a semantic replay claim. */
export async function auditPublisherGraphCommitment(
  data: Uint8Array, anchor: string, signature: string, executable: string, reportPath: string,
): Promise<string> {
  const verified = await verifyArtifact(data, anchor, {
    verifier: executable, format: "publisher-source", signatureHex: signature, graphReport: reportPath,
  });
  if (verified.format !== "publisher-source") throw new Error("publisher source required");
  const graph = verified.facts.graph_report;
  if (graph === undefined) throw new Error("requested graph commitment is missing");
  const recomputed: true = graph.graph_hash_recomputed;
  const semantics: false = graph.graph_semantics_reconstructed;
  const capsuleOnly: false = verified.facts.capsule.graph_hash_recomputed;
  const count: number = graph.module_count;
  const producerClaim: boolean = graph.declared_fully_resolved;
  if (!recomputed || semantics || capsuleOnly || count < 1 || typeof producerClaim !== "boolean") {
    throw new Error("invalid graph commitment scope");
  }
  return graph.graph_input_hash;
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

export async function auditColdArchive(
  data: Uint8Array, productRootAnchor: string, expectedRoot: string, executable: string,
): Promise<string> {
  const verified = await verifyArtifact(data, productRootAnchor, {
    verifier: executable, format: "native-session-cold-archive", expectedArchiveRootSha256: expectedRoot,
  });
  if (verified.format !== "native-session-cold-archive"
      || verified.scope !== "authenticated_archived_supervisor_observations") throw new Error("archive observation required");
  const originals: false = verified.facts.original_receipt_signatures_verified;
  const replay: false = verified.facts.replay_certified;
  const cleanup: false = verified.facts.quiescence_certified;
  const history: false = verified.facts.historical_completeness;
  const population: number = verified.facts.session_count;
  if (originals || replay || cleanup || history || population < 1) throw new Error("archive claim exceeds its scope");
  // @ts-expect-error A cold archive does not expose a per-session original receipt.
  verified.facts.admission_sha256;
  return `${verified.facts.merkle_root_sha256}:${verified.facts.archive_sha256}:${population}`;
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
  } else if (verified.facts.schema_version === "franken-node/native-session-forensics/v1") {
    const absent: null = verified.facts.durable_journal;
    if (absent !== null) throw new Error("v1 carries no durable journal");
  } else {
    const schema: "franken-node/native-session-forensics/v3" = verified.facts.schema_version;
    const reconstructed: false = verified.facts.source_capsule.graph_hash_recomputed;
    const inputCount: number = verified.facts.source_capsule.input_count;
    if (reconstructed || inputCount < 1) throw new Error(`${schema} must retain source content without graph reconstruction`);
    if (verified.facts.durable_journal !== null) {
      const retained: number = verified.facts.durable_journal.record_count;
      const complete: false = verified.facts.durable_journal.historical_completeness;
      if (complete || retained < 1) throw new Error("a journal must be a retained signed prefix");
    }
  }
  if (verified.facts.outcome_kind === "pending") {
    const unknown: null = verified.facts.completed_provider_calls;
    const observed: null = verified.facts.observed_at;
    return epoch + ":" + unknown + ":" + observed;
  }
  const observed: string = verified.facts.observed_at;
  return epoch + ":" + observed + ":" + verified.facts.outcome_kind;
}
