use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(any(test, feature = "control-plane"))]
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "control-plane"))]
use crate::connector::universal_verifier_sdk as node_vsdk;
use crate::{
    supply_chain::provenance::{self, ProvenanceAttestation, VerificationPolicy},
    vef::evidence_capsule::{EvidenceCapsule, EvidenceVerificationContext},
};

pub const EVIDENCE_EXPLAIN_SCHEMA_VERSION: &str = "franken-node/evidence-explain/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceArtifactKind {
    Auto,
    NodeReplayCapsule,
    ProvenanceAttestation,
    VefEvidenceCapsule,
}

impl EvidenceArtifactKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::NodeReplayCapsule => "node-replay-capsule",
            Self::ProvenanceAttestation => "provenance-attestation",
            Self::VefEvidenceCapsule => "vef-evidence-capsule",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExplainStep {
    pub check_id: String,
    pub input_artifact: String,
    pub expected_value: String,
    pub observed_value: String,
    pub verdict: String,
    pub recovery_hint: String,
}

impl EvidenceExplainStep {
    fn pass(
        check_id: impl Into<String>,
        input_artifact: impl Into<String>,
        expected_value: impl Into<String>,
        observed_value: impl Into<String>,
        recovery_hint: impl Into<String>,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            input_artifact: input_artifact.into(),
            expected_value: expected_value.into(),
            observed_value: observed_value.into(),
            verdict: "pass".to_string(),
            recovery_hint: recovery_hint.into(),
        }
    }

    fn fail(
        check_id: impl Into<String>,
        input_artifact: impl Into<String>,
        expected_value: impl Into<String>,
        observed_value: impl Into<String>,
        recovery_hint: impl Into<String>,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            input_artifact: input_artifact.into(),
            expected_value: expected_value.into(),
            observed_value: observed_value.into(),
            verdict: "fail".to_string(),
            recovery_hint: recovery_hint.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExplainReport {
    pub schema_version: String,
    pub command: String,
    pub artifact_kind: String,
    pub input_artifact: String,
    pub overall_verdict: String,
    pub steps: Vec<EvidenceExplainStep>,
    pub next_commands: Vec<String>,
}

impl EvidenceExplainReport {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        self.overall_verdict == "pass"
    }

    fn recompute_verdict(&mut self) {
        self.overall_verdict = if self.steps.iter().all(|step| step.verdict == "pass") {
            "pass".to_string()
        } else {
            "fail".to_string()
        };
    }
}

#[derive(Debug, Deserialize)]
struct ProvenanceEvidenceArtifact {
    attestation: ProvenanceAttestation,
    #[serde(default)]
    policy: Option<VerificationPolicy>,
    #[serde(default)]
    now_epoch: Option<u64>,
    #[serde(default)]
    trace_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VefEvidenceArtifact {
    capsule: EvidenceCapsule,
    #[serde(default)]
    context: Option<EvidenceVerificationContext>,
}

#[must_use]
pub fn render_evidence_explain_human(report: &EvidenceExplainReport) -> String {
    let mut lines = Vec::with_capacity(report.steps.len().saturating_add(2));
    lines.push(format!(
        "evidence_explain artifact={} kind={} verdict={}",
        report.input_artifact, report.artifact_kind, report.overall_verdict
    ));
    for step in &report.steps {
        lines.push(format!(
            "check_id={} verdict={} input_artifact={} expected={:?} observed={:?} recovery_hint={:?}",
            step.check_id,
            step.verdict,
            step.input_artifact,
            step.expected_value,
            step.observed_value,
            step.recovery_hint
        ));
    }
    for command in &report.next_commands {
        lines.push(format!("next_command={command:?}"));
    }
    lines.join("\n")
}

pub fn explain_evidence_file(
    path: &Path,
    requested_kind: EvidenceArtifactKind,
    verifier_identity: &str,
) -> EvidenceExplainReport {
    let artifact_label = path.display().to_string();
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut report =
                explain_evidence_bytes(&bytes, &artifact_label, requested_kind, verifier_identity);
            report.steps.insert(
                0,
                EvidenceExplainStep::pass(
                    "EVEX-READ",
                    &artifact_label,
                    "readable artifact file",
                    format!("{} bytes", bytes.len()),
                    "Use a relative artifact path under the current workspace.",
                ),
            );
            report.recompute_verdict();
            report
        }
        Err(err) => report_from_steps(
            requested_kind.as_str(),
            &artifact_label,
            vec![EvidenceExplainStep::fail(
                "EVEX-READ",
                &artifact_label,
                "readable artifact file",
                err.to_string(),
                "Check the artifact path and run from the workspace that owns the evidence file.",
            )],
        ),
    }
}

#[must_use]
pub fn explain_evidence_bytes(
    bytes: &[u8],
    artifact_label: &str,
    requested_kind: EvidenceArtifactKind,
    verifier_identity: &str,
) -> EvidenceExplainReport {
    let value = match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => value,
        Err(err) => {
            return report_from_steps(
                requested_kind.as_str(),
                artifact_label,
                vec![EvidenceExplainStep::fail(
                    "EVEX-PARSE",
                    artifact_label,
                    "valid JSON evidence artifact",
                    err.to_string(),
                    "Regenerate or export the artifact as JSON before re-running evidence explain.",
                )],
            );
        }
    };

    let resolved_kind = match resolve_kind(&value, requested_kind) {
        Some(kind) => kind,
        None => {
            return report_from_steps(
                "unknown",
                artifact_label,
                vec![
                    EvidenceExplainStep::pass(
                        "EVEX-PARSE",
                        artifact_label,
                        "valid JSON evidence artifact",
                        "valid JSON object",
                        "Continue with kind detection.",
                    ),
                    EvidenceExplainStep::fail(
                        "EVEX-KIND",
                        artifact_label,
                        "one of node-replay-capsule, provenance-attestation, vef-evidence-capsule",
                        "unrecognized JSON shape",
                        "Re-run with --kind or pass an artifact emitted by a supported evidence surface.",
                    ),
                ],
            );
        }
    };

    let mut steps = vec![
        EvidenceExplainStep::pass(
            "EVEX-PARSE",
            artifact_label,
            "valid JSON evidence artifact",
            "valid JSON object",
            "Continue with evidence verification.",
        ),
        EvidenceExplainStep::pass(
            "EVEX-KIND",
            artifact_label,
            requested_kind.as_str(),
            resolved_kind.as_str(),
            "Use --kind to lock this contract in CI if auto-detection is too permissive.",
        ),
    ];

    match resolved_kind {
        EvidenceArtifactKind::NodeReplayCapsule => {
            explain_node_replay_capsule(&value, artifact_label, verifier_identity, &mut steps);
        }
        EvidenceArtifactKind::ProvenanceAttestation => {
            explain_provenance_attestation(&value, artifact_label, &mut steps);
        }
        EvidenceArtifactKind::VefEvidenceCapsule => {
            explain_vef_evidence_capsule(&value, artifact_label, &mut steps);
        }
        EvidenceArtifactKind::Auto => steps.push(EvidenceExplainStep::fail(
            "EVEX-KIND",
            artifact_label,
            "concrete evidence artifact kind",
            "auto remained unresolved",
            "Re-run with --kind and a supported evidence artifact shape.",
        )),
    }

    report_from_steps(resolved_kind.as_str(), artifact_label, steps)
}

fn report_from_steps(
    artifact_kind: &str,
    artifact_label: &str,
    steps: Vec<EvidenceExplainStep>,
) -> EvidenceExplainReport {
    let overall_verdict = if steps.iter().all(|step| step.verdict == "pass") {
        "pass"
    } else {
        "fail"
    };
    let kind_arg = if artifact_kind == "unknown" {
        "auto"
    } else {
        artifact_kind
    };
    EvidenceExplainReport {
        schema_version: EVIDENCE_EXPLAIN_SCHEMA_VERSION.to_string(),
        command: "debug evidence".to_string(),
        artifact_kind: artifact_kind.to_string(),
        input_artifact: artifact_label.to_string(),
        overall_verdict: overall_verdict.to_string(),
        steps,
        next_commands: vec![
            format!(
                "franken-node debug evidence --artifact {artifact_label} --kind {kind_arg} --json"
            ),
            "franken-node doctor --verbose".to_string(),
        ],
    }
}

fn resolve_kind(
    value: &Value,
    requested_kind: EvidenceArtifactKind,
) -> Option<EvidenceArtifactKind> {
    if requested_kind != EvidenceArtifactKind::Auto {
        return Some(requested_kind);
    }
    if looks_like_node_replay_capsule(value) {
        Some(EvidenceArtifactKind::NodeReplayCapsule)
    } else if looks_like_provenance_attestation(value) {
        Some(EvidenceArtifactKind::ProvenanceAttestation)
    } else if looks_like_vef_evidence_capsule(value) {
        Some(EvidenceArtifactKind::VefEvidenceCapsule)
    } else {
        None
    }
}

fn looks_like_node_replay_capsule(value: &Value) -> bool {
    value.get("manifest").is_some()
        && value.get("payload").is_some()
        && value.get("inputs").is_some()
        && value.get("signature").is_some()
}

fn looks_like_provenance_attestation(value: &Value) -> bool {
    let candidate = value.get("attestation").unwrap_or(value);
    candidate.get("source_repository_url").is_some()
        && candidate.get("output_hash").is_some()
        && candidate.get("links").is_some()
}

fn looks_like_vef_evidence_capsule(value: &Value) -> bool {
    let candidate = value.get("capsule").unwrap_or(value);
    candidate.get("capsule_id").is_some()
        && candidate.get("schema_version").is_some()
        && candidate.get("evidence").is_some()
}

#[cfg(any(test, feature = "control-plane"))]
fn explain_node_replay_capsule(
    value: &Value,
    artifact_label: &str,
    verifier_identity: &str,
    steps: &mut Vec<EvidenceExplainStep>,
) {
    let capsule = match serde_json::from_value::<node_vsdk::ReplayCapsule>(value.clone()) {
        Ok(capsule) => {
            steps.push(EvidenceExplainStep::pass(
                "EVEX-NODE-DECODE",
                artifact_label,
                "node universal verifier ReplayCapsule",
                "decoded ReplayCapsule JSON",
                "Continue with live node verifier SDK checks.",
            ));
            capsule
        }
        Err(err) => {
            steps.push(EvidenceExplainStep::fail(
                "EVEX-NODE-DECODE",
                artifact_label,
                "node universal verifier ReplayCapsule",
                err.to_string(),
                "Export a ReplayCapsule with manifest, payload, inputs, and signature fields.",
            ));
            return;
        }
    };

    match node_vsdk::validate_manifest(&capsule.manifest) {
        Ok(()) => steps.push(EvidenceExplainStep::pass(
            "EVEX-NODE-MANIFEST",
            artifact_label,
            "supported schema, signature metadata, and manifest fields",
            format!(
                "schema={} capsule_id={} input_refs={}",
                capsule.manifest.schema_version,
                capsule.manifest.capsule_id,
                capsule.manifest.input_refs.len()
            ),
            "If replay still fails, inspect signature and input refs next.",
        )),
        Err(err) => steps.push(node_error_step(
            "EVEX-NODE-MANIFEST",
            artifact_label,
            "supported schema, signature metadata, and manifest fields",
            &err,
            "Regenerate the capsule manifest with required schema, signature_algorithm, and ed25519_public_key metadata.",
        )),
    }

    match node_vsdk::verify_capsule_signature(&capsule) {
        Ok(()) => steps.push(EvidenceExplainStep::pass(
            "EVEX-NODE-SIGNATURE",
            artifact_label,
            "valid ed25519 capsule signature bound to manifest metadata",
            "signature verified",
            "Continue with deterministic replay output comparison.",
        )),
        Err(err) => steps.push(node_error_step(
            "EVEX-NODE-SIGNATURE",
            artifact_label,
            "valid ed25519 capsule signature bound to manifest metadata",
            &err,
            "Re-sign the capsule after any payload, input_refs, expected hash, or metadata change.",
        )),
    }

    match node_vsdk::replay_capsule(&capsule, verifier_identity) {
        Ok(result) if result.verdict == node_vsdk::CapsuleVerdict::Pass => {
            steps.push(EvidenceExplainStep::pass(
                "EVEX-NODE-REPLAY",
                artifact_label,
                result.expected_output_hash,
                result.actual_output_hash,
                "Replay output hash matches the manifest.",
            ));
        }
        Ok(result) => steps.push(EvidenceExplainStep::fail(
            "EVEX-NODE-REPLAY",
            artifact_label,
            result.expected_output_hash,
            result.actual_output_hash,
            "Inspect payload and input artifact bytes; producer metadata cannot force a pass verdict.",
        )),
        Err(err) => steps.push(node_error_step(
            "EVEX-NODE-REPLAY",
            artifact_label,
            "pass verdict from live node replay verifier",
            &err,
            "Fix the first failing manifest, signature, input-ref, or payload check and replay again.",
        )),
    }
}

#[cfg(not(any(test, feature = "control-plane")))]
fn explain_node_replay_capsule(
    _value: &Value,
    artifact_label: &str,
    _verifier_identity: &str,
    steps: &mut Vec<EvidenceExplainStep>,
) {
    steps.push(EvidenceExplainStep::fail(
        "EVEX-NODE-FEATURE",
        artifact_label,
        "node replay verifier compiled with control-plane support",
        "control-plane feature disabled",
        "Run this command from a franken-node build with the control-plane feature enabled.",
    ));
}

#[cfg(any(test, feature = "control-plane"))]
fn node_error_step(
    check_id: &str,
    artifact_label: &str,
    expected_value: &str,
    err: &node_vsdk::VsdkError,
    recovery_hint: &str,
) -> EvidenceExplainStep {
    match err {
        node_vsdk::VsdkError::SignatureMismatch { expected, actual } => EvidenceExplainStep::fail(
            check_id,
            artifact_label,
            expected.clone(),
            format!(
                "signature_sha256={} len={}",
                sha256_text(actual),
                actual.len()
            ),
            recovery_hint,
        ),
        other => EvidenceExplainStep::fail(
            check_id,
            artifact_label,
            expected_value,
            other.to_string(),
            recovery_hint,
        ),
    }
}

fn explain_provenance_attestation(
    value: &Value,
    artifact_label: &str,
    steps: &mut Vec<EvidenceExplainStep>,
) {
    let parsed = if value.get("attestation").is_some() {
        serde_json::from_value::<ProvenanceEvidenceArtifact>(value.clone())
    } else {
        serde_json::from_value::<ProvenanceAttestation>(value.clone()).map(|attestation| {
            ProvenanceEvidenceArtifact {
                attestation,
                policy: None,
                now_epoch: None,
                trace_id: None,
            }
        })
    };
    let artifact = match parsed {
        Ok(artifact) => {
            steps.push(EvidenceExplainStep::pass(
                "EVEX-PROVENANCE-DECODE",
                artifact_label,
                "provenance attestation artifact",
                "decoded provenance attestation JSON",
                "Continue with live provenance verification policy.",
            ));
            artifact
        }
        Err(err) => {
            steps.push(EvidenceExplainStep::fail(
                "EVEX-PROVENANCE-DECODE",
                artifact_label,
                "provenance attestation artifact",
                err.to_string(),
                "Export either a ProvenanceAttestation or a wrapper with attestation, policy, and now_epoch.",
            ));
            return;
        }
    };

    let policy = artifact
        .policy
        .unwrap_or_else(VerificationPolicy::production_default);
    let now_epoch = artifact.now_epoch.unwrap_or(0);
    let trace_id = artifact
        .trace_id
        .unwrap_or_else(|| "evidence-explain".to_string());

    if policy.trusted_signer_keys.is_empty() && !policy.allow_self_signed {
        steps.push(EvidenceExplainStep::fail(
            "EVEX-PROVENANCE-POLICY",
            artifact_label,
            "trusted signer keys or explicit self-signed development policy",
            "no trusted_signer_keys and allow_self_signed=false",
            "Provide a VerificationPolicy with trusted_signer_keys for every required chain signer.",
        ));
    } else {
        steps.push(EvidenceExplainStep::pass(
            "EVEX-PROVENANCE-POLICY",
            artifact_label,
            "trusted signer keys or explicit self-signed development policy",
            format!(
                "trusted_signer_keys={} allow_self_signed={}",
                policy.trusted_signer_keys.len(),
                policy.allow_self_signed
            ),
            "Continue with provenance chain verification.",
        ));
    }

    let report =
        provenance::verify_attestation_chain(&artifact.attestation, &policy, now_epoch, &trace_id);
    if report.chain_valid {
        steps.push(EvidenceExplainStep::pass(
            "EVEX-PROVENANCE-CHAIN",
            artifact_label,
            "chain_valid=true from live provenance verifier",
            format!(
                "chain_valid=true provenance_level={:?}",
                report.provenance_level
            ),
            "The attestation chain is bound to canonical content, signer keys, and link order.",
        ));
    } else {
        let observed = report
            .issues
            .iter()
            .map(|issue| format!("{:?}:{}", issue.code, issue.message))
            .collect::<Vec<_>>()
            .join(" | ");
        steps.push(EvidenceExplainStep::fail(
            "EVEX-PROVENANCE-CHAIN",
            artifact_label,
            "chain_valid=true from live provenance verifier",
            observed,
            "Fix the first provenance issue; custom producer claims such as verified=true are ignored.",
        ));
    }
}

fn explain_vef_evidence_capsule(
    value: &Value,
    artifact_label: &str,
    steps: &mut Vec<EvidenceExplainStep>,
) {
    let parsed = if value.get("capsule").is_some() {
        serde_json::from_value::<VefEvidenceArtifact>(value.clone())
    } else {
        serde_json::from_value::<EvidenceCapsule>(value.clone()).map(|capsule| {
            VefEvidenceArtifact {
                capsule,
                context: None,
            }
        })
    };
    let artifact = match parsed {
        Ok(artifact) => {
            steps.push(EvidenceExplainStep::pass(
                "EVEX-VEF-DECODE",
                artifact_label,
                "VEF evidence capsule artifact",
                "decoded VEF EvidenceCapsule JSON",
                "Continue with sealed capsule and receipt-chain context checks.",
            ));
            artifact
        }
        Err(err) => {
            steps.push(EvidenceExplainStep::fail(
                "EVEX-VEF-DECODE",
                artifact_label,
                "VEF evidence capsule artifact",
                err.to_string(),
                "Export an EvidenceCapsule or a wrapper with capsule and context fields.",
            ));
            return;
        }
    };

    if artifact.capsule.is_sealed() {
        steps.push(EvidenceExplainStep::pass(
            "EVEX-VEF-SEALED",
            artifact_label,
            "sealed evidence capsule",
            "sealed=true",
            "Continue with receipt-chain context verification.",
        ));
    } else {
        steps.push(EvidenceExplainStep::fail(
            "EVEX-VEF-SEALED",
            artifact_label,
            "sealed evidence capsule",
            "sealed=false",
            "Seal the capsule before it is accepted as verifier evidence.",
        ));
    }

    match artifact.context.as_ref() {
        Some(context) => steps.push(EvidenceExplainStep::pass(
            "EVEX-VEF-CONTEXT",
            artifact_label,
            "trusted receipt-chain commitments and accepted proof types",
            format!(
                "trusted_commitments={} accepted_proof_types={}",
                context.trusted_receipt_chain_commitments.len(),
                context.accepted_proof_types.len()
            ),
            "Continue with live VEF evidence verification.",
        )),
        None => steps.push(EvidenceExplainStep::fail(
            "EVEX-VEF-CONTEXT",
            artifact_label,
            "trusted receipt-chain commitments and accepted proof types",
            "missing verification context",
            "Provide an EvidenceVerificationContext; producer verified=true flags are ignored.",
        )),
    }

    let result = match artifact.context.as_ref() {
        Some(context) => artifact.capsule.verify_all_with_context(context),
        None => artifact.capsule.verify_all(),
    };
    if result.valid {
        steps.push(EvidenceExplainStep::pass(
            "EVEX-VEF-VERIFY",
            artifact_label,
            "valid=true from live VEF evidence verifier",
            format!("checked={} passed={}", result.checked, result.passed),
            "The capsule commitment and trusted context agree.",
        ));
    } else {
        steps.push(EvidenceExplainStep::fail(
            "EVEX-VEF-VERIFY",
            artifact_label,
            "valid=true from live VEF evidence verifier",
            result.failures.join(" | "),
            "Regenerate commitments from canonical evidence and supply trusted context.",
        ));
    }
}

#[cfg(any(test, feature = "control-plane"))]
fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}
