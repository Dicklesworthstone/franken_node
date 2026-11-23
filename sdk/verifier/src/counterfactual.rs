//! Counterfactual replay receipt verification for external verifiers.
//!
//! The producer-side counterfactual replay tool signs the deterministic JSON
//! emitted by `tools::counterfactual_replay::to_canonical_json`. This module
//! mirrors that key-sorted JSON canonicalization and verifies the detached
//! Ed25519 receipt signature without depending on franken-node internals.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::bundle::{
    BundleError, CapabilityPolicyProfile, CapabilityPostcondition, CapabilityProof,
    CapabilityRevocationFreshness, CapabilityScope, EffectKind, verify_capability_proof_schema,
    verify_ed25519_signature,
};
use crate::incident_bundle::{
    IncidentBundleError, VerifiedIncidentBundle, VerifiedRunOrigin, VerifiedRuntimeOrigin,
    decode_evidence_json, verify_incident_bundle, verify_incident_bundle_with_run_key,
    verify_incident_bundle_with_runtime_keys,
};

/// Bound the signed receipt independently of the baseline bundle's byte bound.
pub const MAX_COUNTERFACTUAL_INCIDENT_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_COUNTERFACTUAL_INCIDENT_RESULTS: usize = 20;
const MAX_COUNTERFACTUAL_OUTPUT_NODES: usize = 1_000_000;
const MAX_COUNTERFACTUAL_OUTPUT_DEPTH: usize = 128;

/// Independently supplied authorities and the exact incident selected by the
/// verifier. Never derive the expected hash or any of these keys from the
/// candidate counterfactual transport. The bundle exporter, original receipt
/// authority, product root and counterfactual signer have separate roles.
pub struct CounterfactualIncidentTrust<'a> {
    pub expected_baseline_integrity_hash: &'a str,
    pub trusted_counterfactual_signer: &'a VerifyingKey,
    pub trusted_bundle_signer: &'a VerifyingKey,
    pub trusted_run_signer: Option<&'a VerifyingKey>,
    pub trusted_product_root: Option<&'a VerifyingKey>,
}

/// Authenticated baseline evidence and its signed counterfactual attribution.
///
/// This establishes the exact baseline, its selected original authorities, and
/// the receipt's complete ordered event/context bindings. Decisions, rationales,
/// risk estimates and alternate execution remain signed producer statements;
/// neither the native guest nor the producer's policy model is executed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCounterfactualIncident {
    pub baseline: VerifiedIncidentBundle,
    pub run_origin: Option<VerifiedRunOrigin>,
    pub runtime_origin: Option<VerifiedRuntimeOrigin>,
    pub counterfactual_signer_public_key_hex: String,
    /// SHA-256 of the canonical receipt bytes authenticated by its signature.
    pub counterfactual_output_sha256: String,
    pub mode: &'static str,
    pub result_count: usize,
    pub guest_execution_verified: bool,
}

/// Failures of composed baseline/receipt verification. Display and Debug never
/// echo untrusted source text, paths, policy names or signed receipt contents.
#[derive(Clone, PartialEq, Eq)]
pub enum CounterfactualIncidentError {
    ExpectedBaselineInvalid,
    ExpectedBaselineMismatch,
    TrustPolicyInvalid,
    Baseline(IncidentBundleError),
    Receipt(CounterfactualReceiptError),
    OutputTooLarge,
    OutputInvalid,
    ContextMismatch { field: &'static str },
}

impl CounterfactualIncidentError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ExpectedBaselineInvalid => "COUNTERFACTUAL_BASELINE_PIN_INVALID",
            Self::ExpectedBaselineMismatch => "COUNTERFACTUAL_BASELINE_PIN_MISMATCH",
            Self::TrustPolicyInvalid => "COUNTERFACTUAL_TRUST_POLICY_INVALID",
            Self::Baseline(_) => "COUNTERFACTUAL_BASELINE_INVALID",
            Self::Receipt(_) => "COUNTERFACTUAL_RECEIPT_INVALID",
            Self::OutputTooLarge => "COUNTERFACTUAL_OUTPUT_TOO_LARGE",
            Self::OutputInvalid => "COUNTERFACTUAL_OUTPUT_INVALID",
            Self::ContextMismatch { .. } => "COUNTERFACTUAL_CONTEXT_MISMATCH",
        }
    }
}

impl fmt::Debug for CounterfactualIncidentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for CounterfactualIncidentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpectedBaselineInvalid => {
                "expected incident integrity hash must be canonical lowercase SHA-256"
            }
            Self::ExpectedBaselineMismatch => {
                "authenticated incident does not match the independently selected baseline"
            }
            Self::TrustPolicyInvalid => {
                "runtime-origin verification requires a separate original run authority"
            }
            Self::Baseline(_) => "baseline incident authentication failed",
            Self::Receipt(_) => "counterfactual receipt authentication failed",
            Self::OutputTooLarge => "counterfactual receipt exceeds its verification bounds",
            Self::OutputInvalid => "counterfactual receipt has an unsupported or invalid shape",
            Self::ContextMismatch { .. } => {
                "counterfactual receipt differs from its authenticated incident context"
            }
        })
    }
}

impl std::error::Error for CounterfactualIncidentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Baseline(error) => Some(error),
            Self::Receipt(error) => Some(error),
            _ => None,
        }
    }
}

/// Errors returned while verifying signed counterfactual replay receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterfactualReceiptError {
    Json(String),
    BaselineIntegrityHashMissing,
    BaselineIntegrityHashMalformed { actual: String },
    ResultsEnvelopeMalformed { actual: String },
    CounterfactualBundleHashMissing,
    CounterfactualBundleHashMalformed { actual: String },
    SweepResultBundleHashMissing { index: usize },
    SweepResultBundleHashMalformed { index: usize, actual: String },
    CounterfactualBundleHashMismatch { expected: String, actual: String },
    Signature(BundleError),
}

impl fmt::Display for CounterfactualReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => {
                write!(formatter, "counterfactual receipt JSON error: {message}")
            }
            Self::BaselineIntegrityHashMissing => {
                write!(formatter, "baseline bundle integrity_hash is missing")
            }
            Self::BaselineIntegrityHashMalformed { actual } => write!(
                formatter,
                "baseline bundle integrity_hash must be a 64-nybble hex digest: got {actual}"
            ),
            Self::ResultsEnvelopeMalformed { actual } => write!(
                formatter,
                "counterfactual receipt results must be a non-empty array when present: got {actual}"
            ),
            Self::CounterfactualBundleHashMissing => {
                write!(
                    formatter,
                    "counterfactual receipt metadata.bundle_hash is missing"
                )
            }
            Self::CounterfactualBundleHashMalformed { actual } => write!(
                formatter,
                "counterfactual receipt metadata.bundle_hash must be a 64-nybble hex digest: got {actual}"
            ),
            Self::SweepResultBundleHashMissing { index } => {
                write!(
                    formatter,
                    "counterfactual receipt results[{index}].metadata.bundle_hash is missing"
                )
            }
            Self::SweepResultBundleHashMalformed { index, actual } => write!(
                formatter,
                "counterfactual receipt results[{index}].metadata.bundle_hash must be a 64-nybble hex digest: got {actual}"
            ),
            Self::CounterfactualBundleHashMismatch { expected, actual } => write!(
                formatter,
                "counterfactual receipt bundle hash mismatch: expected {expected}, got {actual}"
            ),
            Self::Signature(source) => {
                write!(
                    formatter,
                    "counterfactual receipt signature invalid: {source}"
                )
            }
        }
    }
}

impl std::error::Error for CounterfactualReceiptError {}

/// Standard result type returned by counterfactual receipt verification.
pub type CounterfactualReceiptResult<T> = Result<T, CounterfactualReceiptError>;

/// Counterfactual capability decision emitted by a producing runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualCapabilityDecision {
    Allow,
    Deny,
}

impl CounterfactualCapabilityDecision {
    const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Capability attempt that an external verifier can replay without runtime access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterfactualCapabilityRequest {
    pub actor: String,
    pub audience: String,
    pub requested_scope: CapabilityScope,
    pub policy_profile: CapabilityPolicyProfile,
    pub epoch: u64,
    pub side_effect_kind: EffectKind,
    pub observed_postconditions: Vec<CapabilityPostcondition>,
}

/// Offline validation report for a counterfactual capability decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualCapabilityValidation {
    pub proof_id: String,
    pub proof_hash: String,
    pub actor: String,
    pub audience: String,
    pub scope: CapabilityScope,
    pub policy_profile: String,
    pub epoch: u64,
    pub side_effect_kind: String,
    pub decision: String,
    pub expected_decision: String,
    pub allowed: bool,
    pub reason: String,
    pub postcondition_count: usize,
}

/// Errors returned while replaying counterfactual capability decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterfactualCapabilityError {
    Proof(BundleError),
    DecisionMismatch {
        expected: String,
        actual: String,
        reason: String,
    },
}

impl fmt::Display for CounterfactualCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(source) => {
                write!(
                    formatter,
                    "counterfactual capability proof invalid: {source}"
                )
            }
            Self::DecisionMismatch {
                expected,
                actual,
                reason,
            } => write!(
                formatter,
                "counterfactual capability decision mismatch: expected {expected}, got {actual} ({reason})"
            ),
        }
    }
}

impl std::error::Error for CounterfactualCapabilityError {}

/// Standard result type returned by counterfactual capability validation.
pub type CounterfactualCapabilityResult<T> = Result<T, CounterfactualCapabilityError>;

/// Verify a signed counterfactual replay receipt.
///
/// `baseline_bundle` may be any serializable baseline bundle shape that carries
/// an `integrity_hash` field. `counterfactual_output` may be either a
/// `CounterfactualResult`-shaped object with `metadata.bundle_hash` or a sweep
/// output with `results[*].metadata.bundle_hash`. The Ed25519 signature covers
/// only the deterministic JSON bytes of `counterfactual_output`, matching
/// `tools::counterfactual_replay::to_canonical_json`.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::counterfactual::verify_counterfactual_receipt;
///
/// verify_counterfactual_receipt(
///     &baseline_bundle,
///     &counterfactual_output,
///     &verifying_key,
///     &signature_bytes,
/// )?;
/// ```
pub fn verify_counterfactual_receipt<B, O>(
    baseline_bundle: &B,
    counterfactual_output: &O,
    verifying_key: &VerifyingKey,
    signature_bytes: &[u8],
) -> CounterfactualReceiptResult<()>
where
    B: Serialize,
    O: Serialize,
{
    let baseline_value = to_value(baseline_bundle)?;
    let expected_bundle_hash = extract_nonempty_string(&baseline_value, &["integrity_hash"])
        .ok_or(CounterfactualReceiptError::BaselineIntegrityHashMissing)?;
    validate_bundle_hash(expected_bundle_hash)
        .map_err(|actual| CounterfactualReceiptError::BaselineIntegrityHashMalformed { actual })?;
    let counterfactual_value = to_value(counterfactual_output)?;
    ensure_counterfactual_references_bundle(&counterfactual_value, expected_bundle_hash)?;
    let canonical = canonical_json_bytes(&counterfactual_value)?;
    verify_ed25519_signature(verifying_key, &canonical, signature_bytes)
        .map_err(CounterfactualReceiptError::Signature)
}

/// Authenticate an independently selected incident and its counterfactual
/// receipt together. Unlike [`verify_counterfactual_receipt`], this verifies the
/// actual baseline bytes, requires an out-of-band baseline pin, and checks that
/// every signed result refers to that incident's full ordered event population,
/// original policy name and capture time.
///
/// Supplying an original run key or a product root opts into the corresponding
/// stronger incident verifier. Missing, malformed or foreign origin evidence
/// then fails; it never silently falls back to exporter-only authentication.
/// A product root without an original run key is invalid configuration.
///
/// This is authenticated attribution and structural binding, not execution of
/// JavaScript or independent recomputation of counterfactual decisions. It
/// preserves the narrower receipt-only API for other signed output shapes.
pub fn verify_counterfactual_incident(
    baseline_bytes: &[u8],
    counterfactual_output: &Value,
    signature_bytes: &[u8],
    trust: &CounterfactualIncidentTrust<'_>,
) -> Result<VerifiedCounterfactualIncident, CounterfactualIncidentError> {
    validate_bundle_hash(trust.expected_baseline_integrity_hash)
        .map_err(|_| CounterfactualIncidentError::ExpectedBaselineInvalid)?;
    if trust.trusted_product_root.is_some() && trust.trusted_run_signer.is_none() {
        return Err(CounterfactualIncidentError::TrustPolicyInvalid);
    }
    let (baseline, run_origin, runtime_origin) =
        match (trust.trusted_run_signer, trust.trusted_product_root) {
            (Some(run_key), Some(product_root)) => {
                let verified = verify_incident_bundle_with_runtime_keys(
                    baseline_bytes,
                    trust.trusted_bundle_signer,
                    run_key,
                    product_root,
                )
                .map_err(CounterfactualIncidentError::Baseline)?;
                (
                    verified.bundle,
                    Some(verified.run_origin),
                    Some(verified.runtime_origin),
                )
            }
            (Some(run_key), None) => {
                let verified = verify_incident_bundle_with_run_key(
                    baseline_bytes,
                    trust.trusted_bundle_signer,
                    run_key,
                )
                .map_err(CounterfactualIncidentError::Baseline)?;
                (verified.bundle, Some(verified.run_origin), None)
            }
            (None, _) => (
                verify_incident_bundle(baseline_bytes, trust.trusted_bundle_signer)
                    .map_err(CounterfactualIncidentError::Baseline)?,
                None,
                None,
            ),
        };
    if !constant_time_eq(
        &baseline.integrity_hash,
        trust.expected_baseline_integrity_hash,
    ) {
        return Err(CounterfactualIncidentError::ExpectedBaselineMismatch);
    }

    // Bound caller-created Values too: the Rust API must not rely on the CLI's
    // JSON decoder to limit nesting, node count or canonicalization allocation.
    validate_counterfactual_output_bounds(counterfactual_output)?;
    ensure_counterfactual_references_bundle(counterfactual_output, &baseline.integrity_hash)
        .map_err(CounterfactualIncidentError::Receipt)?;
    let canonical = canonical_json_bytes(counterfactual_output)
        .map_err(CounterfactualIncidentError::Receipt)?;
    verify_ed25519_signature(
        trust.trusted_counterfactual_signer,
        &canonical,
        signature_bytes,
    )
    .map_err(CounterfactualReceiptError::Signature)
    .map_err(CounterfactualIncidentError::Receipt)?;

    let baseline_value =
        decode_evidence_json(baseline_bytes).map_err(CounterfactualIncidentError::Baseline)?;
    let timeline = baseline_value["timeline"]
        .as_array()
        .ok_or(CounterfactualIncidentError::OutputInvalid)?;
    let (mode, result_count) = match counterfactual_output.get("results") {
        Some(Value::Array(results)) => {
            if results.is_empty() || results.len() > MAX_COUNTERFACTUAL_INCIDENT_RESULTS {
                return Err(CounterfactualIncidentError::OutputTooLarge);
            }
            let envelope = exact_counterfactual_object(
                counterfactual_output,
                &["mode", "parameter", "results"],
                &[],
            )?;
            if envelope["mode"].as_str() != Some("sweep")
                || !matches!(
                    envelope["parameter"].as_str(),
                    Some("quarantine_threshold" | "observe_threshold" | "degraded_mode_bias")
                )
            {
                return Err(CounterfactualIncidentError::OutputInvalid);
            }
            for result in results {
                bind_counterfactual_result(result, &baseline, timeline, false)?;
            }
            ("sweep", results.len())
        }
        None => {
            bind_counterfactual_result(counterfactual_output, &baseline, timeline, true)?;
            ("single", 1)
        }
        Some(_) => return Err(CounterfactualIncidentError::OutputInvalid),
    };
    Ok(VerifiedCounterfactualIncident {
        baseline,
        run_origin,
        runtime_origin,
        counterfactual_signer_public_key_hex: hex::encode(
            trust.trusted_counterfactual_signer.as_bytes(),
        ),
        counterfactual_output_sha256: hex::encode(Sha256::digest(&canonical)),
        mode,
        result_count,
        guest_execution_verified: false,
    })
}

fn validate_counterfactual_output_bounds(value: &Value) -> Result<(), CounterfactualIncidentError> {
    let mut pending = vec![(value, 0_usize)];
    let mut visited = 0_usize;
    while let Some((item, depth)) = pending.pop() {
        visited += 1;
        if depth > MAX_COUNTERFACTUAL_OUTPUT_DEPTH {
            return Err(CounterfactualIncidentError::OutputTooLarge);
        }
        let children = match item {
            Value::Array(values) => values.len(),
            Value::Object(values) => values.len(),
            _ => 0,
        };
        if children > MAX_COUNTERFACTUAL_OUTPUT_NODES.saturating_sub(visited + pending.len()) {
            return Err(CounterfactualIncidentError::OutputTooLarge);
        }
        match item {
            Value::Array(values) => pending.extend(values.iter().map(|item| (item, depth + 1))),
            Value::Object(values) => {
                pending.extend(values.values().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }

    struct SizeLimit(usize);
    impl std::io::Write for SizeLimit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_COUNTERFACTUAL_INCIDENT_OUTPUT_BYTES)
                .ok_or_else(|| std::io::Error::other("counterfactual byte bound exceeded"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Ordering does not change JSON length. Count escaped/encoded bytes before
    // cloning and sorting anything for signature canonicalization.
    serde_json::to_writer(SizeLimit(0), value)
        .map_err(|_| CounterfactualIncidentError::OutputTooLarge)
}

fn exact_counterfactual_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, CounterfactualIncidentError> {
    let object = value
        .as_object()
        .ok_or(CounterfactualIncidentError::OutputInvalid)?;
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(CounterfactualIncidentError::OutputInvalid);
    }
    Ok(object)
}

fn bind_counterfactual_result(
    result: &Value,
    baseline: &VerifiedIncidentBundle,
    timeline: &[Value],
    allow_mode: bool,
) -> Result<(), CounterfactualIncidentError> {
    let object = exact_counterfactual_object(
        result,
        &[
            "scenario_id",
            "original_outcomes",
            "counterfactual_outcomes",
            "divergence_points",
            "summary_statistics",
            "metadata",
        ],
        if allow_mode { &["mode"] } else { &[] },
    )?;
    if object
        .get("mode")
        .is_some_and(|value| value.as_str() != Some("single"))
    {
        return Err(CounterfactualIncidentError::OutputInvalid);
    }
    let context_error = |field| CounterfactualIncidentError::ContextMismatch { field };
    let metadata = exact_counterfactual_object(
        &object["metadata"],
        &[
            "bundle_hash",
            "policy_override_diff",
            "replay_timestamp",
            "engine_version",
            "invocation_event_codes",
        ],
        &[],
    )?;
    if metadata["replay_timestamp"].as_str() != Some(baseline.created_at.as_str()) {
        return Err(context_error("replay_timestamp"));
    }
    let overrides = metadata["policy_override_diff"]
        .as_array()
        .filter(|diffs| diffs.len() <= 32)
        .ok_or(CounterfactualIncidentError::OutputInvalid)?;
    let mut fields = std::collections::BTreeSet::new();
    let mut alternate_policy = baseline.policy_version.as_str();
    for override_value in overrides {
        let entry = exact_counterfactual_object(
            override_value,
            &["field", "original", "counterfactual"],
            &[],
        )?;
        let field = entry["field"]
            .as_str()
            .ok_or(CounterfactualIncidentError::OutputInvalid)?;
        if !matches!(
            field,
            "policy_name" | "quarantine_threshold" | "observe_threshold" | "degraded_mode_bias"
        ) || !fields.insert(field)
            || entry["original"].as_str().is_none()
            || entry["counterfactual"].as_str().is_none()
        {
            return Err(CounterfactualIncidentError::OutputInvalid);
        }
        if field == "policy_name" {
            if entry["original"].as_str() != Some(baseline.policy_version.as_str()) {
                return Err(context_error("policy_name"));
            }
            alternate_policy = entry["counterfactual"]
                .as_str()
                .filter(|name| !name.is_empty())
                .ok_or(CounterfactualIncidentError::OutputInvalid)?;
        }
    }
    let scenario = object["scenario_id"]
        .as_str()
        .ok_or(CounterfactualIncidentError::OutputInvalid)?;
    if scenario
        .strip_prefix(baseline.incident_id.as_str())
        .and_then(|suffix| suffix.strip_prefix("::"))
        != Some(alternate_policy)
    {
        return Err(context_error("scenario_id"));
    }
    for field in ["original_outcomes", "counterfactual_outcomes"] {
        let outcomes = object[field]
            .as_array()
            .ok_or(CounterfactualIncidentError::OutputInvalid)?;
        if outcomes.len() != timeline.len() {
            return Err(context_error(field));
        }
        for (outcome, event) in outcomes.iter().zip(timeline) {
            let outcome = exact_counterfactual_object(
                outcome,
                &[
                    "sequence_number",
                    "event_type",
                    "decision",
                    "rationale",
                    "expected_loss",
                ],
                &["recorded_effects"],
            )?;
            if outcome.get("sequence_number") != event.get("sequence_number")
                || outcome.get("event_type") != event.get("event_type")
            {
                return Err(context_error(field));
            }
            if outcome["decision"].as_str().is_none_or(str::is_empty)
                || outcome["rationale"].as_str().is_none()
                || outcome["expected_loss"].as_u64().is_none()
                || outcome
                    .get("recorded_effects")
                    .is_some_and(|value| !value.is_array())
            {
                return Err(CounterfactualIncidentError::OutputInvalid);
            }
        }
    }
    let statistics = exact_counterfactual_object(
        &object["summary_statistics"],
        &["total_decisions", "changed_decisions", "severity_delta"],
        &[],
    )?;
    let total = statistics["total_decisions"].as_u64();
    if total != u64::try_from(timeline.len()).ok() {
        return Err(context_error("total_decisions"));
    }
    if statistics["changed_decisions"]
        .as_u64()
        .is_none_or(|changed| total.is_none_or(|total| changed > total))
        || statistics["severity_delta"].as_i64().is_none()
    {
        return Err(CounterfactualIncidentError::OutputInvalid);
    }
    if !object["divergence_points"].is_array()
        || metadata["engine_version"]
            .as_str()
            .is_none_or(str::is_empty)
        || metadata["invocation_event_codes"]
            .as_array()
            .is_none_or(|codes| codes.iter().any(|code| code.as_str().is_none()))
    {
        return Err(CounterfactualIncidentError::OutputInvalid);
    }
    Ok(())
}

/// Replay a capability allow/deny decision against an independently checkable proof.
pub fn validate_counterfactual_capability_decision(
    proof: &CapabilityProof,
    request: &CounterfactualCapabilityRequest,
    decision: CounterfactualCapabilityDecision,
) -> CounterfactualCapabilityResult<CounterfactualCapabilityValidation> {
    let proof_hash =
        verify_capability_proof_schema(proof).map_err(CounterfactualCapabilityError::Proof)?;
    let denial_reason = counterfactual_capability_denial_reason(proof, request);
    let expected_decision = if denial_reason.is_some() {
        CounterfactualCapabilityDecision::Deny
    } else {
        CounterfactualCapabilityDecision::Allow
    };
    let reason =
        denial_reason.unwrap_or_else(|| "proof and request bindings permit capability".to_string());

    if decision != expected_decision {
        return Err(CounterfactualCapabilityError::DecisionMismatch {
            expected: expected_decision.label().to_string(),
            actual: decision.label().to_string(),
            reason,
        });
    }

    Ok(CounterfactualCapabilityValidation {
        proof_id: proof.proof_id.clone(),
        proof_hash,
        actor: request.actor.clone(),
        audience: request.audience.clone(),
        scope: request.requested_scope.clone(),
        policy_profile: capability_policy_profile_label(request.policy_profile).to_string(),
        epoch: request.epoch,
        side_effect_kind: effect_kind_label(request.side_effect_kind).to_string(),
        decision: decision.label().to_string(),
        expected_decision: expected_decision.label().to_string(),
        allowed: decision == CounterfactualCapabilityDecision::Allow,
        reason,
        postcondition_count: request.observed_postconditions.len(),
    })
}

fn counterfactual_capability_denial_reason(
    proof: &CapabilityProof,
    request: &CounterfactualCapabilityRequest,
) -> Option<String> {
    if !matches!(
        proof.revocation_freshness,
        CapabilityRevocationFreshness::Fresh { .. }
    ) {
        return Some("capability proof lacks fresh revocation evidence".to_string());
    }
    if !constant_time_eq(&proof.actor, &request.actor) {
        return Some("actor binding mismatch".to_string());
    }
    if !constant_time_eq(&proof.audience, &request.audience) {
        return Some("audience binding mismatch".to_string());
    }
    if proof.policy_profile != request.policy_profile {
        return Some("policy profile binding mismatch".to_string());
    }
    if proof.epoch != request.epoch {
        return Some("epoch binding mismatch".to_string());
    }
    if proof.side_effect_kind != request.side_effect_kind {
        return Some("side effect kind binding mismatch".to_string());
    }
    if !proof.scopes.contains(&request.requested_scope) {
        return Some("requested scope is outside capability proof".to_string());
    }
    if proof.expected_postconditions != request.observed_postconditions {
        return Some("observed postconditions do not match proof".to_string());
    }
    None
}

fn capability_policy_profile_label(profile: CapabilityPolicyProfile) -> &'static str {
    match profile {
        CapabilityPolicyProfile::Strict => "strict",
        CapabilityPolicyProfile::Balanced => "balanced",
        CapabilityPolicyProfile::LegacyRisky => "legacy_risky",
    }
}

fn effect_kind_label(kind: EffectKind) -> &'static str {
    match kind {
        EffectKind::FsRead => "fs_read",
        EffectKind::FsWrite => "fs_write",
        EffectKind::NetConnect => "net_connect",
        EffectKind::HttpRequest => "http_request",
        EffectKind::Spawn => "spawn",
        EffectKind::ModuleResolve => "module_resolve",
        EffectKind::RandomRead => "random_read",
        EffectKind::EnvRead => "env_read",
    }
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, CounterfactualReceiptError> {
    serde_json::to_value(value)
        .map_err(|source| CounterfactualReceiptError::Json(source.to_string()))
}

fn ensure_counterfactual_references_bundle(
    output: &Value,
    expected_bundle_hash: &str,
) -> Result<(), CounterfactualReceiptError> {
    if let Some(results_value) = output.get("results") {
        let results = results_value.as_array().ok_or_else(|| {
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: describe_value_kind(results_value),
            }
        })?;
        if results.is_empty() {
            return Err(CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "array(len=0)".to_string(),
            });
        }
        if let Some(actual_value) = extract_value(output, &["metadata", "bundle_hash"]) {
            let actual = actual_value.as_str().ok_or_else(|| {
                CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                    actual: describe_value_kind(actual_value),
                }
            })?;
            if actual.trim().is_empty() {
                return Err(
                    CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                        actual: actual.to_string(),
                    },
                );
            }
            validate_bundle_hash(actual).map_err(|actual| {
                CounterfactualReceiptError::CounterfactualBundleHashMalformed { actual }
            })?;
            if !constant_time_eq(actual, expected_bundle_hash) {
                return Err(
                    CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                        expected: expected_bundle_hash.to_string(),
                        actual: actual.to_string(),
                    },
                );
            }
        }
        for (index, result) in results.iter().enumerate() {
            let actual = extract_nonempty_string(result, &["metadata", "bundle_hash"])
                .ok_or(CounterfactualReceiptError::SweepResultBundleHashMissing { index })?;
            validate_bundle_hash(actual).map_err(|actual| {
                CounterfactualReceiptError::SweepResultBundleHashMalformed { index, actual }
            })?;
            if !constant_time_eq(actual, expected_bundle_hash) {
                return Err(
                    CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                        expected: expected_bundle_hash.to_string(),
                        actual: actual.to_string(),
                    },
                );
            }
        }
        return Ok(());
    }

    let actual = extract_nonempty_string(output, &["metadata", "bundle_hash"])
        .ok_or(CounterfactualReceiptError::CounterfactualBundleHashMissing)?;
    validate_bundle_hash(actual).map_err(|actual| {
        CounterfactualReceiptError::CounterfactualBundleHashMalformed { actual }
    })?;
    if !constant_time_eq(actual, expected_bundle_hash) {
        return Err(
            CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                expected: expected_bundle_hash.to_string(),
                actual: actual.to_string(),
            },
        );
    }
    Ok(())
}

fn extract_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cursor = value;
    for segment in path {
        cursor = cursor.get(*segment)?;
    }
    Some(cursor)
}

fn describe_value_kind(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => format!("bool({boolean})"),
        Value::Number(number) => format!("number({number})"),
        Value::String(string) => format!("string({string})"),
        Value::Array(items) => format!("array(len={})", items.len()),
        Value::Object(object) => format!("object(len={})", object.len()),
    }
}

fn extract_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    extract_value(value, path)?.as_str()
}

fn extract_nonempty_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let value = extract_string(value, path)?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn validate_bundle_hash(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(value.to_string())
    }
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, CounterfactualReceiptError> {
    let canonical = canonicalize_json(value);
    serde_json::to_vec(&canonical)
        .map_err(|source| CounterfactualReceiptError::Json(source.to_string()))
}

pub fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                if let Some(value) = map.get(key) {
                    out.insert(key.to_string(), canonicalize_json(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const TEST_BUNDLE_HASH: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn sign_counterfactual_value(value: &Value, signing_key: &SigningKey) -> Vec<u8> {
        let canonical = canonical_json_bytes(value).expect("test canonical JSON should serialize");
        signing_key.sign(&canonical).to_bytes().to_vec()
    }

    const INCIDENT_FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle");
    const RUN_INCIDENT_FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/run_origin_protocol/producer-run.fnbundle");

    fn incident_key() -> VerifyingKey {
        let mut key = [0; 32];
        hex::decode_to_slice(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            &mut key,
        )
        .unwrap();
        VerifyingKey::from_bytes(&key).unwrap()
    }

    // These are signed assessment protocol vectors over the existing real CLI
    // fixture, not claims of running its guest or recomputing a policy model.
    fn incident_output(bytes: &[u8]) -> Value {
        let baseline: Value = serde_json::from_slice(bytes).unwrap();
        let outcomes: Vec<Value> = baseline["timeline"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                json!({
                    "sequence_number": event["sequence_number"],
                    "event_type": event["event_type"],
                    "decision": "allow",
                    "rationale": "signed assessment; guest not executed",
                    "expected_loss": 0,
                })
            })
            .collect();
        json!({
            "mode": "single",
            "scenario_id": format!("{}::{}", baseline["incident_id"].as_str().unwrap(), baseline["policy_version"].as_str().unwrap()),
            "original_outcomes": outcomes,
            "counterfactual_outcomes": outcomes,
            "divergence_points": [],
            "summary_statistics": {
                "total_decisions": baseline["timeline"].as_array().unwrap().len(),
                "changed_decisions": 0,
                "severity_delta": 0,
            },
            "metadata": {
                "bundle_hash": baseline["integrity_hash"],
                "policy_override_diff": [],
                "replay_timestamp": baseline["created_at"],
                "engine_version": "counterfactual-v1",
                "invocation_event_codes": ["COUNTERFACTUAL_REPLAY_STARTED", "COUNTERFACTUAL_REPLAY_COMPLETED"],
            },
        })
    }

    fn incident_trust<'a>(
        pin: &'a str,
        receipt_key: &'a VerifyingKey,
        exporter: &'a VerifyingKey,
    ) -> CounterfactualIncidentTrust<'a> {
        CounterfactualIncidentTrust {
            expected_baseline_integrity_hash: pin,
            trusted_counterfactual_signer: receipt_key,
            trusted_bundle_signer: exporter,
            trusted_run_signer: None,
            trusted_product_root: None,
        }
    }

    fn reseal_incident_for_substitution(value: &mut Value) -> Vec<u8> {
        use crate::incident_bundle::{
            incident_bundle_canonical_digest, incident_bundle_signature_payload,
        };
        let mut view = value.as_object().unwrap().clone();
        view.remove("signature");
        view.remove("integrity_hash");
        let hash =
            incident_bundle_canonical_digest(&Value::Object(view), "$.integrity_view").unwrap();
        let payload = incident_bundle_signature_payload(&hash);
        let mut seed = [0; 32];
        hex::decode_to_slice(
            include_str!("../tests/fixtures/cli_incident_bundle/rfc8032_test1_seed.hex").trim(),
            &mut seed,
        )
        .unwrap();
        let exporter = SigningKey::from_bytes(&seed);
        value["integrity_hash"] = json!(hash);
        value["signature"]["signed_payload_sha256"] = json!(hex::encode(Sha256::digest(&payload)));
        value["signature"]["signature_hex"] =
            json!(hex::encode(exporter.sign(&payload).to_bytes()));
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn counterfactual_incident_authenticates_real_baseline_and_independent_receipt() {
        let output = incident_output(INCIDENT_FIXTURE);
        let receipt = SigningKey::from_bytes(&[0x73; 32]);
        let receipt_key = receipt.verifying_key();
        let exporter = incident_key();
        let pin = output["metadata"]["bundle_hash"].as_str().unwrap();
        let trust = incident_trust(pin, &receipt_key, &exporter);
        let signature = sign_counterfactual_value(&output, &receipt);
        let verified =
            verify_counterfactual_incident(INCIDENT_FIXTURE, &output, &signature, &trust).unwrap();
        assert_eq!(verified.baseline.incident_id, "INC-SDK-FIXTURE-1");
        assert_eq!(verified.baseline.integrity_hash, pin);
        assert_eq!(verified.baseline.event_count, 3);
        assert_eq!((verified.mode, verified.result_count), ("single", 1));
        assert_eq!(
            verified.counterfactual_output_sha256,
            hex::encode(Sha256::digest(canonical_json_bytes(&output).unwrap()))
        );
        assert_eq!(
            verified.counterfactual_signer_public_key_hex,
            hex::encode(receipt_key.as_bytes())
        );
        assert_ne!(
            verified.counterfactual_signer_public_key_hex,
            verified.baseline.signer_public_key_hex
        );
        assert!(verified.run_origin.is_none() && verified.runtime_origin.is_none());
        assert!(!verified.guest_execution_verified);

        let mut result = output.clone();
        result.as_object_mut().unwrap().remove("mode");
        let sweep = json!({"mode":"sweep", "parameter":"observe_threshold", "results":[result.clone(), result]});
        let verified = verify_counterfactual_incident(
            INCIDENT_FIXTURE,
            &sweep,
            &sign_counterfactual_value(&sweep, &receipt),
            &trust,
        )
        .unwrap();
        assert_eq!((verified.mode, verified.result_count), ("sweep", 2));
        assert!(!verified.guest_execution_verified);
    }

    #[test]
    fn counterfactual_incident_rejects_another_valid_baseline_despite_matching_receipt() {
        let original = incident_output(INCIDENT_FIXTURE);
        let pin = original["metadata"]["bundle_hash"].as_str().unwrap();
        let mut replacement: Value = serde_json::from_slice(INCIDENT_FIXTURE).unwrap();
        replacement["evidence_refs"] = json!(["different-authenticated-evidence"]);
        let replacement_bytes = reseal_incident_for_substitution(&mut replacement);
        verify_incident_bundle(&replacement_bytes, &incident_key()).unwrap();
        let output = incident_output(&replacement_bytes);
        let receipt = SigningKey::from_bytes(&[0x74; 32]);
        let receipt_key = receipt.verifying_key();
        let exporter = incident_key();
        let signature = sign_counterfactual_value(&output, &receipt);
        // The legacy signature-only API correctly accepts this receipt. The
        // independently retained pin must still refuse the substituted pair.
        verify_counterfactual_receipt(&replacement, &output, &receipt_key, &signature).unwrap();
        assert_eq!(
            verify_counterfactual_incident(
                &replacement_bytes,
                &output,
                &signature,
                &incident_trust(pin, &receipt_key, &exporter),
            ),
            Err(CounterfactualIncidentError::ExpectedBaselineMismatch)
        );
    }

    #[test]
    fn counterfactual_incident_rejects_forged_baseline_and_foreign_authorities() {
        let output = incident_output(INCIDENT_FIXTURE);
        let pin = output["metadata"]["bundle_hash"].as_str().unwrap();
        let receipt = SigningKey::from_bytes(&[0x75; 32]);
        let receipt_key = receipt.verifying_key();
        let exporter = incident_key();
        let trust = incident_trust(pin, &receipt_key, &exporter);
        let signature = sign_counterfactual_value(&output, &receipt);
        let original: Value = serde_json::from_slice(INCIDENT_FIXTURE).unwrap();
        for mutation in 0..3 {
            let mut candidate = original.clone();
            match mutation {
                0 => candidate["timeline"][0]["payload"] = json!({"PRIVATE-source":"changed"}),
                1 => {
                    candidate.as_object_mut().unwrap().remove("signature");
                }
                _ => candidate["signature"]["signature_hex"] = json!("0".repeat(128)),
            }
            let failure = verify_counterfactual_incident(
                &serde_json::to_vec(&candidate).unwrap(),
                &output,
                &signature,
                &trust,
            )
            .unwrap_err();
            assert!(matches!(failure, CounterfactualIncidentError::Baseline(_)));
            assert!(!format!("{failure:?}: {failure}").contains("PRIVATE-source"));
        }
        let foreign = SigningKey::from_bytes(&[0x76; 32]);
        let foreign_key = foreign.verifying_key();
        assert!(matches!(
            verify_counterfactual_incident(
                INCIDENT_FIXTURE,
                &output,
                &signature,
                &incident_trust(pin, &receipt_key, &foreign_key),
            ),
            Err(CounterfactualIncidentError::Baseline(
                IncidentBundleError::SignerNotTrusted
            ))
        ));
        assert!(matches!(
            verify_counterfactual_incident(
                INCIDENT_FIXTURE,
                &output,
                &sign_counterfactual_value(&output, &foreign),
                &trust,
            ),
            Err(CounterfactualIncidentError::Receipt(
                CounterfactualReceiptError::Signature(_)
            ))
        ));
    }

    #[test]
    fn counterfactual_incident_binds_signed_policy_time_and_complete_ordered_events() {
        let output = incident_output(INCIDENT_FIXTURE);
        let pin = output["metadata"]["bundle_hash"].as_str().unwrap();
        let receipt = SigningKey::from_bytes(&[0x77; 32]);
        let receipt_key = receipt.verifying_key();
        let exporter = incident_key();
        let trust = incident_trust(pin, &receipt_key, &exporter);
        for mutation in 0..8 {
            let mut candidate = output.clone();
            match mutation {
                0 => candidate["scenario_id"] = json!("other-incident::policy"),
                1 => candidate["metadata"]["replay_timestamp"] = json!("1970-01-01T00:00:00Z"),
                2 => {
                    candidate["metadata"]["policy_override_diff"] = json!([{
                        "field":"policy_name", "original":"foreign-original-policy", "counterfactual":"strict",
                    }])
                }
                3 => candidate["original_outcomes"]
                    .as_array_mut()
                    .unwrap()
                    .swap(0, 1),
                4 => {
                    candidate["counterfactual_outcomes"]
                        .as_array_mut()
                        .unwrap()
                        .pop();
                }
                5 => candidate["original_outcomes"][0]["event_type"] = json!("unknown_event"),
                6 => candidate["summary_statistics"]["total_decisions"] = json!(0),
                _ => candidate["counterfactual_outcomes"][0]["sequence_number"] = json!(u64::MAX),
            }
            let signature = sign_counterfactual_value(&candidate, &receipt);
            // Every candidate has a genuine signature. These failures must
            // come from cross-binding, not from incidental signature damage.
            assert!(
                matches!(
                    verify_counterfactual_incident(
                        INCIDENT_FIXTURE,
                        &candidate,
                        &signature,
                        &trust
                    ),
                    Err(CounterfactualIncidentError::ContextMismatch { .. })
                ),
                "mutation {mutation}"
            );
        }
        let mut altered = output.clone();
        altered["original_outcomes"][0]["rationale"] = json!("unsigned change");
        assert!(matches!(
            verify_counterfactual_incident(
                INCIDENT_FIXTURE,
                &altered,
                &sign_counterfactual_value(&output, &receipt),
                &trust,
            ),
            Err(CounterfactualIncidentError::Receipt(
                CounterfactualReceiptError::Signature(_)
            ))
        ));
    }

    #[test]
    fn counterfactual_incident_origin_requirements_never_silently_downgrade() {
        let output = incident_output(RUN_INCIDENT_FIXTURE);
        let pin = output["metadata"]["bundle_hash"].as_str().unwrap();
        let receipt = SigningKey::from_bytes(&[0x78; 32]);
        let receipt_key = receipt.verifying_key();
        let exporter = incident_key();
        let mut bytes = [0; 32];
        hex::decode_to_slice(
            include_str!("../tests/fixtures/run_origin_protocol/run-authority.pub").trim(),
            &mut bytes,
        )
        .unwrap();
        let run_key = VerifyingKey::from_bytes(&bytes).unwrap();
        let mut trust = incident_trust(pin, &receipt_key, &exporter);
        trust.trusted_run_signer = Some(&run_key);
        let signature = sign_counterfactual_value(&output, &receipt);
        let verified =
            verify_counterfactual_incident(RUN_INCIDENT_FIXTURE, &output, &signature, &trust)
                .unwrap();
        assert_eq!(
            verified.run_origin.unwrap().signer_public_key_hex,
            hex::encode(run_key.as_bytes())
        );
        assert!(verified.runtime_origin.is_none());
        assert!(!verified.guest_execution_verified);

        let foreign = SigningKey::from_bytes(&[0x79; 32]).verifying_key();
        trust.trusted_run_signer = Some(&foreign);
        assert!(matches!(
            verify_counterfactual_incident(RUN_INCIDENT_FIXTURE, &output, &signature, &trust),
            Err(CounterfactualIncidentError::Baseline(_))
        ));
        trust.trusted_run_signer = Some(&run_key);
        trust.trusted_product_root = Some(&foreign);
        assert!(matches!(
            verify_counterfactual_incident(RUN_INCIDENT_FIXTURE, &output, &signature, &trust),
            Err(CounterfactualIncidentError::Baseline(
                IncidentBundleError::RuntimeOriginMissing
            ))
        ));
        trust.trusted_run_signer = None;
        assert_eq!(
            verify_counterfactual_incident(RUN_INCIDENT_FIXTURE, &output, &signature, &trust),
            Err(CounterfactualIncidentError::TrustPolicyInvalid)
        );
    }

    #[test]
    fn counterfactual_incident_rejects_malformed_pins_before_candidate_processing() {
        let receipt_key = SigningKey::from_bytes(&[0x7a; 32]).verifying_key();
        let exporter = incident_key();
        for pin in ["", "PRIVATE-invalid-pin", &"A".repeat(64), &"0".repeat(63)] {
            let error = verify_counterfactual_incident(
                b"invalid JSON",
                &Value::Null,
                &[],
                &incident_trust(pin, &receipt_key, &exporter),
            )
            .unwrap_err();
            assert_eq!(error, CounterfactualIncidentError::ExpectedBaselineInvalid);
            assert!(!format!("{error:?}: {error}").contains("PRIVATE-invalid-pin"));
        }
    }

    #[test]
    fn counterfactual_incident_bounds_sweeps_and_rejects_mixed_baselines() {
        let output = incident_output(INCIDENT_FIXTURE);
        let pin = output["metadata"]["bundle_hash"].as_str().unwrap();
        let receipt = SigningKey::from_bytes(&[0x7b; 32]);
        let receipt_key = receipt.verifying_key();
        let exporter = incident_key();
        let trust = incident_trust(pin, &receipt_key, &exporter);
        let mut result = output.clone();
        result.as_object_mut().unwrap().remove("mode");
        let oversized = json!({
            "mode":"sweep", "parameter":"observe_threshold", "results":vec![result.clone(); 21],
        });
        assert_eq!(
            verify_counterfactual_incident(
                INCIDENT_FIXTURE,
                &oversized,
                &sign_counterfactual_value(&oversized, &receipt),
                &trust,
            ),
            Err(CounterfactualIncidentError::OutputTooLarge)
        );
        let mut foreign = result.clone();
        foreign["metadata"]["bundle_hash"] = json!("0".repeat(64));
        let mixed =
            json!({"mode":"sweep", "parameter":"observe_threshold", "results":[result, foreign]});
        assert!(matches!(
            verify_counterfactual_incident(
                INCIDENT_FIXTURE,
                &mixed,
                &sign_counterfactual_value(&mixed, &receipt),
                &trust,
            ),
            Err(CounterfactualIncidentError::Receipt(
                CounterfactualReceiptError::CounterfactualBundleHashMismatch { .. }
            ))
        ));
    }

    #[test]
    fn counterfactual_incident_bounds_deep_values_and_escaped_serialization_before_cloning() {
        let mut deep = Value::Null;
        for _ in 0..=MAX_COUNTERFACTUAL_OUTPUT_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        assert_eq!(
            validate_counterfactual_output_bounds(&deep),
            Err(CounterfactualIncidentError::OutputTooLarge)
        );
        // Input text fits under 12 MiB, but escaped JSON exceeds 64 MiB. The
        // size preflight counts its encoded bytes without allocating that JSON.
        let escaped = Value::String("\0".repeat(MAX_COUNTERFACTUAL_INCIDENT_OUTPUT_BYTES / 6 + 1));
        assert_eq!(
            validate_counterfactual_output_bounds(&escaped),
            Err(CounterfactualIncidentError::OutputTooLarge)
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_sweep_result_missing_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("sweep result missing bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMissing { index: 1 }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_accepts_sweep_when_all_results_match_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[8_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect("sweep with matching bundle_hash on every result should verify");
    }

    #[test]
    fn verify_counterfactual_receipt_accepts_matching_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[26_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect("matching top-level bundle_hash should verify for sweep receipts");
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_conflicting_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let conflicting_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": conflicting_hash}
        });
        let signing_key = SigningKey::from_bytes(&[27_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("conflicting top-level bundle_hash must fail closed for sweep receipts");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                expected: TEST_BUNDLE_HASH.to_string(),
                actual: conflicting_hash.to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": "   "}
        });
        let signing_key = SigningKey::from_bytes(&[28_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty top-level bundle_hash must fail closed for sweep receipts");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: "   ".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_non_string_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": 7}
        });
        let signing_key = SigningKey::from_bytes(&[29_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("non-string top-level bundle_hash must fail closed for sweep receipts");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: "number(7)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_object_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("object results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "object(len=1)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_string_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": "not-an-array",
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[22_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("string results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "string(not-an-array)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_null_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": Value::Null,
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("null results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "null".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [],
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[24_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "array(len=0)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_baseline_integrity_hash() {
        let baseline_bundle = json!({"integrity_hash": "   "});
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMissing
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_counterfactual_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": "   "}
        });
        let signing_key = SigningKey::from_bytes(&[10_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMissing
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_sweep_result_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": "  "}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMissing { index: 1 }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_malformed_baseline_integrity_hash() {
        let baseline_bundle = json!({"integrity_hash": "not-a-hash"});
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
        });
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("malformed baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMalformed {
                actual: "not-a-hash".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_whitespace_padded_baseline_integrity_hash() {
        let baseline_bundle = json!({
            "integrity_hash": format!(" {TEST_BUNDLE_HASH} ")
        });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[15_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("whitespace-padded baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMalformed {
                actual: format!(" {TEST_BUNDLE_HASH} "),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_uppercase_baseline_integrity_hash() {
        let baseline_bundle = json!({
            "integrity_hash": TEST_BUNDLE_HASH.to_uppercase()
        });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[18_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("uppercase baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMalformed {
                actual: TEST_BUNDLE_HASH.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_malformed_counterfactual_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": "bad-hash"}
        });
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("malformed signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: "bad-hash".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_whitespace_padded_counterfactual_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": format!(" {TEST_BUNDLE_HASH} ")}
        });
        let signing_key = SigningKey::from_bytes(&[16_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("whitespace-padded signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: format!(" {TEST_BUNDLE_HASH} "),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_uppercase_counterfactual_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH.to_uppercase()}
        });
        let signing_key = SigningKey::from_bytes(&[19_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("uppercase signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: TEST_BUNDLE_HASH.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_malformed_sweep_result_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": "still-not-a-hash"}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[14_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("malformed sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMalformed {
                index: 1,
                actual: "still-not-a-hash".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_uppercase_sweep_result_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH.to_uppercase()}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[20_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("uppercase sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMalformed {
                index: 1,
                actual: TEST_BUNDLE_HASH.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_whitespace_padded_sweep_result_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": format!(" {TEST_BUNDLE_HASH} ")}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("whitespace-padded sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMalformed {
                index: 1,
                actual: format!(" {TEST_BUNDLE_HASH} "),
            }
        );
    }
}
