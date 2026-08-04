use anyhow::{Context, Result};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const CLOSE_CONDITION_RECEIPT_PATH: &str = "artifacts/oracle/close_condition_receipt.json";
const COMPATIBILITY_CORPUS_RESULTS_PATH: &str = "artifacts/13/compatibility_corpus_results.json";
const L1_PROOF_CARRYING_EFFECTS_PATH: &str = "proof_carrying_effects";
/// Acceptance invariant (bd-f5b04.2.4): every canonical first-tranche
/// operation must be BOTH parity-GREEN AND proof-carrying before L1 may
/// report GREEN. The subject list is owned by `schema_versions` so this
/// gate, the `api::compat_gate` contract layer (feature-gated behind
/// `control-plane`), and the Python CI mirror cannot drift independently.
const REQUIRED_L1_PROOF_CARRYING_EFFECT_SUBJECTS: &[&str] =
    crate::schema_versions::L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS;
const REQUIRED_L1_PROOF_CARRYING_EFFECT_RECEIPT_COUNT: u64 =
    REQUIRED_L1_PROOF_CARRYING_EFFECT_SUBJECTS.len() as u64;
const SECTION_10N_GATE_VERDICT_PATH: &str =
    "artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json";
/// bd-ry7d1: the L1 product verdict artifact — the SAME file the Python CI
/// gate (`scripts/check_oracle_close_condition.py`) reads. The Rust gate
/// consumes it too, so the two gates can no longer enforce the dual-oracle
/// close condition over disjoint input sets.
const L1_PRODUCT_VERDICT_PATH: &str = "artifacts/oracle/l1_product_verdict.json";
/// bd-ihusm: the only corpus provenance the L1 ship-gate accepts. A corpus
/// whose `corpus.provenance` is anything else (or absent) is treated as
/// unmeasured evidence and fails closed — synthesized/authored results can
/// never be consumed as a genuine compatibility pass rate.
pub const COMPATIBILITY_CORPUS_ONLINE_PROVENANCE: &str = "lockstep-oracle-run";
const CCG_RESULT_DIGEST_DOMAIN: &[u8] = b"ccg_corpus_result_digest_v1:";
const CLOSE_CONDITION_TIMESTAMP_ENV: &str = "FRANKEN_NODE_CLOSE_CONDITION_TIMESTAMP_UTC";
pub const MAX_CLOSE_CONDITION_CARGO_FILES: usize = 256;
pub const MAX_CLOSE_CONDITION_SCAN_FILES: usize = 4_096;
const CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN: &[u8] = b"close_condition_receipt_v1:";

/// Stable event codes for the acceptance-bar (dual-oracle close-condition)
/// gate. SIEM filters and CI log scrapers pin on these codes, not message
/// text; the code set only grows, existing codes never change meaning.
pub mod event_codes {
    /// The acceptance-bar gate was evaluated over all oracle dimensions.
    pub const ACCEPTANCE_GATE_EVALUATED: &str = "FN-ACCEPT-001";
    /// PASS: every dimension is GREEN — parity (lockstep) AND proof-carrying
    /// host-effect evidence both verified, plus the engine-boundary and
    /// release-policy dimensions.
    pub const ACCEPTANCE_GATE_PASS: &str = "FN-ACCEPT-002";
    /// FAIL-CLOSED: at least one dimension is RED; the composite verdict
    /// refuses. Parity-GREEN-but-unproven and proven-but-parity-RED both
    /// land here.
    pub const ACCEPTANCE_GATE_FAIL_CLOSED: &str = "FN-ACCEPT-003";
    /// One blocking finding behind a FAIL-CLOSED verdict (emitted once per
    /// finding, prefixed with the owning dimension).
    pub const ACCEPTANCE_GATE_BLOCKING_FINDING: &str = "FN-ACCEPT-004";
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OracleColor {
    Green,
    Red,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct L1ProductOracle {
    pub verdict: OracleColor,
    pub source_path: String,
    pub corpus_version: Option<String>,
    /// bd-ihusm: how the corpus results were produced. Surfaced so a consumer
    /// can see at a glance whether the pass rate came from a genuine oracle
    /// run or from authored/synthesized fixtures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_provenance: Option<String>,
    pub total_test_cases: u64,
    pub passed_test_cases: u64,
    pub failed_test_cases: u64,
    pub errored_test_cases: u64,
    pub skipped_test_cases: u64,
    pub pass_rate_pct: f64,
    pub required_pass_rate_pct: f64,
    pub blocking_findings: Vec<String>,
}

/// Recompute the canonical content digest over a corpus's per-test results.
/// Both this gate and `scripts/check_compatibility_corpus_pass_gate.py` derive
/// the SAME bytes (domain-separated, field-separated, sorted) so a fabricated
/// or silently-edited `result_digest` fails closed.
pub fn compute_compatibility_corpus_result_digest(per_test_results: &[Value]) -> String {
    let mut rows: Vec<[String; 5]> = per_test_results
        .iter()
        .map(|row| {
            [
                get_str(row, &["test_id"]).unwrap_or_default().to_string(),
                get_str(row, &["api_family"])
                    .unwrap_or_default()
                    .to_string(),
                get_str(row, &["band"]).unwrap_or_default().to_string(),
                get_str(row, &["risk_band"]).unwrap_or_default().to_string(),
                get_str(row, &["status"]).unwrap_or_default().to_string(),
            ]
        })
        .collect();
    rows.sort();
    let mut hasher = Sha256::new();
    hasher.update(CCG_RESULT_DIGEST_DOMAIN);
    for row in &rows {
        for field in row {
            hasher.update(field.as_bytes());
            hasher.update([0x1f]);
        }
        hasher.update([0x1e]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SplitContractCheck {
    pub id: String,
    pub status: OracleColor,
    pub details: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct L2EngineBoundaryOracle {
    pub verdict: OracleColor,
    pub source: String,
    pub contract_ref: String,
    pub checks: Vec<SplitContractCheck>,
    pub summary: SplitContractSummary,
    pub blocking_findings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SplitContractSummary {
    pub total_checks: usize,
    pub passing_checks: usize,
    pub failing_checks: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleasePolicyLinkage {
    pub verdict: OracleColor,
    pub source: String,
    pub ci_outputs_accessible: bool,
    pub ci_output_ref: Option<String>,
    pub consumed_oracles: Vec<String>,
    pub blocking_findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleasePolicyLinkageError {
    #[error("release-policy CI output not accessible: {detail}")]
    CiOutputNotAccessible { detail: String },
}

#[derive(Debug, thiserror::Error)]
enum CloseConditionScanError {
    #[error("{scan_kind} scan exceeded limit {limit} while visiting {path}")]
    LimitExceeded {
        scan_kind: &'static str,
        limit: usize,
        path: String,
    },
    #[error(transparent)]
    Walk(#[from] anyhow::Error),
}

pub struct CloseConditionSigningMaterial<'a> {
    pub signing_key: &'a ed25519_dalek::SigningKey,
    pub key_source: &'a str,
    pub signing_identity: &'a str,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CloseConditionReceiptSignature {
    pub algorithm: String,
    pub public_key_hex: String,
    pub key_id: String,
    pub key_source: String,
    pub signing_identity: String,
    pub trust_scope: String,
    pub signed_payload_sha256: String,
    pub signature_hex: String,
}

impl std::fmt::Debug for CloseConditionReceiptSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloseConditionReceiptSignature")
            .field("algorithm", &self.algorithm)
            .field("public_key_hex", &self.public_key_hex)
            .field("key_id", &self.key_id)
            .field("key_source", &self.key_source)
            .field("signing_identity", &self.signing_identity)
            .field("trust_scope", &self.trust_scope)
            .field("signed_payload_sha256", &self.signed_payload_sha256)
            .field("signature_hex", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TamperEvidence {
    pub algorithm: String,
    pub canonicalization: String,
    pub hash_scope: String,
    pub sha256: String,
    pub signature: CloseConditionReceiptSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloseConditionReceiptCore {
    pub schema_version: String,
    pub receipt_path: String,
    pub generated_at_utc: String,
    #[serde(rename = "L1_product_oracle")]
    pub l1_product_oracle: L1ProductOracle,
    #[serde(rename = "L2_engine_boundary_oracle")]
    pub l2_engine_boundary_oracle: L2EngineBoundaryOracle,
    pub release_policy_linkage: ReleasePolicyLinkage,
    pub composite_verdict: OracleColor,
    pub failing_dimensions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloseConditionReceipt {
    #[serde(flatten)]
    pub core: CloseConditionReceiptCore,
    pub tamper_evidence: TamperEvidence,
}

pub fn generate_close_condition_receipt(
    root: &Path,
    signing_material: &CloseConditionSigningMaterial<'_>,
) -> Result<CloseConditionReceipt> {
    let l1_product_oracle = evaluate_l1_product_oracle(root);
    let l2_engine_boundary_oracle = evaluate_l2_engine_boundary_oracle(root)?;
    let release_policy_linkage = evaluate_release_policy_linkage(root)
        .context("failed evaluating release-policy linkage")?;

    let mut failing_dimensions = Vec::new();
    if l1_product_oracle.verdict != OracleColor::Green {
        failing_dimensions.push("L1_product_oracle".to_string());
    }
    if l2_engine_boundary_oracle.verdict != OracleColor::Green {
        failing_dimensions.push("L2_engine_boundary_oracle".to_string());
    }
    if release_policy_linkage.verdict != OracleColor::Green {
        failing_dimensions.push("release_policy_linkage".to_string());
    }

    let composite_verdict = if failing_dimensions.is_empty() {
        OracleColor::Green
    } else {
        OracleColor::Red
    };

    let core = CloseConditionReceiptCore {
        schema_version: "oracle-close-condition-receipt/v1".to_string(),
        receipt_path: CLOSE_CONDITION_RECEIPT_PATH.to_string(),
        generated_at_utc: generated_at_utc(),
        l1_product_oracle,
        l2_engine_boundary_oracle,
        release_policy_linkage,
        composite_verdict,
        failing_dimensions,
    };

    let canonical = canonical_json_value(&serde_json::to_value(&core)?);
    let signed_preimage = close_condition_receipt_signed_preimage(&canonical);
    let payload_sha256 = hex::encode(Sha256::digest(&signed_preimage));
    let signature = signing_material.signing_key.sign(&signed_preimage);
    let verifying_key = signing_material.signing_key.verifying_key();
    let tamper_evidence = TamperEvidence {
        algorithm: "SHA-256".to_string(),
        canonicalization: "lexicographically-sorted-json-keys/no-whitespace".to_string(),
        hash_scope: "close_condition_receipt_v1_len_prefixed_core".to_string(),
        sha256: format!("sha256:{payload_sha256}"),
        signature: CloseConditionReceiptSignature {
            algorithm: "ed25519".to_string(),
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            key_id: crate::supply_chain::artifact_signing::KeyId::from_verifying_key(
                &verifying_key,
            )
            .to_string(),
            key_source: signing_material.key_source.to_string(),
            signing_identity: signing_material.signing_identity.to_string(),
            trust_scope: "oracle_close_condition".to_string(),
            signed_payload_sha256: payload_sha256,
            signature_hex: hex::encode(signature.to_bytes()),
        },
    };

    Ok(CloseConditionReceipt {
        core,
        tamper_evidence,
    })
}

pub fn verify_close_condition_receipt_signature(
    receipt: &CloseConditionReceipt,
    trusted_key_id: &str,
) -> Result<()> {
    let signature = &receipt.tamper_evidence.signature;
    if !crate::security::constant_time::ct_eq(&signature.algorithm, "ed25519") {
        anyhow::bail!(
            "unsupported close-condition receipt signature algorithm {}",
            signature.algorithm
        );
    }
    if !crate::security::constant_time::ct_eq(&signature.key_id, trusted_key_id) {
        anyhow::bail!(
            "close-condition receipt key id {} is not trusted key id {}",
            signature.key_id,
            trusted_key_id
        );
    }

    let mut public_key_bytes = [0_u8; 32];
    hex::decode_to_slice(&signature.public_key_hex, &mut public_key_bytes)
        .context("close-condition receipt public key must be 32 bytes of hex")?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .context("close-condition receipt public key is invalid")?;
    let derived_key_id =
        crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string();
    if !crate::security::constant_time::ct_eq(&signature.key_id, &derived_key_id) {
        anyhow::bail!(
            "close-condition receipt key id {} does not match public key {}",
            signature.key_id,
            derived_key_id
        );
    }

    let canonical = canonical_json_value(&serde_json::to_value(&receipt.core)?);
    let signed_preimage = close_condition_receipt_signed_preimage(&canonical);
    let payload_sha256 = hex::encode(Sha256::digest(&signed_preimage));
    let expected_tamper_hash = format!("sha256:{payload_sha256}");
    if !crate::security::constant_time::ct_eq(
        &receipt.tamper_evidence.sha256,
        &expected_tamper_hash,
    ) {
        anyhow::bail!("close-condition receipt tamper hash does not match canonical payload");
    }
    if !crate::security::constant_time::ct_eq(&signature.signed_payload_sha256, &payload_sha256) {
        anyhow::bail!(
            "close-condition receipt signed payload hash does not match canonical payload"
        );
    }

    let mut signature_bytes = [0_u8; 64];
    hex::decode_to_slice(&signature.signature_hex, &mut signature_bytes)
        .context("close-condition receipt signature must be 64 bytes of hex")?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    // Use `verify_strict` (not `verify`) to reject malleable / non-canonical-s
    // signatures. The aca68213 / 71eee3b2 / fa77136c sweep hardened every
    // other Ed25519 verification seam in the crate to `verify_strict`; this
    // close-condition receipt site was missed by those passes. Signatures
    // produced by `Ed25519Scheme` / canonical signing helpers are always
    // canonical and continue to verify; only malleated duplicates (a
    // signature-forgery / replay-equivalence class — RFC 8032 §5.1.7) are
    // now rejected.
    verifying_key
        .verify_strict(&signed_preimage, &signature)
        .context("close-condition receipt signature verification failed")
}

pub fn write_close_condition_receipt(
    root: &Path,
    receipt: &CloseConditionReceipt,
) -> Result<PathBuf> {
    let path = root.join(CLOSE_CONDITION_RECEIPT_PATH);
    let parent = path
        .parent()
        .context("close-condition receipt path must have a parent")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    fs::write(
        &path,
        format!("{}\n", render_close_condition_receipt_json(receipt)?),
    )
    .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn render_close_condition_receipt_json(receipt: &CloseConditionReceipt) -> Result<String> {
    serde_json::to_string_pretty(receipt).context("failed to render close-condition receipt")
}

#[derive(Clone, Debug, Serialize)]
struct CloseConditionStructuredLogLine {
    timestamp: String,
    level: &'static str,
    event_code: &'static str,
    message: String,
    trace_id: String,
    span_id: &'static str,
    surface: &'static str,
}

fn close_condition_structured_log_line(
    receipt: &CloseConditionReceipt,
    trace_id: &str,
    level: &'static str,
    event_code: &'static str,
    message: String,
) -> CloseConditionStructuredLogLine {
    CloseConditionStructuredLogLine {
        timestamp: receipt.core.generated_at_utc.clone(),
        level,
        event_code,
        message,
        trace_id: trace_id.to_string(),
        span_id: "doctor-close-condition",
        surface: "CLI-DOCTOR-CLOSE-CONDITION",
    }
}

/// Render the stable `FN-ACCEPT-*` acceptance-bar event stream for one
/// close-condition receipt as JSONL. Always emits `FN-ACCEPT-001`
/// (evaluated), then exactly one of `FN-ACCEPT-002` (PASS) or
/// `FN-ACCEPT-003` (FAIL-CLOSED), and one `FN-ACCEPT-004` line per
/// blocking finding when the gate refuses.
pub fn render_close_condition_structured_logs_jsonl(
    receipt: &CloseConditionReceipt,
    trace_id: &str,
) -> Result<String> {
    let core = &receipt.core;
    let mut lines = Vec::new();
    lines.push(close_condition_structured_log_line(
        receipt,
        trace_id,
        "info",
        event_codes::ACCEPTANCE_GATE_EVALUATED,
        format!(
            "acceptance-bar gate evaluated: L1_product_oracle={:?} L2_engine_boundary_oracle={:?} release_policy_linkage={:?}",
            core.l1_product_oracle.verdict,
            core.l2_engine_boundary_oracle.verdict,
            core.release_policy_linkage.verdict,
        ),
    ));

    if core.composite_verdict == OracleColor::Green {
        lines.push(close_condition_structured_log_line(
            receipt,
            trace_id,
            "info",
            event_codes::ACCEPTANCE_GATE_PASS,
            "acceptance-bar gate PASS: parity AND proof-carrying evidence verified across all dimensions".to_string(),
        ));
    } else {
        lines.push(close_condition_structured_log_line(
            receipt,
            trace_id,
            "error",
            event_codes::ACCEPTANCE_GATE_FAIL_CLOSED,
            format!(
                "acceptance-bar gate FAIL-CLOSED: failing dimensions [{}]",
                core.failing_dimensions.join(", ")
            ),
        ));
        let finding_groups = [
            (
                "L1_product_oracle",
                &core.l1_product_oracle.blocking_findings,
            ),
            (
                "L2_engine_boundary_oracle",
                &core.l2_engine_boundary_oracle.blocking_findings,
            ),
            (
                "release_policy_linkage",
                &core.release_policy_linkage.blocking_findings,
            ),
        ];
        for (dimension, findings) in finding_groups {
            for finding in findings {
                lines.push(close_condition_structured_log_line(
                    receipt,
                    trace_id,
                    "error",
                    event_codes::ACCEPTANCE_GATE_BLOCKING_FINDING,
                    format!("{dimension}: {finding}"),
                ));
            }
        }
    }

    let mut rendered = String::new();
    for line in &lines {
        rendered.push_str(
            &serde_json::to_string(line)
                .context("failed to render close-condition structured log line")?,
        );
        rendered.push('\n');
    }
    Ok(rendered)
}

fn generated_at_utc() -> String {
    std::env::var(CLOSE_CONDITION_TIMESTAMP_ENV).unwrap_or_else(|_| chrono::Utc::now().to_rfc3339())
}

fn evaluate_l1_product_oracle(root: &Path) -> L1ProductOracle {
    let source_path = COMPATIBILITY_CORPUS_RESULTS_PATH.to_string();
    let mut blocking_findings = Vec::new();
    let path = root.join(COMPATIBILITY_CORPUS_RESULTS_PATH);
    let data = match read_json_value(&path) {
        Ok(data) => data,
        Err(err) => {
            return L1ProductOracle {
                verdict: OracleColor::Red,
                source_path,
                corpus_version: None,
                corpus_provenance: None,
                total_test_cases: 0,
                passed_test_cases: 0,
                failed_test_cases: 0,
                errored_test_cases: 0,
                skipped_test_cases: 0,
                pass_rate_pct: 0.0,
                required_pass_rate_pct: 0.0,
                blocking_findings: vec![err],
            };
        }
    };

    let total_test_cases = get_u64(&data, &["totals", "total_test_cases"]).unwrap_or(0);
    let passed_test_cases = get_u64(&data, &["totals", "passed_test_cases"]).unwrap_or(0);
    let failed_test_cases = get_u64(&data, &["totals", "failed_test_cases"]).unwrap_or(0);
    let errored_test_cases = get_u64(&data, &["totals", "errored_test_cases"]).unwrap_or(0);
    let skipped_test_cases = get_u64(&data, &["totals", "skipped_test_cases"]).unwrap_or(0);
    let pass_rate_pct = get_f64(&data, &["totals", "overall_pass_rate_pct"]).unwrap_or(0.0);
    let required_pass_rate_pct =
        get_f64(&data, &["thresholds", "overall_pass_rate_min_pct"]).unwrap_or(95.0);
    let corpus_version = get_str(&data, &["corpus", "corpus_version"]).map(ToString::to_string);
    let corpus_provenance = get_str(&data, &["corpus", "provenance"]).map(ToString::to_string);

    // bd-ihusm: the L1 pass rate is only real if the corpus attests a genuine
    // lockstep-oracle run AND its results are digest-bound. A corpus with
    // authored/synthesized (or absent) provenance, or whose `result_digest`
    // does not recompute from `per_test_results`, is refused — synthesized
    // totals can no longer be consumed as if real.
    blocking_findings.extend(validate_l1_corpus_provenance(
        &data,
        corpus_provenance.as_deref(),
    ));

    if total_test_cases == 0 {
        blocking_findings.push("compatibility corpus has zero test cases".to_string());
    }
    if pass_rate_pct < required_pass_rate_pct {
        blocking_findings.push(format!(
            "compatibility corpus pass rate {pass_rate_pct:.2}% is below required {required_pass_rate_pct:.2}%"
        ));
    }
    if errored_test_cases > 0 {
        blocking_findings.push(format!(
            "compatibility corpus has {errored_test_cases} errored test cases"
        ));
    }
    blocking_findings.extend(validate_l1_proof_carrying_effects(&data));
    blocking_findings.extend(validate_l1_verdict_artifact(root, &data));

    L1ProductOracle {
        verdict: if blocking_findings.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        source_path,
        corpus_version,
        corpus_provenance,
        total_test_cases,
        passed_test_cases,
        failed_test_cases,
        errored_test_cases,
        skipped_test_cases,
        pass_rate_pct,
        required_pass_rate_pct,
        blocking_findings,
    }
}

/// bd-ihusm: refuse a corpus that does not attest a genuine oracle run or
/// whose per-test results are not digest-bound. Fail-closed on every gap so a
/// synthesized artifact can never satisfy the L1 pass-rate leg.
fn validate_l1_corpus_provenance(data: &Value, provenance: Option<&str>) -> Vec<String> {
    let mut findings = Vec::new();
    match provenance {
        None => {
            findings.push(
                "compatibility corpus is missing `corpus.provenance`; L1 requires a genuine \
                 lockstep-oracle run (expected provenance `lockstep-oracle-run`)"
                    .to_string(),
            );
        }
        Some(value) if value != COMPATIBILITY_CORPUS_ONLINE_PROVENANCE => {
            findings.push(format!(
                "compatibility corpus provenance `{value}` is not a genuine oracle run; L1 \
                 refuses to consume it as a real pass rate (expected \
                 `{COMPATIBILITY_CORPUS_ONLINE_PROVENANCE}`)"
            ));
        }
        Some(_) => {}
    }

    // Bind the declared totals to the per-test results via a recomputed
    // digest, whatever the provenance claims. A genuine-run artifact must
    // carry per_test_results whose canonical digest matches `result_digest`.
    match data.get("per_test_results").and_then(Value::as_array) {
        None => findings.push(
            "compatibility corpus has no `per_test_results`; the pass rate cannot be \
             re-derived or digest-verified"
                .to_string(),
        ),
        Some(per_test_results) => {
            let recomputed = compute_compatibility_corpus_result_digest(per_test_results);
            match get_str(data, &["corpus", "result_digest"]) {
                None => findings.push(
                    "compatibility corpus is missing `corpus.result_digest`; results are not \
                     content-bound"
                        .to_string(),
                ),
                // Content-hash comparison uses the crate's constant-time helper
                // per the hardening watchlist, even though both operands are
                // public here.
                Some(declared) if !crate::security::constant_time::ct_eq(declared, &recomputed) => {
                    findings.push(format!(
                        "compatibility corpus result_digest `{declared}` does not match the \
                         digest recomputed from per_test_results `{recomputed}`"
                    ));
                }
                Some(_) => {}
            }

            let recomputed_passed = per_test_results
                .iter()
                .filter(|row| get_str(row, &["status"]) == Some("pass"))
                .count() as u64;
            let declared_passed = get_u64(data, &["totals", "passed_test_cases"]).unwrap_or(0);
            let declared_total = get_u64(data, &["totals", "total_test_cases"]).unwrap_or(0);
            if per_test_results.len() as u64 != declared_total {
                findings.push(format!(
                    "compatibility corpus per_test_results count {} does not match declared \
                     total_test_cases {declared_total}",
                    per_test_results.len()
                ));
            }
            if recomputed_passed != declared_passed {
                findings.push(format!(
                    "compatibility corpus declared passed_test_cases {declared_passed} does not \
                     match the {recomputed_passed} passes in per_test_results"
                ));
            }
        }
    }
    findings
}

fn validate_l1_proof_carrying_effects(data: &Value) -> Vec<String> {
    let Some(summary) = get_value(data, &[L1_PROOF_CARRYING_EFFECTS_PATH]) else {
        return vec![format!(
            "proof-carrying host-effect evidence missing at {L1_PROOF_CARRYING_EFFECTS_PATH}"
        )];
    };
    if !summary.is_object() {
        return vec![format!(
            "proof-carrying host-effect evidence at {L1_PROOF_CARRYING_EFFECTS_PATH} must be an object"
        )];
    }

    let schema_version = get_str(data, &[L1_PROOF_CARRYING_EFFECTS_PATH, "schema_version"]);
    if schema_version == Some(crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2) {
        return validate_l1_proof_carrying_effects_v2(summary);
    }

    // bd-qr5i2.4: v1 acceptance is retired. A declared-only summary (no
    // embedded receipt chain) can no longer pass the gate — regenerate the
    // artifact from a real run with `franken-node ops proof-carrying-evidence`.
    // The v1 schema id stays registered in `schema_versions` (registry is
    // append-only); only its ACCEPTANCE here is withdrawn.
    vec![format!(
        "proof-carrying evidence schema_version {schema_version:?} is unsupported: only {} is \
         accepted (v1 declared-summary acceptance retired; regenerate via `franken-node ops \
         proof-carrying-evidence`)",
        crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2
    )]
}

/// v2 evidence: the gate does not trust the declared summary — it re-derives
/// chain integrity, per-receipt validity, subjects, and counts from the
/// embedded `receipt_chain_entries` and fails closed both on any
/// declared↔derived mismatch and on the acceptance requirements themselves
/// (evaluated over the DERIVED values only).
fn validate_l1_proof_carrying_effects_v2(summary: &Value) -> Vec<String> {
    use crate::runtime::effect_receipt::{
        EffectReceiptChain, EffectReceiptChainEntry, PolicyOutcome,
    };

    let Some(entries_value) = summary.get("receipt_chain_entries") else {
        return vec![
            "proof-carrying v2 evidence missing receipt_chain_entries; v2 requires the embedded receipt chain"
                .to_string(),
        ];
    };
    let entries: Vec<EffectReceiptChainEntry> = match serde_json::from_value(entries_value.clone())
    {
        Ok(entries) => entries,
        Err(err) => {
            return vec![format!(
                "proof-carrying v2 receipt_chain_entries failed to parse: {err}"
            )];
        }
    };

    let mut findings = Vec::new();

    let derived_chain_verified = match EffectReceiptChain::verify_entries_integrity(&entries) {
        Ok(()) => true,
        Err(err) => {
            findings.push(format!(
                "proof-carrying receipt chain failed re-derivation: {err}"
            ));
            false
        }
    };

    let mut derived_invalid: u64 = 0;
    let mut derived_verified: u64 = 0;
    let mut derived_subjects: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();
    for entry in &entries {
        if entry.receipt.validate().is_err() {
            derived_invalid = derived_invalid.saturating_add(1);
            continue;
        }
        // Denied receipts are legitimate ledger content (fail-closed proof
        // that nothing ran) but they do not evidence an executed subject.
        if !matches!(entry.receipt.policy_outcome, PolicyOutcome::Allowed { .. }) {
            continue;
        }
        if let Some(subject) = entry.receipt.effect_kind.l1_acceptance_subject()
            && REQUIRED_L1_PROOF_CARRYING_EFFECT_SUBJECTS.contains(&subject)
        {
            derived_subjects.insert(subject);
            derived_verified = derived_verified.saturating_add(1);
        }
    }

    // Declared summary fields must match the re-derived values exactly; an
    // artifact that overstates (or understates) its own evidence fails closed.
    let declared_subjects: std::collections::BTreeSet<String> = summary
        .get("verified_subjects")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let derived_subject_set: std::collections::BTreeSet<String> =
        derived_subjects.iter().map(ToString::to_string).collect();
    if declared_subjects != derived_subject_set {
        findings.push(format!(
            "declared verified_subjects {declared_subjects:?} do not match re-derived {derived_subject_set:?}"
        ));
    }
    let declared_verified = summary
        .get("effect_receipts_verified")
        .and_then(Value::as_u64);
    if declared_verified != Some(derived_verified) {
        findings.push(format!(
            "declared effect_receipts_verified {declared_verified:?} does not match re-derived {derived_verified}"
        ));
    }
    let declared_invalid = summary.get("invalid_receipts").and_then(Value::as_u64);
    if declared_invalid != Some(derived_invalid) {
        findings.push(format!(
            "declared invalid_receipts {declared_invalid:?} does not match re-derived {derived_invalid}"
        ));
    }
    let declared_chain_verified = summary
        .get("receipt_chain_verified")
        .and_then(Value::as_bool);
    if declared_chain_verified != Some(derived_chain_verified) {
        findings.push(format!(
            "declared receipt_chain_verified {declared_chain_verified:?} does not match re-derived {derived_chain_verified}"
        ));
    }

    // Acceptance requirements over the DERIVED values only.
    for subject in REQUIRED_L1_PROOF_CARRYING_EFFECT_SUBJECTS {
        if !derived_subjects.contains(subject) {
            findings.push(format!("proof-carrying evidence missing subject {subject}"));
        }
    }
    if derived_verified < REQUIRED_L1_PROOF_CARRYING_EFFECT_RECEIPT_COUNT {
        findings.push(format!(
            "proof-carrying effect receipt count {derived_verified} below required {REQUIRED_L1_PROOF_CARRYING_EFFECT_RECEIPT_COUNT}",
        ));
    }
    if derived_invalid != 0 {
        findings.push(format!(
            "proof-carrying evidence contains {derived_invalid} invalid receipt(s)"
        ));
    }

    findings
}

/// bd-ry7d1: the Rust gate consumes the SAME L1 product verdict artifact the
/// Python CI gate reads, and BINDS it to the corpus-results input — the two
/// gate implementations can no longer pass over drifted input sets.
///
/// Fail-closed findings when: the artifact is missing/unparseable, its
/// declared verdict is not GREEN, its `evidence.lockstep_verdict` block is
/// absent or does not re-derive (see [`validate_l1_lockstep_verdict`]), or
/// its `evidence.proof_carrying_effects` copy differs from the
/// corpus-results copy the pass-rate leg was evaluated against.
fn validate_l1_verdict_artifact(root: &Path, corpus_data: &Value) -> Vec<String> {
    let path = root.join(L1_PRODUCT_VERDICT_PATH);
    let data = match read_json_value(&path) {
        Ok(data) => data,
        Err(err) => {
            return vec![format!("L1 verdict artifact unreadable: {err}")];
        }
    };

    let mut findings = Vec::new();

    let declared_verdict = get_str(&data, &["verdict"]);
    if declared_verdict != Some("GREEN") {
        findings.push(format!(
            "L1 verdict artifact declares verdict {declared_verdict:?}, expected \"GREEN\""
        ));
    }

    let Some(evidence) = get_value(&data, &["evidence"]).filter(|value| value.is_object()) else {
        findings.push("L1 verdict artifact evidence object missing".to_string());
        return findings;
    };

    findings.extend(validate_l1_lockstep_verdict(
        evidence.get(crate::ops::proof_carrying_evidence::LOCKSTEP_VERDICT_KEY),
    ));

    // Cross-file binding: the verdict artifact and the corpus-results
    // artifact must carry the SAME proof-carrying evidence block, so the
    // Rust gate (corpus reader) and the Python gate (verdict reader) are
    // provably validating one evidence set, not two drifting copies.
    let corpus_proof = get_value(corpus_data, &[L1_PROOF_CARRYING_EFFECTS_PATH]);
    let artifact_proof = evidence.get(L1_PROOF_CARRYING_EFFECTS_PATH);
    match (corpus_proof, artifact_proof) {
        (_, None) => {
            findings.push(
                "L1 verdict artifact evidence.proof_carrying_effects missing (binding to the \
                 corpus-results copy is required)"
                    .to_string(),
            );
        }
        (None, Some(_)) => {
            // The corpus-side absence is already a blocking finding from
            // validate_l1_proof_carrying_effects; the binding cannot be
            // evaluated without it.
            findings.push(
                "L1 verdict artifact proof_carrying_effects binding unverifiable: corpus \
                 results carry no proof_carrying_effects block"
                    .to_string(),
            );
        }
        (Some(corpus_copy), Some(artifact_copy)) => {
            if corpus_copy != artifact_copy {
                findings.push(
                    "L1 verdict artifact proof_carrying_effects does not match the \
                     corpus-results copy (the two gate inputs have drifted; regenerate both \
                     via `franken-node ops proof-carrying-evidence --merge-corpus \
                     --merge-l1-verdict`)"
                        .to_string(),
                );
            }
        }
    }

    findings
}

/// bd-ry7d1: validate the `lockstep_verdict` evidence block by RE-DERIVING
/// the verdict from the embedded `DivergenceReport` — a declared "pass" is
/// never trusted. The L1 acceptance bar over the DERIVED report:
/// ≥2 registered runtimes with ≥2 distinct executor names, at least one
/// reference (non-franken) and one non-reference (franken) leg, ≥1
/// cross-runtime check with every check outcome `Agree`, zero divergences,
/// and a `Pass` verdict consistent with all of the above. Every declared
/// summary field must equal its derived counterpart.
fn validate_l1_lockstep_verdict(block: Option<&Value>) -> Vec<String> {
    use crate::runtime::nversion_oracle::{CheckOutcome, OracleVerdict};

    let Some(block) = block else {
        return vec![
            "L1 verdict artifact evidence.lockstep_verdict missing; the L1 lockstep leg \
             requires a real lockstep-oracle verdict (regenerate via `franken-node ops \
             proof-carrying-evidence --merge-l1-verdict`)"
                .to_string(),
        ];
    };
    if !block.is_object() {
        return vec!["L1 lockstep_verdict evidence must be an object".to_string()];
    }

    let schema_version = get_str(block, &["schema_version"]);
    if schema_version != Some(crate::schema_versions::L1_LOCKSTEP_VERDICT_V1) {
        return vec![format!(
            "L1 lockstep_verdict schema_version {schema_version:?} is unsupported: only {} is \
             accepted",
            crate::schema_versions::L1_LOCKSTEP_VERDICT_V1
        )];
    }

    let Some(report_value) = block.get("report") else {
        return vec![
            "L1 lockstep_verdict missing embedded report; v1 requires the full divergence \
             report for re-derivation"
                .to_string(),
        ];
    };
    let report: crate::runtime::nversion_oracle::DivergenceReport =
        match serde_json::from_value(report_value.clone()) {
            Ok(report) => report,
            Err(err) => {
                return vec![format!(
                    "L1 lockstep_verdict embedded report failed to parse: {err}"
                )];
            }
        };

    let mut findings = Vec::new();

    if report.schema_version != crate::runtime::nversion_oracle::SCHEMA_VERSION {
        findings.push(format!(
            "L1 lockstep report schema_version {} is not the supported {}",
            report.schema_version,
            crate::runtime::nversion_oracle::SCHEMA_VERSION
        ));
    }

    // Runtime-set requirements: a real cross-check needs at least two
    // distinct executors, at least one independent reference runtime, and at
    // least one franken (non-reference) runtime under test.
    if report.runtimes.len() < 2 {
        findings.push(format!(
            "L1 lockstep report registered only {} runtime(s); a lockstep verdict requires at \
             least 2",
            report.runtimes.len()
        ));
    }
    let distinct_names: std::collections::BTreeSet<&str> = report
        .runtimes
        .values()
        .map(|entry| entry.runtime_name.as_str())
        .collect();
    if report.runtimes.len() >= 2 && distinct_names.len() < 2 {
        findings.push(
            "L1 lockstep report runtimes share one executor name; self-agreement is not a \
             cross-check"
                .to_string(),
        );
    }
    if !report.runtimes.values().any(|entry| entry.is_reference) {
        findings.push(
            "L1 lockstep report has no reference runtime leg (is_reference=true)".to_string(),
        );
    }
    if !report.runtimes.values().any(|entry| !entry.is_reference) {
        findings
            .push("L1 lockstep report has no franken runtime leg (is_reference=false)".to_string());
    }

    // Check requirements: at least one executed cross-check, every check
    // must have an outcome, and every outcome must be Agree.
    if report.checks.is_empty() {
        findings.push("L1 lockstep report contains no cross-runtime checks".to_string());
    }
    for check in &report.checks {
        match &check.outcome {
            Some(CheckOutcome::Agree { .. }) => {}
            Some(CheckOutcome::Diverge { .. }) => {
                findings.push(format!(
                    "L1 lockstep check {} diverged across runtimes",
                    check.check_id
                ));
            }
            None => {
                findings.push(format!(
                    "L1 lockstep check {} has no recorded outcome",
                    check.check_id
                ));
            }
        }
    }

    // Divergence + verdict requirements over the DERIVED report.
    if !report.divergences.is_empty() {
        findings.push(format!(
            "L1 lockstep report carries {} divergence(s); the L1 bar requires zero",
            report.divergences.len()
        ));
    }
    if report.verdict != OracleVerdict::Pass {
        findings.push(format!(
            "L1 lockstep report verdict is {} (not pass)",
            report.verdict.label()
        ));
    }

    // Declared summary fields must match the re-derived values exactly.
    let declared_verdict = get_str(block, &["oracle_verdict"]);
    if declared_verdict != Some(report.verdict.label()) {
        findings.push(format!(
            "L1 lockstep declared oracle_verdict {declared_verdict:?} does not match re-derived \
             {}",
            report.verdict.label()
        ));
    }
    let declared_trace = get_str(block, &["trace_id"]);
    if declared_trace != Some(report.trace_id.as_str()) {
        findings.push(format!(
            "L1 lockstep declared trace_id {declared_trace:?} does not match report trace_id {}",
            report.trace_id
        ));
    }
    let declared_runtimes: std::collections::BTreeSet<String> = block
        .get("runtimes")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let derived_runtimes: std::collections::BTreeSet<String> =
        report.runtimes.keys().cloned().collect();
    if declared_runtimes != derived_runtimes {
        findings.push(format!(
            "L1 lockstep declared runtimes {declared_runtimes:?} do not match re-derived \
             {derived_runtimes:?}"
        ));
    }
    let declared_checks = get_u64(block, &["checks_total"]);
    if declared_checks != Some(report.checks.len() as u64) {
        findings.push(format!(
            "L1 lockstep declared checks_total {declared_checks:?} does not match re-derived {}",
            report.checks.len()
        ));
    }
    let declared_divergences = get_u64(block, &["divergence_count"]);
    if declared_divergences != Some(report.divergences.len() as u64) {
        findings.push(format!(
            "L1 lockstep declared divergence_count {declared_divergences:?} does not match \
             re-derived {}",
            report.divergences.len()
        ));
    }

    findings
}

fn evaluate_l2_engine_boundary_oracle(root: &Path) -> Result<L2EngineBoundaryOracle> {
    let checks = vec![
        check_no_local_engine_crates(root),
        check_engine_path_dependencies(root)?,
        check_no_engine_internal_imports(root)?,
        check_governance_docs(root),
    ];
    let blocking_findings = checks
        .iter()
        .filter(|check| check.status != OracleColor::Green)
        .map(|check| format!("{} failed", check.id))
        .collect::<Vec<_>>();
    let summary = SplitContractSummary {
        total_checks: checks.len(),
        passing_checks: checks
            .iter()
            .filter(|check| check.status == OracleColor::Green)
            .count(),
        failing_checks: checks
            .iter()
            .filter(|check| check.status != OracleColor::Green)
            .count(),
    };

    Ok(L2EngineBoundaryOracle {
        verdict: if blocking_findings.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        source: "engine_split_contract_check".to_string(),
        contract_ref: "docs/ENGINE_SPLIT_CONTRACT.md".to_string(),
        checks,
        summary,
        blocking_findings,
    })
}

fn evaluate_release_policy_linkage(
    root: &Path,
) -> std::result::Result<ReleasePolicyLinkage, ReleasePolicyLinkageError> {
    let source_path = root.join(SECTION_10N_GATE_VERDICT_PATH);
    let data = read_json_value(&source_path)
        .map_err(|detail| ReleasePolicyLinkageError::CiOutputNotAccessible { detail })?;
    let oracle_check = data
        .get("checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks.iter().find(|check| {
                get_str(check, &["check_id"]) == Some("10N-ORACLE")
                    || get_str(check, &["name"]) == Some("Dual-Oracle Close Condition Gate")
            })
        })
        .ok_or_else(|| ReleasePolicyLinkageError::CiOutputNotAccessible {
            detail: format!(
                "{}: missing Dual-Oracle Close Condition Gate result",
                source_path.display()
            ),
        })?;

    let status = get_str(oracle_check, &["status"]).unwrap_or("FAIL");
    let verdict = if status == "PASS" {
        OracleColor::Green
    } else {
        OracleColor::Red
    };
    let blocking_findings = if verdict == OracleColor::Green {
        Vec::new()
    } else {
        vec![format!("CI gate output status is {status}, expected PASS")]
    };

    Ok(ReleasePolicyLinkage {
        verdict,
        source: "ci_gate_output".to_string(),
        ci_outputs_accessible: true,
        ci_output_ref: Some(SECTION_10N_GATE_VERDICT_PATH.to_string()),
        consumed_oracles: vec![
            "L1_product_oracle".to_string(),
            "L2_engine_boundary_oracle".to_string(),
        ],
        blocking_findings,
    })
}

fn check_no_local_engine_crates(root: &Path) -> SplitContractCheck {
    let forbidden = ["crates/franken-engine", "crates/franken-extension-host"];
    let violations = forbidden
        .iter()
        .filter(|rel| root.join(rel).exists())
        .map(|rel| Value::String((*rel).to_string()))
        .collect::<Vec<_>>();

    SplitContractCheck {
        id: "SPLIT-NO-LOCAL".to_string(),
        status: if violations.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        details: serde_json::json!({
            "checked": forbidden,
            "violations": violations,
        }),
    }
}

fn check_engine_path_dependencies(root: &Path) -> Result<SplitContractCheck> {
    let cargo_files = match collect_files_named(root, "Cargo.toml") {
        Ok(files) => files,
        Err(err @ CloseConditionScanError::LimitExceeded { .. }) => {
            return Ok(scan_limit_exceeded_check("SPLIT-PATH-DEPS", &err));
        }
        Err(err) => return Err(anyhow::Error::new(err)),
    };
    let engine_crates = ["frankenengine-engine", "frankenengine-extension-host"];
    let mut cargo_file_reports = Vec::new();
    let mut violations = Vec::new();

    for cargo_file in cargo_files {
        let content = fs::read_to_string(&cargo_file)
            .with_context(|| format!("failed to read {}", cargo_file.display()))?;
        let mut engine_deps = Vec::new();
        for crate_name in engine_crates {
            for path in engine_dependency_paths(&content, crate_name) {
                let valid = validate_engine_dependency_path(&cargo_file, &path);
                if !valid {
                    violations.push(serde_json::json!({
                        "file": relative_path(root, &cargo_file),
                        "crate": crate_name,
                        "path": path,
                    }));
                }
                engine_deps.push(serde_json::json!({
                    "crate": crate_name,
                    "path": path,
                    "valid": valid,
                }));
            }
        }

        if !engine_deps.is_empty() {
            cargo_file_reports.push(serde_json::json!({
                "path": relative_path(root, &cargo_file),
                "engine_deps": engine_deps,
            }));
        }
    }

    Ok(SplitContractCheck {
        id: "SPLIT-PATH-DEPS".to_string(),
        status: if violations.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        details: serde_json::json!({
            "cargo_files": cargo_file_reports,
            "violations": violations,
        }),
    })
}

fn check_no_engine_internal_imports(root: &Path) -> Result<SplitContractCheck> {
    let rust_files = match collect_rust_files(root) {
        Ok(files) => files,
        Err(err @ CloseConditionScanError::LimitExceeded { .. }) => {
            return Ok(scan_limit_exceeded_check("SPLIT-NO-INTERNALS", &err));
        }
        Err(err) => return Err(anyhow::Error::new(err)),
    };
    let internal_patterns = [
        "use frankenengine_engine::internal",
        "use frankenengine_extension_host::internal",
        "mod franken_engine",
        "mod franken_extension_host",
    ];
    let mut violations = Vec::new();

    for rust_file in &rust_files {
        let content = fs::read_to_string(rust_file)
            .with_context(|| format!("failed to read {}", rust_file.display()))?;
        for line in content.lines() {
            let trimmed = line.trim_start();
            for pattern in internal_patterns {
                let matches_import = pattern.starts_with("use ")
                    && trimmed
                        .strip_prefix(pattern)
                        .is_some_and(matches_rust_statement_suffix);
                let matches_module = pattern.starts_with("mod ")
                    && trimmed
                        .strip_prefix(pattern)
                        .is_some_and(matches_rust_statement_suffix);
                if matches_import || matches_module {
                    violations.push(serde_json::json!({
                        "file": relative_path(root, rust_file),
                        "pattern": pattern,
                    }));
                }
            }
        }
    }

    Ok(SplitContractCheck {
        id: "SPLIT-NO-INTERNALS".to_string(),
        status: if violations.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        details: serde_json::json!({
            "files_scanned": rust_files.len(),
            "violations": violations,
        }),
    })
}

fn check_governance_docs(root: &Path) -> SplitContractCheck {
    let docs = ["docs/ENGINE_SPLIT_CONTRACT.md", "docs/PRODUCT_CHARTER.md"];
    let mut doc_reports = Vec::new();
    let mut violations = Vec::new();
    for doc in docs {
        let path = root.join(doc);
        let exists = path.exists();
        if !exists {
            violations.push(serde_json::json!({
                "path": doc,
                "error": "missing",
            }));
        }
        doc_reports.push(serde_json::json!({
            "path": doc,
            "exists": exists,
        }));
    }

    let split_contract = root.join("docs/ENGINE_SPLIT_CONTRACT.md");
    if let Ok(content) = fs::read_to_string(&split_contract) {
        let content_lower = content.to_lowercase();
        for keyword in ["franken_engine", "MUST NOT", "path dependencies"] {
            if !content_lower.contains(&keyword.to_lowercase()) {
                violations.push(serde_json::json!({
                    "path": "docs/ENGINE_SPLIT_CONTRACT.md",
                    "missing_keyword": keyword,
                }));
            }
        }
    }

    SplitContractCheck {
        id: "SPLIT-GOVERNANCE".to_string(),
        status: if violations.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        details: serde_json::json!({
            "docs": doc_reports,
            "violations": violations,
        }),
    }
}

fn matches_rust_statement_suffix(suffix: &str) -> bool {
    suffix == ";"
        || suffix.starts_with("::")
        || suffix.chars().next().is_some_and(char::is_whitespace)
}

fn scan_limit_exceeded_check(id: &str, err: &CloseConditionScanError) -> SplitContractCheck {
    SplitContractCheck {
        id: id.to_string(),
        status: OracleColor::Red,
        details: serde_json::json!({
            "error": "close_condition_scan_limit_exceeded",
            "detail": err.to_string(),
        }),
    }
}

fn read_json_value(path: &Path) -> std::result::Result<Value, String> {
    let raw = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("{}: {err}", path.display()))
}

fn get_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn get_u64(value: &Value, path: &[&str]) -> Option<u64> {
    get_value(value, path).and_then(Value::as_u64)
}

fn get_f64(value: &Value, path: &[&str]) -> Option<f64> {
    get_value(value, path).and_then(Value::as_f64)
}

fn get_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    get_value(value, path).and_then(Value::as_str)
}

fn collect_files_named(
    root: &Path,
    name: &str,
) -> std::result::Result<Vec<PathBuf>, CloseConditionScanError> {
    let mut files = Vec::new();
    collect_files(root, root, &mut |path| {
        if path.file_name().and_then(|part| part.to_str()) == Some(name) {
            push_scanned_file(
                &mut files,
                path,
                MAX_CLOSE_CONDITION_CARGO_FILES,
                "cargo-manifest",
            )?;
        }
        Ok(())
    })?;
    Ok(files)
}

fn collect_rust_files(root: &Path) -> std::result::Result<Vec<PathBuf>, CloseConditionScanError> {
    let mut files = Vec::new();
    for rel in ["crates", "src"] {
        let base = root.join(rel);
        if base.exists() {
            collect_files(root, &base, &mut |path| {
                if path.extension().and_then(|part| part.to_str()) == Some("rs") {
                    push_scanned_file(
                        &mut files,
                        path,
                        MAX_CLOSE_CONDITION_SCAN_FILES,
                        "rust-source",
                    )?;
                }
                Ok(())
            })?;
        }
    }
    Ok(files)
}

fn push_scanned_file(
    files: &mut Vec<PathBuf>,
    path: &Path,
    limit: usize,
    scan_kind: &'static str,
) -> std::result::Result<(), CloseConditionScanError> {
    if files.len() >= limit {
        return Err(CloseConditionScanError::LimitExceeded {
            scan_kind,
            limit,
            path: path.display().to_string(),
        });
    }
    files.push(path.to_path_buf());
    Ok(())
}

fn collect_files(
    root: &Path,
    dir: &Path,
    visit: &mut impl FnMut(&Path) -> std::result::Result<(), CloseConditionScanError>,
) -> std::result::Result<(), CloseConditionScanError> {
    if should_skip_path(root, dir) {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        if should_skip_path(root, &path) {
            continue;
        }
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", path.display()))?;
        if file_type.is_dir() {
            collect_files(root, &path, visit)?;
        } else if file_type.is_file() {
            visit(&path)?;
        }
    }
    Ok(())
}

fn should_skip_path(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components().any(|component| {
        let part = component.as_os_str().to_string_lossy();
        matches!(
            part.as_ref(),
            "target" | ".beads" | ".git" | "artifacts" | ".rch-tmp"
        )
    })
}

fn engine_dependency_paths(content: &str, crate_name: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Parse TOML content properly instead of string scanning
    let parsed = match toml::from_str::<toml::Value>(content) {
        Ok(value) => value,
        Err(_) => return paths, // Invalid TOML, return empty
    };

    // Check dependencies sections
    let sections = ["dependencies", "dev-dependencies", "build-dependencies"];
    for section in sections {
        if let Some(deps) = parsed.get(section).and_then(|v| v.as_table())
            && let Some(dep) = deps.get(crate_name)
        {
            let path_value = match dep {
                // Handle both string and table forms:
                // crate_name = { path = "...", ... }
                toml::Value::Table(table) => table.get("path").and_then(|v| v.as_str()),
                // Simple string paths are not valid for engine dependencies
                _ => None,
            };

            if let Some(path) = path_value {
                paths.push(path.to_string());
            }
        }
    }

    paths
}

/// Validates that an engine dependency path is secure and points to an allowed location.
/// Manually validates path components to prevent traversal attacks and ensures
/// the canonical resolved path equals one of the allowed engine crate directories.
fn validate_engine_dependency_path(cargo_file: &Path, path_str: &str) -> bool {
    use std::path::{Component, Path};

    // First, validate that the path doesn't contain any traversal attempts
    let path = Path::new(path_str);

    let mut past_initial_dots = false;

    // Check each path component for traversal attempts
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if past_initial_dots {
                    // Reject ".." components after normal directories to prevent internal traversal
                    return false;
                }
            }
            Component::CurDir => {
                if past_initial_dots {
                    return false;
                }
            }
            Component::Normal(_) => {
                past_initial_dots = true;
            }
            Component::Prefix(_) | Component::RootDir => {
                // Absolute paths or Windows prefixes are not allowed for dependencies
                return false;
            }
        }
    }

    // Resolve the path relative to the cargo file's directory
    let cargo_dir = cargo_file.parent().unwrap_or_else(|| Path::new("."));
    let resolved_path = cargo_dir.join(path);

    // Get the canonical path - but be careful about TOCTOU and symlink attacks
    let canonical_path = match resolved_path.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            // If canonicalization fails, the path doesn't exist or is inaccessible
            // This is suspicious for a declared dependency, reject it
            return false;
        }
    };

    // Define the allowed canonical paths for engine dependencies
    // These should be absolute paths to the expected engine crate locations
    let allowed_paths = [
        "franken_engine/crates/franken-engine",
        "franken_engine/crates/franken-extension-host",
    ];

    // Check if the canonical path equals one of our allowed paths (strict equality, not suffix)
    // This prevents suffix bypass attacks like "frankenengine-engine_evil"
    let canonical_str = canonical_path.to_string_lossy();
    for allowed in &allowed_paths {
        // Use strict path component equality instead of suffix matching
        let normalized = canonical_str.replace('\\', "/");

        // Additional validation: ensure the path doesn't contain suspicious traversals
        // even after canonicalization (in case of complex symlink attacks)
        if normalized.contains("/../") || normalized.contains("/./") {
            continue;
        }

        // Check if the normalized canonical path ends with exactly the allowed path
        // with proper path separator boundaries to prevent suffix bypass
        if let Some(prefix_len) = normalized.len().checked_sub(allowed.len()) {
            let suffix = &normalized[prefix_len..];
            if suffix == *allowed
                && (prefix_len == 0 || normalized.as_bytes()[prefix_len - 1] == b'/')
            {
                return true;
            }
        }
    }

    // If we get here, the path doesn't point to an allowed engine crate
    false
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn canonical_json_value(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("JSON scalar serialization should be infallible")
        }
        Value::Array(items) => {
            let rendered = items
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{rendered}]")
        }
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            let rendered = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key)
                            .expect("JSON object key serialization should be infallible"),
                        canonical_json_value(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

/// The signed/tamper-evidence preimage over a receipt's canonical JSON:
/// domain separator, little-endian u64 length prefix, then the canonical
/// bytes. Public so conformance harnesses pin the EXACT production preimage
/// (bd-38iny) instead of re-implementing (and silently drifting from) it.
pub fn close_condition_receipt_signed_preimage(canonical_json: &str) -> Vec<u8> {
    let canonical_len = u64::try_from(canonical_json.len()).unwrap_or(u64::MAX);
    let mut preimage = Vec::with_capacity(
        CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN
            .len()
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(canonical_json.len()),
    );
    preimage.extend_from_slice(CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN);
    preimage.extend_from_slice(&canonical_len.to_le_bytes());
    preimage.extend_from_slice(canonical_json.as_bytes());
    preimage
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    fn corpus_totals_json(passed: u64, failed: u64, pass_rate_pct: f64) -> Value {
        serde_json::json!({
            "corpus": { "corpus_version": "compat-corpus-test" },
            "thresholds": { "overall_pass_rate_min_pct": 95.0 },
            "totals": {
                "total_test_cases": passed + failed,
                "passed_test_cases": passed,
                "failed_test_cases": failed,
                "errored_test_cases": 0,
                "skipped_test_cases": 0,
                "overall_pass_rate_pct": pass_rate_pct,
            },
        })
    }

    /// A genuine, re-derivable v2 evidence block built through the production
    /// chain API (no hand-written hashes) — the only accepted schema after
    /// bd-qr5i2.4 retired v1 declared-summary acceptance.
    fn valid_proof_carrying_effects_json() -> Value {
        use crate::runtime::effect_receipt::{EffectKind, EffectReceipt, EffectReceiptChain};
        use crate::storage::cas::content_hash;

        let mut chain = EffectReceiptChain::new();
        for (seq, kind) in [
            (0_u64, EffectKind::FsRead),
            (1, EffectKind::FsWrite),
            (2, EffectKind::HttpRequest),
        ] {
            let receipt = EffectReceipt::allowed(
                seq,
                "close-condition-inline-tests",
                kind,
                "cap-l1-acceptance",
                content_hash(b"pre-state"),
                content_hash(b"args"),
                content_hash(b"result"),
                content_hash(b"post-state"),
                1_774_000_000_000,
            );
            chain.append(receipt).expect("append acceptance receipt");
        }
        serde_json::json!({
            "schema_version": crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2,
            "required_subjects": ["fs.read", "fs.write", "http.request"],
            "verified_subjects": ["fs.read", "fs.write", "http.request"],
            "effect_receipts_verified": 3,
            "invalid_receipts": 0,
            "receipt_chain_verified": true,
            "receipt_chain_entries": chain.entries(),
        })
    }

    fn corpus_with_valid_proof(passed: u64, failed: u64, pass_rate_pct: f64) -> Value {
        let mut data = corpus_totals_json(passed, failed, pass_rate_pct);
        data["proof_carrying_effects"] = valid_proof_carrying_effects_json();
        data
    }

    #[test]
    fn valid_proof_carrying_effects_evidence_yields_no_findings() {
        let data = corpus_with_valid_proof(100, 0, 100.0);
        assert!(validate_l1_proof_carrying_effects(&data).is_empty());
    }

    #[test]
    fn proof_carrying_effects_missing_evidence_fails_closed() {
        let data = corpus_totals_json(100, 0, 100.0);
        let findings = validate_l1_proof_carrying_effects(&data);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("evidence missing"), "{findings:?}");
    }

    #[test]
    fn proof_carrying_effects_non_object_evidence_fails_closed() {
        let mut data = corpus_totals_json(100, 0, 100.0);
        data["proof_carrying_effects"] = serde_json::json!("trust me");
        let findings = validate_l1_proof_carrying_effects(&data);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("must be an object"), "{findings:?}");
    }

    /// bd-qr5i2.4: v1 (and any other non-v2 schema) is refused outright —
    /// the declared-summary acceptance path is retired.
    #[test]
    fn proof_carrying_effects_retired_or_missing_schema_version_fails_closed() {
        for tamper in [
            Some(serde_json::json!(
                "franken-node/l1-proof-carrying-effects/v1"
            )),
            Some(serde_json::json!(
                "franken-node/l1-proof-carrying-effects/v0"
            )),
            None,
        ] {
            let mut data = corpus_with_valid_proof(100, 0, 100.0);
            let proof = data["proof_carrying_effects"].as_object_mut().unwrap();
            match tamper {
                Some(version) => {
                    proof.insert("schema_version".to_string(), version);
                }
                None => {
                    proof.remove("schema_version");
                }
            }
            let findings = validate_l1_proof_carrying_effects(&data);
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(findings[0].contains("is unsupported"), "{findings:?}");
        }
    }

    /// Understating verified_subjects no longer slips through as a plain
    /// subject gap: the declared set disagrees with the re-derived one.
    #[test]
    fn proof_carrying_effects_declared_subject_mismatch_fails_closed() {
        for missing in REQUIRED_L1_PROOF_CARRYING_EFFECT_SUBJECTS {
            let mut data = corpus_with_valid_proof(100, 0, 100.0);
            let subjects = REQUIRED_L1_PROOF_CARRYING_EFFECT_SUBJECTS
                .iter()
                .filter(|subject| subject != &missing)
                .collect::<Vec<_>>();
            data["proof_carrying_effects"]["verified_subjects"] = serde_json::json!(subjects);
            let findings = validate_l1_proof_carrying_effects(&data);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.contains("do not match re-derived")),
                "{findings:?}"
            );
        }
    }

    /// A declared count that disagrees with the re-derived count (inflated,
    /// deflated, or missing) fails closed as a mismatch.
    #[test]
    fn proof_carrying_effects_declared_count_mismatch_fails_closed() {
        for tamper in [Some(serde_json::json!(2)), Some(serde_json::json!(4)), None] {
            let mut data = corpus_with_valid_proof(100, 0, 100.0);
            let proof = data["proof_carrying_effects"].as_object_mut().unwrap();
            match tamper {
                Some(count) => {
                    proof.insert("effect_receipts_verified".to_string(), count);
                }
                None => {
                    proof.remove("effect_receipts_verified");
                }
            }
            let findings = validate_l1_proof_carrying_effects(&data);
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(
                findings[0].contains("effect_receipts_verified")
                    && findings[0].contains("does not match re-derived"),
                "{findings:?}"
            );
        }
    }

    /// Declared invalid_receipts must equal the re-derived value (0 for a
    /// genuine chain); a nonzero or missing declaration is a mismatch.
    #[test]
    fn proof_carrying_effects_declared_invalid_mismatch_fails_closed() {
        for tamper in [Some(serde_json::json!(1)), None] {
            let mut data = corpus_with_valid_proof(100, 0, 100.0);
            let proof = data["proof_carrying_effects"].as_object_mut().unwrap();
            match tamper {
                Some(count) => {
                    proof.insert("invalid_receipts".to_string(), count);
                }
                None => {
                    proof.remove("invalid_receipts");
                }
            }
            let findings = validate_l1_proof_carrying_effects(&data);
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(
                findings[0].contains("invalid_receipts")
                    && findings[0].contains("does not match re-derived"),
                "{findings:?}"
            );
        }
    }

    /// Declaring the chain unverified (or omitting the flag) while the
    /// embedded chain actually re-derives is itself a mismatch — the
    /// declared summary must be honest in both directions.
    #[test]
    fn proof_carrying_effects_declared_chain_flag_mismatch_fails_closed() {
        for tamper in [Some(serde_json::json!(false)), None] {
            let mut data = corpus_with_valid_proof(100, 0, 100.0);
            let proof = data["proof_carrying_effects"].as_object_mut().unwrap();
            match tamper {
                Some(flag) => {
                    proof.insert("receipt_chain_verified".to_string(), flag);
                }
                None => {
                    proof.remove("receipt_chain_verified");
                }
            }
            let findings = validate_l1_proof_carrying_effects(&data);
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(
                findings[0].contains("receipt_chain_verified")
                    && findings[0].contains("does not match re-derived"),
                "{findings:?}"
            );
        }
    }

    /// Tampering with an embedded entry breaks re-derivation: the chain
    /// finding plus the now-dishonest declared flag both fail closed.
    #[test]
    fn proof_carrying_effects_tampered_entry_fails_rederivation() {
        let mut data = corpus_with_valid_proof(100, 0, 100.0);
        data["proof_carrying_effects"]["receipt_chain_entries"][1]["receipt"]["trace_id"] =
            serde_json::json!("rewritten-history");
        let findings = validate_l1_proof_carrying_effects(&data);
        assert!(
            findings
                .iter()
                .any(|finding| finding.contains("failed re-derivation")),
            "{findings:?}"
        );
    }

    fn write_corpus_fixture(root: &Path, data: &Value) {
        let path = root.join(COMPATIBILITY_CORPUS_RESULTS_PATH);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(data).unwrap()).unwrap();
    }

    /// A lockstep verdict block whose embedded report is built through the
    /// REAL oracle API — internally consistent by construction, so the
    /// gate's re-derivation accepts it and every tamper test can start from
    /// a known-green baseline.
    fn valid_lockstep_verdict_json() -> Value {
        use crate::runtime::nversion_oracle::{BoundaryScope, RuntimeEntry, RuntimeOracle};

        let mut oracle = RuntimeOracle::new("l1-lockstep:close-condition-inline", 100);
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "bun".to_string(),
                runtime_name: "bun".to_string(),
                version: "1.0-test".to_string(),
                is_reference: true,
            })
            .unwrap();
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "franken-engine-native".to_string(),
                runtime_name: "franken-engine-native".to_string(),
                version: "0.1-test".to_string(),
                is_reference: false,
            })
            .unwrap();
        let mut outputs = std::collections::BTreeMap::new();
        outputs.insert("bun".to_string(), b"l1-lockstep:ok\n".to_vec());
        outputs.insert(
            "franken-engine-native".to_string(),
            b"l1-lockstep:ok\n".to_vec(),
        );
        oracle
            .run_cross_check(
                "l1-lockstep:close-condition-inline:check-0",
                BoundaryScope::IO,
                b"guest-src",
                &outputs,
            )
            .unwrap();
        let report = oracle.generate_report(1_774_000_000);
        serde_json::json!({
            "schema_version": crate::schema_versions::L1_LOCKSTEP_VERDICT_V1,
            "trace_id": report.trace_id,
            "produced_at": "2026-07-10T00:00:00+00:00",
            "producer": "close-condition-inline-tests",
            "guest_program_content_hash":
                crate::storage::cas::content_hash(b"guest-src").as_str(),
            "runtimes": report.runtimes.keys().cloned().collect::<Vec<_>>(),
            "oracle_verdict": report.verdict.label(),
            "checks_total": report.checks.len(),
            "divergence_count": report.divergences.len(),
            "report": report,
        })
    }

    /// A DIVERGED lockstep block (still internally consistent: declared
    /// summary matches the derived one) — must fail the gate's L1 bar.
    fn diverged_lockstep_verdict_json() -> Value {
        use crate::runtime::nversion_oracle::{
            BoundaryScope, RiskTier, RuntimeEntry, RuntimeOracle,
        };

        let mut oracle = RuntimeOracle::new("l1-lockstep:close-condition-diverged", 100);
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "bun".to_string(),
                runtime_name: "bun".to_string(),
                version: "1.0-test".to_string(),
                is_reference: true,
            })
            .unwrap();
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "franken-engine-native".to_string(),
                runtime_name: "franken-engine-native".to_string(),
                version: "0.1-test".to_string(),
                is_reference: false,
            })
            .unwrap();
        let mut outputs = std::collections::BTreeMap::new();
        outputs.insert("bun".to_string(), b"left\n".to_vec());
        outputs.insert("franken-engine-native".to_string(), b"right\n".to_vec());
        let check = oracle
            .run_cross_check(
                "l1-lockstep:close-condition-diverged:check-0",
                BoundaryScope::IO,
                b"guest-src",
                &outputs,
            )
            .unwrap();
        assert!(check.outcome.is_some());
        oracle.classify_divergence(
            "l1-lockstep:close-condition-diverged:div-0",
            "l1-lockstep:close-condition-diverged:check-0",
            BoundaryScope::IO,
            RiskTier::High,
            &outputs,
        );
        let report = oracle.generate_report(1_774_000_000);
        serde_json::json!({
            "schema_version": crate::schema_versions::L1_LOCKSTEP_VERDICT_V1,
            "trace_id": report.trace_id,
            "produced_at": "2026-07-10T00:00:00+00:00",
            "producer": "close-condition-inline-tests",
            "guest_program_content_hash":
                crate::storage::cas::content_hash(b"guest-src").as_str(),
            "runtimes": report.runtimes.keys().cloned().collect::<Vec<_>>(),
            "oracle_verdict": report.verdict.label(),
            "checks_total": report.checks.len(),
            "divergence_count": report.divergences.len(),
            "report": report,
        })
    }

    /// Write an L1 product verdict artifact fixture whose
    /// `proof_carrying_effects` copy is taken from the corpus fixture (so
    /// the cross-file binding holds by construction).
    fn write_l1_verdict_fixture(root: &Path, corpus_data: &Value, lockstep: Value) {
        let mut evidence = serde_json::Map::new();
        if let Some(proof) = corpus_data.get(L1_PROOF_CARRYING_EFFECTS_PATH) {
            evidence.insert(L1_PROOF_CARRYING_EFFECTS_PATH.to_string(), proof.clone());
        }
        evidence.insert(
            crate::ops::proof_carrying_evidence::LOCKSTEP_VERDICT_KEY.to_string(),
            lockstep,
        );
        let artifact = serde_json::json!({
            "dimension": "l1_product",
            "verdict": "GREEN",
            "owner_track": "10.2",
            "timestamp": "2026-07-10T00:00:00+00:00",
            "evidence": Value::Object(evidence),
        });
        let path = root.join(L1_PRODUCT_VERDICT_PATH);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();
    }

    /// Convenience: write both L1 gate inputs in their bound-together form.
    fn write_bound_l1_fixtures(root: &Path, corpus_data: &Value) {
        write_corpus_fixture(root, corpus_data);
        write_l1_verdict_fixture(root, corpus_data, valid_lockstep_verdict_json());
    }

    /// The acceptance-bar conjunction at the L1 unit level: GREEN iff
    /// parity passes AND proof-carrying evidence verifies; each arm missing
    /// independently forces RED (fail-closed), as does both missing.
    #[test]
    fn l1_oracle_verdict_is_conjunction_of_parity_and_proof() {
        // All legs satisfied (parity + proof + verdict artifact with a real
        // lockstep verdict, bound together) => GREEN.
        let temp = TempDir::new().unwrap();
        write_bound_l1_fixtures(temp.path(), &corpus_with_valid_proof(100, 0, 100.0));
        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Green, "{oracle:?}");
        assert!(oracle.blocking_findings.is_empty(), "{oracle:?}");

        // Parity GREEN but unproven => FAIL-CLOSED.
        let temp = TempDir::new().unwrap();
        write_bound_l1_fixtures(temp.path(), &corpus_totals_json(100, 0, 100.0));
        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("proof-carrying")),
            "{oracle:?}"
        );

        // Proven but parity RED => FAIL-CLOSED.
        let temp = TempDir::new().unwrap();
        write_bound_l1_fixtures(temp.path(), &corpus_with_valid_proof(90, 10, 90.0));
        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("pass rate")),
            "{oracle:?}"
        );
        assert!(
            !oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("proof-carrying")),
            "proof leg should be clean in this arm: {oracle:?}"
        );

        // Both legs missing => FAIL-CLOSED with findings from both legs.
        let temp = TempDir::new().unwrap();
        write_bound_l1_fixtures(temp.path(), &corpus_totals_json(0, 0, 0.0));
        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("zero test cases")),
            "{oracle:?}"
        );
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("proof-carrying")),
            "{oracle:?}"
        );
    }

    // ── bd-ry7d1: the L1 verdict artifact + lockstep leg + binding ──

    /// The L1 leg fails closed when the verdict artifact the Python gate
    /// reads is absent — the two gates must consume the same input set.
    #[test]
    fn l1_fails_closed_without_verdict_artifact() {
        let temp = TempDir::new().unwrap();
        write_corpus_fixture(temp.path(), &corpus_with_valid_proof(100, 0, 100.0));
        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("L1 verdict artifact unreadable")),
            "{oracle:?}"
        );
    }

    #[test]
    fn l1_fails_closed_when_verdict_artifact_declares_non_green() {
        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        write_l1_verdict_fixture(temp.path(), &corpus, valid_lockstep_verdict_json());
        let path = temp.path().join(L1_PRODUCT_VERDICT_PATH);
        let mut artifact: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        artifact["verdict"] = serde_json::json!("RED");
        std::fs::write(&path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("declares verdict Some(\"RED\")")),
            "{oracle:?}"
        );
    }

    #[test]
    fn l1_fails_closed_when_lockstep_verdict_missing() {
        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        let artifact = serde_json::json!({
            "verdict": "GREEN",
            "evidence": {
                L1_PROOF_CARRYING_EFFECTS_PATH: corpus[L1_PROOF_CARRYING_EFFECTS_PATH].clone(),
            },
        });
        let path = temp.path().join(L1_PRODUCT_VERDICT_PATH);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("lockstep_verdict missing")),
            "{oracle:?}"
        );
    }

    /// A genuinely diverged oracle run (built through the real oracle API,
    /// declared summary honest) still fails the L1 bar: divergences,
    /// non-Agree check, and non-pass verdict each produce findings.
    #[test]
    fn l1_fails_closed_on_diverged_lockstep_report() {
        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        write_l1_verdict_fixture(temp.path(), &corpus, diverged_lockstep_verdict_json());

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        for needle in ["diverged across runtimes", "divergence(s)", "not pass"] {
            assert!(
                oracle
                    .blocking_findings
                    .iter()
                    .any(|finding| finding.contains(needle)),
                "expected finding containing {needle:?}: {oracle:?}"
            );
        }
    }

    /// A tampered declaration (report says pass, block claims something
    /// else — or vice versa) is caught by the declared↔derived cross-check.
    #[test]
    fn l1_fails_closed_on_declared_lockstep_mismatch() {
        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        let mut lockstep = valid_lockstep_verdict_json();
        lockstep["oracle_verdict"] = serde_json::json!("block_release");
        write_l1_verdict_fixture(temp.path(), &corpus, lockstep);

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("declared oracle_verdict")
                    && finding.contains("does not match re-derived")),
            "{oracle:?}"
        );
    }

    /// Two legs claiming the SAME executor cannot fake a cross-check. The
    /// oracle API itself refuses same-fingerprint registration
    /// (ERR_NVO_FINGERPRINT_COLLISION), so a self-agreeing report can only
    /// arrive as a hand-crafted artifact — exactly what the gate's
    /// re-derivation must catch, since the artifact JSON is
    /// attacker-controllable.
    #[test]
    fn l1_fails_closed_on_lockstep_self_agreement() {
        let mut lockstep = valid_lockstep_verdict_json();
        lockstep["report"]["runtimes"]["franken-engine-native"]["runtime_name"] =
            serde_json::json!("bun");

        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        write_l1_verdict_fixture(temp.path(), &corpus, lockstep);

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("self-agreement")),
            "{oracle:?}"
        );
    }

    /// The cross-file binding: the verdict artifact's proof-carrying block
    /// must be value-identical to the corpus-results copy.
    #[test]
    fn l1_fails_closed_when_proof_copies_drift() {
        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        let mut drifted = corpus.clone();
        drifted["proof_carrying_effects"]["produced_at"] = serde_json::json!("2020-01-01");
        write_l1_verdict_fixture(temp.path(), &drifted, valid_lockstep_verdict_json());

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("does not match the corpus-results copy")),
            "{oracle:?}"
        );
    }

    /// Unsupported lockstep schema versions are refused outright.
    #[test]
    fn l1_fails_closed_on_unsupported_lockstep_schema() {
        let temp = TempDir::new().unwrap();
        let corpus = corpus_with_valid_proof(100, 0, 100.0);
        write_corpus_fixture(temp.path(), &corpus);
        let mut lockstep = valid_lockstep_verdict_json();
        lockstep["schema_version"] = serde_json::json!("franken-node/l1-lockstep-verdict/v0");
        write_l1_verdict_fixture(temp.path(), &corpus, lockstep);

        let oracle = evaluate_l1_product_oracle(temp.path());
        assert_eq!(oracle.verdict, OracleColor::Red, "{oracle:?}");
        assert!(
            oracle
                .blocking_findings
                .iter()
                .any(|finding| finding.contains("schema_version")
                    && finding.contains("is unsupported")),
            "{oracle:?}"
        );
    }

    fn test_receipt(
        l1_verdict: OracleColor,
        l1_findings: Vec<String>,
        composite_verdict: OracleColor,
        failing_dimensions: Vec<String>,
    ) -> CloseConditionReceipt {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        CloseConditionReceipt {
            core: CloseConditionReceiptCore {
                schema_version: "oracle-close-condition-receipt/v1".to_string(),
                receipt_path: CLOSE_CONDITION_RECEIPT_PATH.to_string(),
                generated_at_utc: "2026-07-04T00:00:00Z".to_string(),
                l1_product_oracle: L1ProductOracle {
                    verdict: l1_verdict,
                    source_path: COMPATIBILITY_CORPUS_RESULTS_PATH.to_string(),
                    corpus_version: Some("compat-corpus-test".to_string()),
                    corpus_provenance: Some(COMPATIBILITY_CORPUS_ONLINE_PROVENANCE.to_string()),
                    total_test_cases: 100,
                    passed_test_cases: 100,
                    failed_test_cases: 0,
                    errored_test_cases: 0,
                    skipped_test_cases: 0,
                    pass_rate_pct: 100.0,
                    required_pass_rate_pct: 95.0,
                    blocking_findings: l1_findings,
                },
                l2_engine_boundary_oracle: L2EngineBoundaryOracle {
                    verdict: OracleColor::Green,
                    source: "engine_split_contract_check".to_string(),
                    contract_ref: "docs/ENGINE_SPLIT_CONTRACT.md".to_string(),
                    checks: Vec::new(),
                    summary: SplitContractSummary {
                        total_checks: 0,
                        passing_checks: 0,
                        failing_checks: 0,
                    },
                    blocking_findings: Vec::new(),
                },
                release_policy_linkage: ReleasePolicyLinkage {
                    verdict: OracleColor::Green,
                    source: "ci_gate_output".to_string(),
                    ci_outputs_accessible: true,
                    ci_output_ref: Some(SECTION_10N_GATE_VERDICT_PATH.to_string()),
                    consumed_oracles: vec![
                        "L1_product_oracle".to_string(),
                        "L2_engine_boundary_oracle".to_string(),
                    ],
                    blocking_findings: Vec::new(),
                },
                composite_verdict,
                failing_dimensions,
            },
            tamper_evidence: TamperEvidence {
                algorithm: "SHA-256".to_string(),
                canonicalization: "lexicographically-sorted-json-keys/no-whitespace".to_string(),
                hash_scope: "close_condition_receipt_v1_len_prefixed_core".to_string(),
                sha256: "sha256:unused-in-log-render".to_string(),
                signature: CloseConditionReceiptSignature {
                    algorithm: "ed25519".to_string(),
                    public_key_hex: hex::encode(verifying_key.to_bytes()),
                    key_id: "test-key".to_string(),
                    key_source: "test".to_string(),
                    signing_identity: "oracle-close-condition".to_string(),
                    trust_scope: "oracle_close_condition".to_string(),
                    signed_payload_sha256: "unused".to_string(),
                    signature_hex: "unused".to_string(),
                },
            },
        }
    }

    fn parse_jsonl(rendered: &str) -> Vec<Value> {
        rendered
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn acceptance_gate_structured_logs_pass_emits_evaluated_then_pass() {
        let receipt = test_receipt(
            OracleColor::Green,
            Vec::new(),
            OracleColor::Green,
            Vec::new(),
        );
        let rendered =
            render_close_condition_structured_logs_jsonl(&receipt, "trace-accept-pass").unwrap();
        let lines = parse_jsonl(&rendered);
        assert_eq!(lines.len(), 2, "{rendered}");
        assert_eq!(
            lines[0]["event_code"],
            event_codes::ACCEPTANCE_GATE_EVALUATED
        );
        assert_eq!(lines[1]["event_code"], event_codes::ACCEPTANCE_GATE_PASS);
        assert_eq!(lines[1]["level"], "info");
        for line in &lines {
            assert_eq!(line["trace_id"], "trace-accept-pass");
            assert_eq!(line["surface"], "CLI-DOCTOR-CLOSE-CONDITION");
        }
    }

    #[test]
    fn acceptance_gate_structured_logs_fail_closed_emits_findings() {
        let receipt = test_receipt(
            OracleColor::Red,
            vec![
                "proof-carrying host-effect evidence missing at proof_carrying_effects".to_string(),
                "compatibility corpus pass rate 90.00% is below required 95.00%".to_string(),
            ],
            OracleColor::Red,
            vec!["L1_product_oracle".to_string()],
        );
        let rendered =
            render_close_condition_structured_logs_jsonl(&receipt, "trace-accept-fail").unwrap();
        let lines = parse_jsonl(&rendered);
        assert_eq!(lines.len(), 4, "{rendered}");
        assert_eq!(
            lines[0]["event_code"],
            event_codes::ACCEPTANCE_GATE_EVALUATED
        );
        assert_eq!(
            lines[1]["event_code"],
            event_codes::ACCEPTANCE_GATE_FAIL_CLOSED
        );
        assert_eq!(lines[1]["level"], "error");
        assert!(
            lines[1]["message"]
                .as_str()
                .unwrap()
                .contains("L1_product_oracle"),
            "{rendered}"
        );
        for finding_line in &lines[2..] {
            assert_eq!(
                finding_line["event_code"],
                event_codes::ACCEPTANCE_GATE_BLOCKING_FINDING
            );
            assert_eq!(finding_line["level"], "error");
        }
        assert!(
            lines[2]["message"]
                .as_str()
                .unwrap()
                .contains("proof-carrying"),
            "{rendered}"
        );
        assert!(
            lines[3]["message"].as_str().unwrap().contains("pass rate"),
            "{rendered}"
        );
    }

    #[test]
    fn test_engine_dependency_paths_proper_toml_parsing() {
        // Test that we properly parse TOML instead of using string scanning
        let content = r#"
[dependencies]
frankenengine-engine = { path = "../franken_engine/crates/franken-engine", version = "0.1.0" }
some-other-crate = "1.0.0"

[dev-dependencies]
frankenengine-extension-host = { path = "../franken_engine/crates/franken-extension-host" }
"#;

        let paths = engine_dependency_paths(content, "frankenengine-engine");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "../franken_engine/crates/franken-engine");

        let paths = engine_dependency_paths(content, "frankenengine-extension-host");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "../franken_engine/crates/franken-extension-host");

        // Should not find non-existent crates
        let paths = engine_dependency_paths(content, "non-existent-crate");
        assert_eq!(paths.len(), 0);
    }

    #[test]
    fn test_validate_engine_dependency_path_rejects_traversal_attacks() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_file = temp_dir.path().join("Cargo.toml");
        std::fs::write(&cargo_file, "").unwrap();

        // BD-3K70D regression tests: path traversal attacks that should be rejected

        // Attack 1: "../../../franken_engine/crates/../../evil" - escapes and re-enters
        let malicious_path = "../../../franken_engine/crates/../../evil";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject path traversal attack: {}",
            malicious_path
        );

        // Attack 2: "../../../../evil" - attempts to escape entirely
        let malicious_path = "../../../../evil";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject path traversal attack: {}",
            malicious_path
        );

        // Attack 3: "./../../franken_engine/crates/../../../etc/passwd" - mixed traversal
        let malicious_path = "./../../franken_engine/crates/../../../etc/passwd";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject path traversal attack: {}",
            malicious_path
        );

        // Attack 4: Absolute paths should be rejected
        let malicious_path = "/franken_engine/crates/franken-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject absolute path: {}",
            malicious_path
        );

        // Attack 5: Windows absolute paths should be rejected
        let malicious_path = "C:\\franken_engine\\crates\\franken-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject Windows absolute path: {}",
            malicious_path
        );
    }

    #[test]
    fn test_validate_engine_dependency_path_rejects_substring_lookalikes() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_file = temp_dir.path().join("Cargo.toml");
        std::fs::write(&cargo_file, "").unwrap();

        // BD-3K70D regression tests: substring look-alikes that should be rejected

        // Attack 6: "/not_franken_engine/crates_imposter/" - contains target substrings but wrong location
        let malicious_path = "../not_franken_engine/crates_imposter/franken-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike: {}",
            malicious_path
        );

        // Attack 7: "franken_engine_crates" - looks similar but missing separator
        let malicious_path = "../franken_engine_crates/franken-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike: {}",
            malicious_path
        );

        // Attack 8: "some_franken_engine/crates/" - contains target but with prefix
        let malicious_path = "../some_franken_engine/crates/franken-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike with prefix: {}",
            malicious_path
        );

        // Attack 9: "franken_engine/crates_but_not_really/" - starts right but ends wrong
        let malicious_path = "../franken_engine/crates_but_not_really/franken-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike with suffix: {}",
            malicious_path
        );
    }

    #[test]
    fn test_validate_engine_dependency_path_allows_legitimate_paths() {
        // Create a temporary directory structure that simulates the expected layout
        let temp_dir = TempDir::new().unwrap();
        let cargo_file = temp_dir.path().join("test_crate").join("Cargo.toml");
        std::fs::create_dir_all(cargo_file.parent().unwrap()).unwrap();
        std::fs::write(&cargo_file, "").unwrap();

        // Create the expected franken_engine directory structure
        let franken_engine_dir = temp_dir.path().join("franken_engine").join("crates");
        std::fs::create_dir_all(&franken_engine_dir.join("franken-engine")).unwrap();
        std::fs::create_dir_all(&franken_engine_dir.join("franken-extension-host")).unwrap();

        // These legitimate paths should be allowed
        let legitimate_paths = [
            "../franken_engine/crates/franken-engine",
            "../franken_engine/crates/franken-extension-host",
        ];

        for legitimate_path in &legitimate_paths {
            assert!(
                validate_engine_dependency_path(&cargo_file, legitimate_path),
                "Should allow legitimate path: {}",
                legitimate_path
            );
        }
    }

    #[test]
    fn test_validate_engine_dependency_path_rejects_nonexistent_paths() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_file = temp_dir.path().join("Cargo.toml");
        std::fs::write(&cargo_file, "").unwrap();

        // Paths that don't exist should be rejected (canonicalization will fail)
        let nonexistent_paths = [
            "../this/does/not/exist",
            "../franken_engine/crates/nonexistent-crate",
            "definitely/not/a/real/path",
        ];

        for nonexistent_path in &nonexistent_paths {
            assert!(
                !validate_engine_dependency_path(&cargo_file, nonexistent_path),
                "Should reject nonexistent path: {}",
                nonexistent_path
            );
        }
    }

    #[test]
    fn test_suffix_bypass_attack_bd_3iey5_regression() {
        // BD-3IEY5: Suffix bypass attack regression tests
        // Ensure paths with malicious suffixes are rejected even if they contain the allowed path as a suffix

        let temp_dir = TempDir::new().unwrap();
        let cargo_file = temp_dir.path().join("test_crate").join("Cargo.toml");
        std::fs::create_dir_all(cargo_file.parent().unwrap()).unwrap();
        std::fs::write(&cargo_file, "").unwrap();

        // Create legitimate engine directories
        let franken_engine_dir = temp_dir.path().join("franken_engine").join("crates");
        std::fs::create_dir_all(&franken_engine_dir.join("franken-engine")).unwrap();
        std::fs::create_dir_all(&franken_engine_dir.join("franken-extension-host")).unwrap();

        // Create malicious directories that contain the allowed path as a suffix
        std::fs::create_dir_all(&franken_engine_dir.join("franken-engine_evil")).unwrap();
        std::fs::create_dir_all(&franken_engine_dir.join("prefix_franken-engine")).unwrap();

        // Test 1: Legitimate path should pass
        assert!(
            validate_engine_dependency_path(&cargo_file, "../franken_engine/crates/franken-engine"),
            "Legitimate path should be allowed"
        );

        // Test 2: franken-engine_evil should be rejected (suffix bypass attack)
        assert!(
            !validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/franken-engine_evil"
            ),
            "Should reject suffix bypass attack: franken-engine_evil"
        );

        // Test 3: prefix_franken-engine should be rejected (suffix bypass attack)
        assert!(
            !validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/prefix_franken-engine"
            ),
            "Should reject suffix bypass attack: prefix_franken-engine"
        );

        // Test 4: Create traversal path that canonicalizes to legitimate location but has traversal
        // This tests that even after canonicalization, we still reject paths with traversal components
        let traversal_dir = temp_dir
            .path()
            .join("franken_engine")
            .join("crates")
            .join("dummy");
        std::fs::create_dir_all(&traversal_dir).unwrap();

        // This path: "../franken_engine/crates/dummy/../franken-engine"
        // Would canonicalize to the legitimate path but should be rejected due to traversal
        assert!(
            !validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/dummy/../franken-engine"
            ),
            "Should reject path with traversal components even if it canonicalizes correctly"
        );

        // Test 5: Path that looks like "franken_engine/../../../etc" - should be rejected due to traversal
        // We don't need to create this path since the traversal check will reject it before canonicalization
        assert!(
            !validate_engine_dependency_path(&cargo_file, "../franken_engine/../../../etc"),
            "Should reject traversal attack attempting to escape to /etc"
        );

        // Test 6: Legitimate extension host should still work
        assert!(
            validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/franken-extension-host"
            ),
            "Legitimate extension host path should be allowed"
        );
    }
}
