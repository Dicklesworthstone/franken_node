use anyhow::{Context, Result};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const CLOSE_CONDITION_RECEIPT_PATH: &str = "artifacts/oracle/close_condition_receipt.json";
const COMPATIBILITY_CORPUS_RESULTS_PATH: &str = "artifacts/13/compatibility_corpus_results.json";
const SECTION_10N_GATE_VERDICT_PATH: &str =
    "artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json";
const CLOSE_CONDITION_TIMESTAMP_ENV: &str = "FRANKEN_NODE_CLOSE_CONDITION_TIMESTAMP_UTC";
pub const MAX_CLOSE_CONDITION_CARGO_FILES: usize = 256;
pub const MAX_CLOSE_CONDITION_SCAN_FILES: usize = 4_096;
const CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN: &[u8] = b"close_condition_receipt_v1:";

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
    pub total_test_cases: u64,
    pub passed_test_cases: u64,
    pub failed_test_cases: u64,
    pub errored_test_cases: u64,
    pub skipped_test_cases: u64,
    pub pass_rate_pct: f64,
    pub required_pass_rate_pct: f64,
    pub blocking_findings: Vec<String>,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    if signature.algorithm != "ed25519" {
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

    let public_key_bytes = hex::decode(&signature.public_key_hex)
        .context("close-condition receipt public key must be hex")?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("expected 32 public key bytes, got {}", bytes.len())
    })?;
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

    let signature_bytes = hex::decode(&signature.signature_hex)
        .context("close-condition receipt signature must be hex")?;
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("expected 64 signature bytes, got {}", bytes.len())
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&signed_preimage, &signature)
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

    L1ProductOracle {
        verdict: if blocking_findings.is_empty() {
            OracleColor::Green
        } else {
            OracleColor::Red
        },
        source_path,
        corpus_version,
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
        for pattern in internal_patterns {
            if content.contains(pattern) {
                violations.push(serde_json::json!({
                    "file": relative_path(root, rust_file),
                    "pattern": pattern,
                }));
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
        "franken_engine/crates/frankenengine-engine",
        "franken_engine/crates/frankenengine-extension-host",
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

fn close_condition_receipt_signed_preimage(canonical_json: &str) -> Vec<u8> {
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

    #[test]
    fn test_engine_dependency_paths_proper_toml_parsing() {
        // Test that we properly parse TOML instead of using string scanning
        let content = r#"
[dependencies]
frankenengine-engine = { path = "../franken_engine/crates/frankenengine-engine", version = "0.1.0" }
some-other-crate = "1.0.0"

[dev-dependencies]
frankenengine-extension-host = { path = "../franken_engine/crates/frankenengine-extension-host" }
"#;

        let paths = engine_dependency_paths(content, "frankenengine-engine");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "../franken_engine/crates/frankenengine-engine");

        let paths = engine_dependency_paths(content, "frankenengine-extension-host");
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0],
            "../franken_engine/crates/frankenengine-extension-host"
        );

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
        let malicious_path = "/franken_engine/crates/frankenengine-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject absolute path: {}",
            malicious_path
        );

        // Attack 5: Windows absolute paths should be rejected
        let malicious_path = "C:\\franken_engine\\crates\\frankenengine-engine";
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
        let malicious_path = "../not_franken_engine/crates_imposter/frankenengine-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike: {}",
            malicious_path
        );

        // Attack 7: "franken_engine_crates" - looks similar but missing separator
        let malicious_path = "../franken_engine_crates/frankenengine-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike: {}",
            malicious_path
        );

        // Attack 8: "some_franken_engine/crates/" - contains target but with prefix
        let malicious_path = "../some_franken_engine/crates/frankenengine-engine";
        assert!(
            !validate_engine_dependency_path(&cargo_file, malicious_path),
            "Should reject substring look-alike with prefix: {}",
            malicious_path
        );

        // Attack 9: "franken_engine/crates_but_not_really/" - starts right but ends wrong
        let malicious_path = "../franken_engine/crates_but_not_really/frankenengine-engine";
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
        std::fs::create_dir_all(&franken_engine_dir.join("frankenengine-engine")).unwrap();
        std::fs::create_dir_all(&franken_engine_dir.join("frankenengine-extension-host")).unwrap();

        // These legitimate paths should be allowed
        let legitimate_paths = [
            "../franken_engine/crates/frankenengine-engine",
            "../franken_engine/crates/frankenengine-extension-host",
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
        std::fs::create_dir_all(&franken_engine_dir.join("frankenengine-engine")).unwrap();
        std::fs::create_dir_all(&franken_engine_dir.join("frankenengine-extension-host")).unwrap();

        // Create malicious directories that contain the allowed path as a suffix
        std::fs::create_dir_all(&franken_engine_dir.join("frankenengine-engine_evil")).unwrap();
        std::fs::create_dir_all(&franken_engine_dir.join("prefix_frankenengine-engine")).unwrap();

        // Test 1: Legitimate path should pass
        assert!(
            validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/frankenengine-engine"
            ),
            "Legitimate path should be allowed"
        );

        // Test 2: frankenengine-engine_evil should be rejected (suffix bypass attack)
        assert!(
            !validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/frankenengine-engine_evil"
            ),
            "Should reject suffix bypass attack: frankenengine-engine_evil"
        );

        // Test 3: prefix_frankenengine-engine should be rejected (suffix bypass attack)
        assert!(
            !validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/prefix_frankenengine-engine"
            ),
            "Should reject suffix bypass attack: prefix_frankenengine-engine"
        );

        // Test 4: Create traversal path that canonicalizes to legitimate location but has traversal
        // This tests that even after canonicalization, we still reject paths with traversal components
        let traversal_dir = temp_dir
            .path()
            .join("franken_engine")
            .join("crates")
            .join("dummy");
        std::fs::create_dir_all(&traversal_dir).unwrap();

        // This path: "../franken_engine/crates/dummy/../frankenengine-engine"
        // Would canonicalize to the legitimate path but should be rejected due to traversal
        assert!(
            !validate_engine_dependency_path(
                &cargo_file,
                "../franken_engine/crates/dummy/../frankenengine-engine"
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
                "../franken_engine/crates/frankenengine-extension-host"
            ),
            "Legitimate extension host path should be allowed"
        );
    }
}
