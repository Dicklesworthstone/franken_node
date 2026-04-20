use anyhow::{Context, Result};
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
    pub placeholder_schema: Option<Value>,
    pub blocking_findings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TamperEvidence {
    pub algorithm: String,
    pub canonicalization: String,
    pub hash_scope: String,
    pub sha256: String,
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

pub fn generate_close_condition_receipt(root: &Path) -> Result<CloseConditionReceipt> {
    let l1_product_oracle = evaluate_l1_product_oracle(root);
    let l2_engine_boundary_oracle = evaluate_l2_engine_boundary_oracle(root)?;
    let release_policy_linkage = evaluate_release_policy_linkage(root);

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
    let tamper_evidence = TamperEvidence {
        algorithm: "SHA-256".to_string(),
        canonicalization: "lexicographically-sorted-json-keys/no-whitespace".to_string(),
        hash_scope: "receipt_without_tamper_evidence".to_string(),
        sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        ),
    };

    Ok(CloseConditionReceipt {
        core,
        tamper_evidence,
    })
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

fn evaluate_release_policy_linkage(root: &Path) -> ReleasePolicyLinkage {
    let source_path = root.join(SECTION_10N_GATE_VERDICT_PATH);
    if let Ok(data) = read_json_value(&source_path) {
        let oracle_check = data
            .get("checks")
            .and_then(Value::as_array)
            .and_then(|checks| {
                checks.iter().find(|check| {
                    get_str(check, &["check_id"]) == Some("10N-ORACLE")
                        || get_str(check, &["name"]) == Some("Dual-Oracle Close Condition Gate")
                })
            });

        if let Some(check) = oracle_check {
            let status = get_str(check, &["status"]).unwrap_or("FAIL");
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
            return ReleasePolicyLinkage {
                verdict,
                source: "ci_gate_output".to_string(),
                ci_outputs_accessible: true,
                ci_output_ref: Some(SECTION_10N_GATE_VERDICT_PATH.to_string()),
                consumed_oracles: vec![
                    "L1_product_oracle".to_string(),
                    "L2_engine_boundary_oracle".to_string(),
                ],
                placeholder_schema: None,
                blocking_findings,
            };
        }
    }

    ReleasePolicyLinkage {
        verdict: OracleColor::Red,
        source: "placeholder_schema".to_string(),
        ci_outputs_accessible: false,
        ci_output_ref: None,
        consumed_oracles: vec![
            "L1_product_oracle".to_string(),
            "L2_engine_boundary_oracle".to_string(),
        ],
        placeholder_schema: Some(serde_json::json!({
            "workflow_ref": "string",
            "run_id": "string|null",
            "consumed_oracles": ["L1_product_oracle", "L2_engine_boundary_oracle"],
            "verdict": "GREEN|RED",
            "artifact_ref": "artifacts/oracle/close_condition_receipt.json"
        })),
        blocking_findings: vec![
            "release-policy CI output was not accessible; emitted placeholder schema".to_string(),
        ],
    }
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
    let cargo_files = collect_files_named(root, "Cargo.toml")?;
    let engine_crates = ["frankenengine-engine", "frankenengine-extension-host"];
    let mut cargo_file_reports = Vec::new();
    let mut violations = Vec::new();

    for cargo_file in cargo_files {
        let content = fs::read_to_string(&cargo_file)
            .with_context(|| format!("failed to read {}", cargo_file.display()))?;
        let mut engine_deps = Vec::new();
        for crate_name in engine_crates {
            for path in engine_dependency_paths(&content, crate_name) {
                let valid = path.contains("franken_engine/crates/")
                    || path.contains("../../../franken_engine/crates/");
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
    let rust_files = collect_rust_files(root)?;
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

fn collect_files_named(root: &Path, name: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut |path| {
        if path.file_name().and_then(|part| part.to_str()) == Some(name) {
            files.push(path.to_path_buf());
        }
    })?;
    Ok(files)
}

fn collect_rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for rel in ["crates", "src"] {
        let base = root.join(rel);
        if base.exists() {
            collect_files(root, &base, &mut |path| {
                if path.extension().and_then(|part| part.to_str()) == Some("rs") {
                    files.push(path.to_path_buf());
                }
            })?;
        }
    }
    Ok(files)
}

fn collect_files(root: &Path, dir: &Path, visit: &mut impl FnMut(&Path)) -> Result<()> {
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
            visit(&path);
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
    let mut remaining = content;
    while let Some(index) = remaining.find(crate_name) {
        let after = &remaining[index + crate_name.len()..];
        let candidate = &after[..after.len().min(512)];
        if let Some(path_key_index) = candidate.find("path") {
            let after_path = &candidate[path_key_index + "path".len()..];
            if let Some(first_quote) = after_path.find('"') {
                let after_quote = &after_path[first_quote + 1..];
                if let Some(second_quote) = after_quote.find('"') {
                    paths.push(after_quote[..second_quote].to_string());
                }
            }
        }
        remaining = after;
    }
    paths
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
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
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
