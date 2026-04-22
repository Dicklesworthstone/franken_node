use frankenengine_node::migration::{
    MigrationAuditReport, MigrationRewriteReport, MigrationRollbackPlan, MigrationValidateReport,
};
use serde::Deserialize;
use serde_json::{Map, Value};

const MIGRATION_REPORT_SCHEMA_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/migration_report_schema_vectors.json");

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct MigrationReportConformanceVectors {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<MigrationReportVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Deserialize)]
struct MigrationReportVector {
    name: String,
    report_kind: MigrationReportKind,
    report: Value,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MigrationReportKind {
    Audit,
    Validate,
    Rewrite,
    RollbackPlan,
}

fn load_vectors() -> Result<MigrationReportConformanceVectors, String> {
    serde_json::from_str(MIGRATION_REPORT_SCHEMA_VECTORS_JSON)
        .map_err(|err| format!("migration report conformance vectors must parse: {err}"))
}

fn value_object<'a>(
    value: &'a Value,
    vector_name: &str,
    context: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{vector_name}: {context} must be a JSON object"))
}

fn field_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> Result<&'a Map<String, Value>, String> {
    object
        .get(field)
        .ok_or_else(|| format!("{vector_name}: missing object field `{field}`"))
        .and_then(|value| value_object(value, vector_name, field))
}

fn field_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> Result<&'a Vec<Value>, String> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{vector_name}: field `{field}` must be an array"))
}

fn require_string_field(object: &Map<String, Value>, field: &str, vector_name: &str) -> TestResult {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(|_| ())
        .ok_or_else(|| format!("{vector_name}: field `{field}` must be a string"))
}

fn require_bool_field(object: &Map<String, Value>, field: &str, vector_name: &str) -> TestResult {
    object
        .get(field)
        .and_then(Value::as_bool)
        .map(|_| ())
        .ok_or_else(|| format!("{vector_name}: field `{field}` must be a boolean"))
}

fn require_unsigned_field(
    object: &Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> TestResult {
    object
        .get(field)
        .and_then(Value::as_u64)
        .map(|_| ())
        .ok_or_else(|| format!("{vector_name}: field `{field}` must be an unsigned integer"))
}

fn require_nullable_string_field(
    object: &Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> TestResult {
    match object.get(field) {
        Some(Value::String(_)) | Some(Value::Null) => Ok(()),
        _ => Err(format!(
            "{vector_name}: field `{field}` must be a string or null"
        )),
    }
}

fn require_enum_field(
    object: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
    vector_name: &str,
) -> TestResult {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{vector_name}: field `{field}` must be a string enum"))?;
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "{vector_name}: field `{field}` has unsupported enum value `{value}`"
        ))
    }
}

fn assert_field_set(
    object: &Map<String, Value>,
    expected_fields: &[&str],
    vector_name: &str,
    context: &str,
) -> TestResult {
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected_fields.to_vec();
    expected.sort_unstable();

    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{vector_name}: {context} fields changed: expected {expected:?}, actual {actual:?}"
        ))
    }
}

fn assert_common_report_schema(
    object: &Map<String, Value>,
    vector_name: &str,
    fields: &[&str],
) -> TestResult {
    assert_field_set(object, fields, vector_name, "top-level report")?;
    require_string_field(object, "schema_version", vector_name)?;
    require_string_field(object, "project_path", vector_name)?;
    require_string_field(object, "generated_at_utc", vector_name)
}

fn assert_summary_schema(object: &Map<String, Value>, vector_name: &str) -> TestResult {
    assert_field_set(
        object,
        &[
            "files_scanned",
            "js_files",
            "ts_files",
            "package_manifests",
            "risky_scripts",
            "lockfiles",
        ],
        vector_name,
        "audit summary",
    )?;
    for field in [
        "files_scanned",
        "js_files",
        "ts_files",
        "package_manifests",
        "risky_scripts",
    ] {
        require_unsigned_field(object, field, vector_name)?;
    }
    for lockfile in field_array(object, "lockfiles", vector_name)? {
        if !lockfile.is_string() {
            return Err(format!("{vector_name}: lockfiles entries must be strings"));
        }
    }
    Ok(())
}

fn assert_finding_schema(value: &Value, vector_name: &str) -> TestResult {
    let object = value_object(value, vector_name, "finding")?;
    assert_field_set(
        object,
        &[
            "id",
            "category",
            "severity",
            "message",
            "path",
            "recommendation",
        ],
        vector_name,
        "audit finding",
    )?;
    require_string_field(object, "id", vector_name)?;
    require_enum_field(
        object,
        "category",
        &["project", "dependencies", "scripts", "runtime"],
        vector_name,
    )?;
    require_enum_field(
        object,
        "severity",
        &["info", "low", "medium", "high"],
        vector_name,
    )?;
    require_string_field(object, "message", vector_name)?;
    require_nullable_string_field(object, "path", vector_name)?;
    require_nullable_string_field(object, "recommendation", vector_name)
}

fn assert_findings_array_schema(
    object: &Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> TestResult {
    for finding in field_array(object, field, vector_name)? {
        assert_finding_schema(finding, vector_name)?;
    }
    Ok(())
}

fn assert_audit_schema(report: &Value, vector_name: &str) -> TestResult {
    let object = value_object(report, vector_name, "audit report")?;
    assert_common_report_schema(
        object,
        vector_name,
        &[
            "schema_version",
            "project_path",
            "generated_at_utc",
            "summary",
            "findings",
        ],
    )?;
    assert_summary_schema(field_object(object, "summary", vector_name)?, vector_name)?;
    assert_findings_array_schema(object, "findings", vector_name)
}

fn assert_validation_check_schema(value: &Value, vector_name: &str) -> TestResult {
    let object = value_object(value, vector_name, "validation check")?;
    assert_field_set(
        object,
        &["id", "passed", "message", "remediation"],
        vector_name,
        "validation check",
    )?;
    require_string_field(object, "id", vector_name)?;
    require_bool_field(object, "passed", vector_name)?;
    require_string_field(object, "message", vector_name)?;
    require_nullable_string_field(object, "remediation", vector_name)
}

fn assert_validate_schema(report: &Value, vector_name: &str) -> TestResult {
    let object = value_object(report, vector_name, "validate report")?;
    assert_common_report_schema(
        object,
        vector_name,
        &[
            "schema_version",
            "project_path",
            "generated_at_utc",
            "status",
            "checks",
            "blocking_findings",
            "warning_findings",
        ],
    )?;
    require_enum_field(object, "status", &["pass", "fail"], vector_name)?;
    for check in field_array(object, "checks", vector_name)? {
        assert_validation_check_schema(check, vector_name)?;
    }
    assert_findings_array_schema(object, "blocking_findings", vector_name)?;
    assert_findings_array_schema(object, "warning_findings", vector_name)
}

fn assert_rewrite_entry_schema(value: &Value, vector_name: &str) -> TestResult {
    let object = value_object(value, vector_name, "rewrite entry")?;
    assert_field_set(
        object,
        &["id", "path", "action", "detail", "applied"],
        vector_name,
        "rewrite entry",
    )?;
    require_string_field(object, "id", vector_name)?;
    require_nullable_string_field(object, "path", vector_name)?;
    require_enum_field(
        object,
        "action",
        &[
            "pin_node_engine",
            "rewrite_package_script",
            "rewrite_common_js_require",
            "rewrite_esm_import",
            "module_graph_discovery",
            "manual_module_review",
            "manual_script_review",
            "manifest_read_error",
            "manifest_parse_error",
            "no_package_manifest",
        ],
        vector_name,
    )?;
    require_string_field(object, "detail", vector_name)?;
    require_bool_field(object, "applied", vector_name)
}

fn assert_rollback_entry_schema(value: &Value, vector_name: &str) -> TestResult {
    let object = value_object(value, vector_name, "rollback entry")?;
    assert_field_set(
        object,
        &["path", "original_content", "rewritten_content"],
        vector_name,
        "rollback entry",
    )?;
    require_string_field(object, "path", vector_name)?;
    require_string_field(object, "original_content", vector_name)?;
    require_string_field(object, "rewritten_content", vector_name)
}

fn assert_rewrite_schema(report: &Value, vector_name: &str) -> TestResult {
    let object = value_object(report, vector_name, "rewrite report")?;
    assert_common_report_schema(
        object,
        vector_name,
        &[
            "schema_version",
            "project_path",
            "generated_at_utc",
            "apply_mode",
            "package_manifests_scanned",
            "rewrites_planned",
            "rewrites_applied",
            "manual_review_items",
            "entries",
            "rollback_entries",
        ],
    )?;
    require_bool_field(object, "apply_mode", vector_name)?;
    for field in [
        "package_manifests_scanned",
        "rewrites_planned",
        "rewrites_applied",
        "manual_review_items",
    ] {
        require_unsigned_field(object, field, vector_name)?;
    }
    for entry in field_array(object, "entries", vector_name)? {
        assert_rewrite_entry_schema(entry, vector_name)?;
    }
    for entry in field_array(object, "rollback_entries", vector_name)? {
        assert_rollback_entry_schema(entry, vector_name)?;
    }
    Ok(())
}

fn assert_rollback_plan_schema(report: &Value, vector_name: &str) -> TestResult {
    let object = value_object(report, vector_name, "rollback plan")?;
    assert_common_report_schema(
        object,
        vector_name,
        &[
            "schema_version",
            "project_path",
            "generated_at_utc",
            "apply_mode",
            "entry_count",
            "entries",
        ],
    )?;
    require_bool_field(object, "apply_mode", vector_name)?;
    require_unsigned_field(object, "entry_count", vector_name)?;
    for entry in field_array(object, "entries", vector_name)? {
        assert_rollback_entry_schema(entry, vector_name)?;
    }
    Ok(())
}

fn assert_round_trip(vector: &MigrationReportVector) -> TestResult {
    let round_trip = match vector.report_kind {
        MigrationReportKind::Audit => {
            let report: MigrationAuditReport = serde_json::from_value(vector.report.clone())
                .map_err(|err| format!("{} audit report must deserialize: {err}", vector.name))?;
            serde_json::to_value(report)
                .map_err(|err| format!("{} audit report must serialize: {err}", vector.name))?
        }
        MigrationReportKind::Validate => {
            let report: MigrationValidateReport = serde_json::from_value(vector.report.clone())
                .map_err(|err| {
                    format!("{} validate report must deserialize: {err}", vector.name)
                })?;
            serde_json::to_value(report)
                .map_err(|err| format!("{} validate report must serialize: {err}", vector.name))?
        }
        MigrationReportKind::Rewrite => {
            let report: MigrationRewriteReport = serde_json::from_value(vector.report.clone())
                .map_err(|err| format!("{} rewrite report must deserialize: {err}", vector.name))?;
            serde_json::to_value(report)
                .map_err(|err| format!("{} rewrite report must serialize: {err}", vector.name))?
        }
        MigrationReportKind::RollbackPlan => {
            let report: MigrationRollbackPlan = serde_json::from_value(vector.report.clone())
                .map_err(|err| format!("{} rollback plan must deserialize: {err}", vector.name))?;
            serde_json::to_value(report)
                .map_err(|err| format!("{} rollback plan must serialize: {err}", vector.name))?
        }
    };

    if round_trip == vector.report {
        Ok(())
    } else {
        Err(format!(
            "{} migration report round-trip changed JSON shape",
            vector.name
        ))
    }
}

fn assert_schema(vector: &MigrationReportVector) -> TestResult {
    match vector.report_kind {
        MigrationReportKind::Audit => assert_audit_schema(&vector.report, &vector.name),
        MigrationReportKind::Validate => assert_validate_schema(&vector.report, &vector.name),
        MigrationReportKind::Rewrite => assert_rewrite_schema(&vector.report, &vector.name),
        MigrationReportKind::RollbackPlan => {
            assert_rollback_plan_schema(&vector.report, &vector.name)
        }
    }
}

#[test]
fn migration_report_conformance_vectors_cover_required_contract() -> TestResult {
    let vectors = load_vectors()?;
    assert_eq!(
        vectors.schema_version,
        "franken-node/migration-report-schema-conformance/v1"
    );
    assert!(
        !vectors.vectors.is_empty(),
        "migration report conformance vectors must not be empty"
    );

    for required in [
        "MIGRATION-REPORT-COMMON",
        "MIGRATION-AUDIT-REPORT",
        "MIGRATION-VALIDATE-REPORT",
        "MIGRATION-REWRITE-REPORT",
        "MIGRATION-ROLLBACK-PLAN",
    ] {
        assert!(
            vectors
                .coverage
                .iter()
                .any(|row| row.spec_section == required && row.level == "MUST" && row.tested),
            "{required} must be covered by the conformance matrix"
        );
    }

    Ok(())
}

#[test]
fn migration_report_conformance_vectors_round_trip() -> TestResult {
    let vectors = load_vectors()?;
    for vector in &vectors.vectors {
        assert_round_trip(vector)?;
    }
    Ok(())
}

#[test]
fn migration_report_conformance_vectors_match_json_schema() -> TestResult {
    let vectors = load_vectors()?;
    for vector in &vectors.vectors {
        assert_schema(vector)?;
    }
    Ok(())
}
