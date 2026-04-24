use frankenengine_node::migration::{
    MigrationAuditReport, MigrationRewriteReport, MigrationRollbackPlan, MigrationValidateReport,
    run_rewrite,
};
use proptest::prelude::*;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::path::Path;

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

fn write_rewrite_fixture_file(project: &Path, relative_path: &str, content: &str) -> TestResult {
    let path = project.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create parent directory for {relative_path}: {err}"))?;
    }
    std::fs::write(path, content).map_err(|err| format!("write {relative_path}: {err}"))
}

fn write_rewrite_metamorphic_fixture(project: &Path, seed: u8) -> TestResult {
    match seed % 4 {
        0 => {
            write_rewrite_fixture_file(project, "src/index.js", "console.log('start');\n")?;
            write_rewrite_fixture_file(project, "tools/build.mjs", "console.log('build');\n")?;
            let manifest = serde_json::json!({
                "name": format!("metamorphic-script-{seed}"),
                "version": "1.0.0",
                "scripts": {
                    "start": format!("node src/index.js --seed={seed}"),
                    "build": "bun tools/build.mjs",
                    "lint": "eslint ."
                }
            });
            let manifest = serde_json::to_string_pretty(&manifest)
                .map_err(|err| format!("serialize script manifest: {err}"))?;
            write_rewrite_fixture_file(project, "package.json", &manifest)
        }
        1 => {
            write_rewrite_fixture_file(
                project,
                "package.json",
                r#"{
                  "name":"metamorphic-hardened",
                  "version":"1.0.0",
                  "engines":{"node":">=20 <23"},
                  "scripts":{"test":"node test.js"}
                }"#,
            )?;
            write_rewrite_fixture_file(project, "local.js", "module.exports = 42;\n")?;
            write_rewrite_fixture_file(
                project,
                "index.js",
                "const fs = require(\"fs\");\nconst local = require(\"./local\");\nconsole.log(fs.existsSync(\"package.json\"), local);\n",
            )
        }
        2 => {
            let manifest = serde_json::json!({
                "name": format!("metamorphic-esm-{seed}"),
                "version": "1.0.0",
                "type": "module",
                "engines": {"node": ">=20 <23"}
            });
            let manifest = serde_json::to_string_pretty(&manifest)
                .map_err(|err| format!("serialize esm manifest: {err}"))?;
            write_rewrite_fixture_file(project, "package.json", &manifest)?;
            write_rewrite_fixture_file(
                project,
                "src/index.js",
                "import fs from \"fs\";\nimport path from \"path\";\nexport const exists = fs.existsSync(path.join(\".\"));\n",
            )
        }
        _ => {
            write_rewrite_fixture_file(project, "src/local.js", "module.exports = 'local';\n")?;
            write_rewrite_fixture_file(
                project,
                "src/index.js",
                "const path = require(\"path\");\nconst local = require(\"./local\");\nconsole.log(path.sep, local);\n",
            )?;
            let manifest = serde_json::json!({
                "name": format!("metamorphic-combo-{seed}"),
                "version": "1.0.0",
                "scripts": {
                    "start": format!("node src/index.js --seed={seed}")
                }
            });
            let manifest = serde_json::to_string_pretty(&manifest)
                .map_err(|err| format!("serialize combo manifest: {err}"))?;
            write_rewrite_fixture_file(project, "package.json", &manifest)
        }
    }
}

fn project_text_snapshot(project: &Path) -> Result<Vec<(String, String)>, String> {
    fn collect(project: &Path, dir: &Path, snapshot: &mut Vec<(String, String)>) -> TestResult {
        let mut entries = std::fs::read_dir(dir)
            .map_err(|err| format!("read directory {}: {err}", dir.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|err| format!("read directory entry in {}: {err}", dir.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();

        for path in entries {
            if path.is_dir() {
                collect(project, &path, snapshot)?;
            } else {
                let relative = path
                    .strip_prefix(project)
                    .map_err(|err| format!("strip project prefix from {}: {err}", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = std::fs::read_to_string(&path)
                    .map_err(|err| format!("read text file {}: {err}", path.display()))?;
                snapshot.push((relative, text));
            }
        }

        Ok(())
    }

    let mut snapshot = Vec::new();
    collect(project, project, &mut snapshot)?;
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(snapshot)
}

proptest! {
    #[test]
    fn migration_rewrite_apply_many_inputs_reaches_fixed_point(seed in 0_u8..64) {
        let temp = tempfile::tempdir()
            .map_err(|err| TestCaseError::fail(format!("create tempdir: {err}")))?;
        let project = temp.path();
        write_rewrite_metamorphic_fixture(project, seed)
            .map_err(TestCaseError::fail)?;

        let first = run_rewrite(project, true)
            .map_err(|err| TestCaseError::fail(format!("first rewrite failed: {err}")))?;
        prop_assert!(first.rewrites_applied <= first.rewrites_planned);
        let after_first = project_text_snapshot(project).map_err(TestCaseError::fail)?;

        let second = run_rewrite(project, true)
            .map_err(|err| TestCaseError::fail(format!("second rewrite failed: {err}")))?;
        let after_second = project_text_snapshot(project).map_err(TestCaseError::fail)?;
        prop_assert_eq!(
            &after_first,
            &after_second,
            "rewrite(apply(rewrite(apply(project)))) changed the fixed-point project"
        );
        prop_assert_eq!(second.rewrites_applied, 0);
        prop_assert_eq!(second.rollback_entries.len(), 0);

        let dry_run_after_apply = run_rewrite(project, false)
            .map_err(|err| TestCaseError::fail(format!("dry run after apply failed: {err}")))?;
        let after_dry_run = project_text_snapshot(project).map_err(TestCaseError::fail)?;
        prop_assert_eq!(
            &after_second,
            &after_dry_run,
            "dry-run rewrite mutated a fixed-point project"
        );
        prop_assert_eq!(dry_run_after_apply.rewrites_planned, 0);
        prop_assert_eq!(dry_run_after_apply.rewrites_applied, 0);
    }
}
