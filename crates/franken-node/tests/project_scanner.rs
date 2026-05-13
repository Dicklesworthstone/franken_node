use frankenengine_node::supply_chain::project_scanner::{
    MigrationReadiness, PROJECT_SCANNER_GATE, PROJECT_SCANNER_SCHEMA_ID, ProjectScanError,
    RiskLevel, load_default_registry, scan_project_at, scan_project_with_registry_at,
    verification_report_at,
};
use std::collections::BTreeSet;
use tempfile::tempdir;

#[test]
fn scans_js_project_into_schema_compatible_report() {
    let tmp = tempdir().expect("tempdir");
    let project = tmp.path();
    std::fs::write(
        project.join("app.js"),
        "const fs = require('fs');\n\
         const path = require('path');\n\
         const data = fs.readFileSync('config.json', 'utf8');\n\
         const full = path.join(__dirname, 'data');\n\
         console.log(process.env.NODE_ENV);\n",
    )
    .expect("write app");
    std::fs::write(
        project.join("server.js"),
        "const http = require('http');\n\
         http.createServer((req, res) => res.end('ok')).listen(3000);\n",
    )
    .expect("write server");
    std::fs::write(
        project.join("package.json"),
        r#"{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"}}"#,
    )
    .expect("write package");

    let report = scan_project_at(project, "2026-05-13T00:00:00Z").expect("scan");
    let api_names: BTreeSet<_> = report
        .api_usage
        .iter()
        .map(|usage| (usage.api_family.as_str(), usage.api_name.as_str()))
        .collect();

    assert_eq!(report.scan_timestamp, "2026-05-13T00:00:00Z");
    assert!(api_names.contains(&("fs", "readFile")));
    assert!(api_names.contains(&("fs", "readFileSync")));
    assert!(api_names.contains(&("path", "join")));
    assert!(api_names.contains(&("process", "env")));
    assert!(api_names.contains(&("http", "createServer")));
    assert_eq!(report.summary.total_apis_detected, 5);
    assert_eq!(report.dependencies.len(), 2);
    assert_eq!(
        report.summary.migration_readiness,
        MigrationReadiness::Partial
    );

    let json = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(
        json.get("summary")
            .and_then(|summary| summary.get("migration_readiness"))
            .and_then(|readiness| readiness.as_str()),
        Some("partial")
    );
}

#[test]
fn native_addon_and_unsafe_api_make_project_not_ready() {
    let tmp = tempdir().expect("tempdir");
    let project = tmp.path();
    std::fs::write(project.join("index.js"), "eval('alert(1)');\n").expect("write index");
    std::fs::write(
        project.join("package.json"),
        r#"{"dependencies":{"sharp":"^0.32.0","express":"^4.18.0"}}"#,
    )
    .expect("write package");

    let report = scan_project_at(project, "2026-05-13T00:00:00Z").expect("scan");

    assert_eq!(
        report.summary.migration_readiness,
        MigrationReadiness::NotReady
    );
    assert_eq!(report.summary.risk_distribution.critical, 2);
    assert!(report.recommendations.iter().any(|recommendation| {
        recommendation.category == "blocking" && recommendation.severity == "error"
    }));
    assert!(
        report
            .api_usage
            .iter()
            .any(|usage| usage.api_family == "unsafe" && usage.risk_level == RiskLevel::Critical)
    );
}

#[test]
fn fixed_timestamp_scans_are_deterministic_and_skip_node_modules() {
    let tmp = tempdir().expect("tempdir");
    let project = tmp.path();
    let node_modules = project.join("node_modules");
    std::fs::create_dir(&node_modules).expect("create node_modules");
    std::fs::write(
        node_modules.join("ignored.js"),
        "const env = process.env.NODE_ENV;\n",
    )
    .expect("write ignored");
    std::fs::write(project.join("cli.ts"), "const argv = process.argv;\n").expect("write cli");

    let registry = load_default_registry().expect("registry");
    let first = scan_project_with_registry_at(project, &registry, "2026-05-13T00:00:00Z")
        .expect("first scan");
    let second = scan_project_with_registry_at(project, &registry, "2026-05-13T00:00:00Z")
        .expect("second scan");

    assert_eq!(first, second);
    assert_eq!(first.summary.total_apis_detected, 1);
    assert_eq!(first.api_usage[0].api_name, "argv");
}

#[test]
fn malformed_package_json_fails_closed() {
    let tmp = tempdir().expect("tempdir");
    let project = tmp.path();
    std::fs::write(project.join("package.json"), "{not-json").expect("write malformed package");

    let error = scan_project_at(project, "2026-05-13T00:00:00Z")
        .expect_err("malformed package should fail closed");

    assert!(matches!(error, ProjectScanError::Json { .. }));
}

#[test]
fn verification_report_exercises_rust_scanner_contract() {
    let tmp = tempdir().expect("tempdir");
    let project = tmp.path();
    std::fs::write(
        project.join("index.js"),
        "const env = process.env.NODE_ENV;\n",
    )
    .expect("write index");
    std::fs::write(
        project.join("package.json"),
        r#"{"dependencies":{"express":"^4.18.0"}}"#,
    )
    .expect("write package");

    let report = verification_report_at(project, "2026-05-13T00:00:00Z").expect("verification");
    let json = serde_json::to_value(&report.sample_report).expect("serialize sample report");

    assert_eq!(
        PROJECT_SCANNER_SCHEMA_ID,
        "franken_node/migration/scan_report/v1"
    );
    assert_eq!(report.gate, PROJECT_SCANNER_GATE);
    assert_eq!(report.verdict, "PASS");
    assert_eq!(report.summary.failing_checks, 0);
    assert!(
        json.get("api_usage")
            .and_then(|value| value.as_array())
            .is_some()
    );
}
