use frankenengine_node::migration::rewrite_suggestion_engine::RewriteApiUsage;
use frankenengine_node::migration::rewrite_suggestion_engine::{
    REWRITE_ENGINE_GATE, REWRITE_ENGINE_SCHEMA_ID, RewriteCategory, RewriteRiskLevel,
    RewriteSuggestionReport, generate_suggestions, produce_report_at, rewrite_rule_count,
    unsafe_rewrite_count, verification_report_at,
};
use frankenengine_node::supply_chain::project_scanner::scan_project_at;
use tempfile::tempdir;

#[test]
fn rust_project_scan_feeds_rewrite_suggestion_report() {
    let tmp = tempdir().expect("tempdir");
    let project = tmp.path();
    std::fs::write(
        project.join("app.js"),
        "const fs = require('fs');\n\
         const path = require('path');\n\
         const data = fs.readFileSync('config.json', 'utf8');\n\
         const full = path.join(__dirname, 'data');\n\
         const mode = process.env.NODE_ENV;\n\
         eval(data);\n",
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
        r#"{"dependencies":{"express":"^4.18.0"}}"#,
    )
    .expect("write package");

    let scan = scan_project_at(project, "2026-05-13T00:00:00Z").expect("scan");
    let report = produce_report_at(&scan, "2026-05-13T00:01:00Z");

    assert_eq!(report.schema_version, REWRITE_ENGINE_SCHEMA_ID);
    assert_eq!(report.report_timestamp, "2026-05-13T00:01:00Z");
    assert_eq!(report.summary.total_suggestions, 6);
    assert_eq!(report.suggestions[0].risk_level, RewriteRiskLevel::Critical);
    assert_eq!(
        report.suggestions[0].category,
        RewriteCategory::RemovalNeeded
    );
    assert!(
        report
            .suggestions
            .iter()
            .any(|suggestion| suggestion.category == RewriteCategory::AdapterNeeded)
    );
    assert_eq!(report.rollback_plan.suggestion_count, 6);
    assert_eq!(report.rollback_plan.affected_files.len(), 2);
    assert!(
        report
            .rollback_plan
            .rollback_commands
            .iter()
            .all(|command| command.argv[0] == "git" && command.argv[2] == "--")
    );
}

#[test]
fn unknown_and_unsafe_apis_get_deterministic_categories() {
    let usages = vec![
        RewriteApiUsage {
            api_family: "path".to_string(),
            api_name: "join".to_string(),
            source_file: "a.js".to_string(),
            line_number: Some(1),
            risk_level: RewriteRiskLevel::Low,
        },
        RewriteApiUsage {
            api_family: "unsafe".to_string(),
            api_name: "process.binding".to_string(),
            source_file: "legacy.js".to_string(),
            line_number: Some(7),
            risk_level: RewriteRiskLevel::Critical,
        },
        RewriteApiUsage {
            api_family: "native_addon".to_string(),
            api_name: "sharp".to_string(),
            source_file: "package.json".to_string(),
            line_number: None,
            risk_level: RewriteRiskLevel::Medium,
        },
    ];

    let suggestions = generate_suggestions(&usages);

    assert_eq!(suggestions[0].api_name, "process.binding");
    assert_eq!(suggestions[0].category, RewriteCategory::RemovalNeeded);
    assert_eq!(suggestions[1].category, RewriteCategory::ManualReview);
    assert_eq!(suggestions[2].category, RewriteCategory::DirectReplacement);
}

#[test]
fn report_generation_is_deterministic_for_fixed_timestamp() {
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

    let scan = scan_project_at(project, "2026-05-13T00:00:00Z").expect("scan");
    let first = produce_report_at(&scan, "2026-05-13T00:01:00Z");
    let second = produce_report_at(&scan, "2026-05-13T00:01:00Z");

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_string(&first).expect("serialize first"),
        serde_json::to_string(&second).expect("serialize second")
    );
}

#[test]
fn rollback_commands_quote_paths_and_preserve_argv() {
    let usages = vec![RewriteApiUsage {
        api_family: "fs".to_string(),
        api_name: "readFileSync".to_string(),
        source_file: "src/has space's.js".to_string(),
        line_number: Some(3),
        risk_level: RewriteRiskLevel::Low,
    }];

    let suggestions = generate_suggestions(&usages);
    let command = &suggestions
        .first()
        .expect("rewrite suggestion for fs.readFileSync")
        .rollback;

    assert_eq!(
        command.argv,
        vec![
            "git".to_string(),
            "restore".to_string(),
            "--".to_string(),
            "src/has space's.js".to_string()
        ]
    );
    assert!(command.command.contains("'src/has space'\\''s.js'"));
}

#[test]
fn verification_report_covers_rules_priority_and_rollback() {
    let verification = verification_report_at("2026-05-13T00:02:00Z");
    let sample_json =
        serde_json::to_value(&verification.sample_report).expect("serialize sample report");

    assert_eq!(verification.gate, REWRITE_ENGINE_GATE);
    assert_eq!(verification.verdict, "PASS");
    assert_eq!(verification.summary.failing_checks, 0);
    assert_eq!(rewrite_rule_count(), 12);
    assert_eq!(unsafe_rewrite_count(), 4);
    assert!(
        sample_json
            .get("suggestions")
            .and_then(|value| value.as_array())
            .is_some()
    );
    let _: RewriteSuggestionReport =
        serde_json::from_value(sample_json).expect("sample report round-trips");
}
