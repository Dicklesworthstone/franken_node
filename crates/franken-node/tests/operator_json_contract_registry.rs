use frankenengine_node::operator_json_contracts::{
    OperatorJsonContractError, OperatorJsonSurface, all_operator_json_contracts,
    operator_json_registry_report, registered_surface_names, validate_operator_json_value,
};
use serde_json::Value;

fn snapshot_json(snapshot: &str) -> Value {
    let trimmed = snapshot.trim_start();
    let json_start = if let Some(stripped) = trimmed.strip_prefix("---") {
        let end = stripped
            .find("\n---")
            .expect("insta snapshot frontmatter terminator");
        &stripped[end + "\n---".len()..]
    } else {
        trimmed
    };
    serde_json::from_str(json_start.trim()).expect("snapshot should contain JSON")
}

#[test]
fn registry_reports_eight_operator_contracts_with_redaction_guidance() {
    let report = operator_json_registry_report();
    assert_eq!(
        report.schema_id,
        "franken-node/operator-json-contract-registry"
    );
    assert_eq!(report.contract_count, all_operator_json_contracts().len());
    assert!(report.contract_count >= 5);
    assert!(report.redaction_guidance.len() >= 4);

    let surfaces = registered_surface_names();
    for expected in [
        "doctor_report",
        "verify_release_report",
        "fleet_reconcile_report",
        "trust_card_export",
        "incident_bundle",
        "bench_run_report",
        "runtime_epoch_report",
        "remote_capability_issue_report",
    ] {
        assert!(surfaces.contains(expected), "missing {expected}");
    }
}

#[test]
fn existing_golden_json_outputs_satisfy_registered_contracts() {
    let cases = [
        (
            OperatorJsonSurface::DoctorReport,
            include_str!("goldens/doctor_cli/doctor_json.snap"),
        ),
        (
            OperatorJsonSurface::VerifyReleaseReport,
            include_str!("goldens/verify_cli/verify_release_json.snap"),
        ),
        (
            OperatorJsonSurface::FleetReconcileReport,
            include_str!("goldens/fleet_cli/fleet_reconcile_json.snap"),
        ),
        (
            OperatorJsonSurface::TrustCardExport,
            include_str!("goldens/trust_card_cli/export_acme.json.snap"),
        ),
        (
            OperatorJsonSurface::IncidentBundle,
            include_str!("goldens/incident/bundle_basic.fnbundle.json.golden"),
        ),
        (
            OperatorJsonSurface::BenchRunReport,
            include_str!("goldens/bench_cli/bench_run_secure_extension_heavy_json.snap"),
        ),
        (
            OperatorJsonSurface::RuntimeEpochReport,
            include_str!("goldens/runtime_cli/runtime_epoch_mismatch_json.snap"),
        ),
        (
            OperatorJsonSurface::RemoteCapabilityIssueReport,
            include_str!("goldens/remotecap_cli/remotecap_issue_json.snap"),
        ),
    ];

    for (surface, raw) in cases {
        let json = snapshot_json(raw);
        validate_operator_json_value(surface, &json)
            .unwrap_or_else(|errors| panic!("{surface:?} contract errors: {errors:?}"));
    }
}

#[test]
fn validator_fails_negative_fixture_when_required_field_is_renamed_or_dropped() {
    let negative = snapshot_json(include_str!(
        "../../../artifacts/operator_json_contracts/bd-mka4a_negative_fixture.json"
    ));
    let errors = validate_operator_json_value(OperatorJsonSurface::VerifyReleaseReport, &negative)
        .expect_err("negative fixture must fail");
    assert_eq!(
        errors,
        vec![OperatorJsonContractError::MissingRequiredField {
            surface: OperatorJsonSurface::VerifyReleaseReport,
            field_path: "overall_pass".to_string(),
        }]
    );
}

#[test]
fn additive_optional_fields_do_not_break_registered_contract() {
    let mut value = snapshot_json(include_str!("goldens/doctor_cli/doctor_json.snap"));
    value
        .as_object_mut()
        .expect("doctor report should be an object")
        .insert(
            "future_additive_diagnostic".to_string(),
            serde_json::json!({"ok": true}),
        );

    validate_operator_json_value(OperatorJsonSurface::DoctorReport, &value)
        .expect("additive optional diagnostic field should pass");
}
