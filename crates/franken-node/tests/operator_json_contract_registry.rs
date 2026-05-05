use frankenengine_node::operator_json_contracts::{
    OperatorJsonContractError, OperatorJsonSurface, all_operator_json_contracts,
    operator_json_registry_report, registered_surface_names, validate_operator_json_value,
};
use serde_json::Value;
use std::error::Error;

fn snapshot_json(snapshot: &str) -> Result<Value, Box<dyn Error>> {
    let trimmed = snapshot.trim_start();
    let json_start = if let Some(stripped) = trimmed.strip_prefix("---") {
        let end = stripped
            .find("\n---")
            .ok_or("insta snapshot frontmatter terminator missing")?;
        stripped
            .get(end + "\n---".len()..)
            .ok_or("insta snapshot frontmatter terminator was not a string boundary")?
    } else {
        trimmed
    };
    Ok(serde_json::from_str(json_start.trim())?)
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
fn existing_golden_json_outputs_satisfy_registered_contracts() -> Result<(), Box<dyn Error>> {
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
        let json = snapshot_json(raw)?;
        let result = validate_operator_json_value(surface, &json);
        assert!(
            result.is_ok(),
            "{surface:?} contract errors: {:?}",
            result.err()
        );
    }
    Ok(())
}

#[test]
fn validator_fails_negative_fixture_when_required_field_is_renamed_or_dropped()
-> Result<(), Box<dyn Error>> {
    let negative = snapshot_json(include_str!(
        "../../../artifacts/operator_json_contracts/bd-mka4a_negative_fixture.json"
    ))?;
    let Err(errors) =
        validate_operator_json_value(OperatorJsonSurface::VerifyReleaseReport, &negative)
    else {
        return Err("negative fixture must fail".into());
    };
    assert_eq!(
        errors,
        vec![OperatorJsonContractError::MissingRequiredField {
            surface: OperatorJsonSurface::VerifyReleaseReport,
            field_path: "overall_pass".to_string(),
        }]
    );
    Ok(())
}

#[test]
fn additive_optional_fields_do_not_break_registered_contract() -> Result<(), Box<dyn Error>> {
    let mut value = snapshot_json(include_str!("goldens/doctor_cli/doctor_json.snap"))?;
    let Some(object) = value.as_object_mut() else {
        return Err("doctor report should be an object".into());
    };
    object.insert(
        "future_additive_diagnostic".to_string(),
        serde_json::json!({"ok": true}),
    );

    assert!(
        validate_operator_json_value(OperatorJsonSurface::DoctorReport, &value).is_ok(),
        "additive optional diagnostic field should pass"
    );
    Ok(())
}
