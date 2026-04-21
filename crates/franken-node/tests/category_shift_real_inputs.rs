use frankenengine_node::supply_chain::category_shift::EvidenceInput;
use frankenengine_node::supply_chain::category_shift::{
    BetStatus, CategoryShiftDimensionInput, CategoryShiftError, ClaimInput, MoonshotBetEntry,
    ReportDimension, build_category_shift_report, sha256_hex,
};

fn evidence(path: &str, content: &str, now_secs: u64) -> EvidenceInput {
    EvidenceInput {
        artifact_path: path.to_string(),
        sha256_hash: sha256_hex(content.as_bytes()),
        generated_at_secs: now_secs.saturating_sub(60),
        content: Some(content.to_string()),
    }
}

fn claim(summary: &str, value: f64, unit: &str, evidence: EvidenceInput) -> ClaimInput {
    ClaimInput {
        summary: summary.to_string(),
        value,
        unit: unit.to_string(),
        evidence,
    }
}

#[test]
fn category_shift_report_uses_caller_supplied_evidence() {
    let now: u64 = 1_000_000;
    let benchmark = r#"{"compatibility_percent":97,"suite":"caller-benchmark"}"#;
    let security = r#"{"compromise_reduction":12,"suite":"caller-security"}"#;
    let migration = r#"{"migration_velocity":4,"suite":"caller-migration"}"#;
    let dimensions = vec![
        CategoryShiftDimensionInput {
            dimension: ReportDimension::BenchmarkComparisons,
            source_name: "real-benchmark-job".to_string(),
            source_bead: "bd-real-benchmark".to_string(),
            claims: vec![claim(
                "caller benchmark evidence exceeds compatibility target",
                97.0,
                "percent",
                evidence("artifacts/real/benchmark.json", benchmark, now),
            )],
        },
        CategoryShiftDimensionInput {
            dimension: ReportDimension::SecurityPosture,
            source_name: "real-security-job".to_string(),
            source_bead: "bd-real-security".to_string(),
            claims: vec![claim(
                "caller security evidence exceeds compromise target",
                12.0,
                "factor",
                evidence("artifacts/real/security.json", security, now),
            )],
        },
        CategoryShiftDimensionInput {
            dimension: ReportDimension::MigrationVelocity,
            source_name: "real-migration-job".to_string(),
            source_bead: "bd-real-migration".to_string(),
            claims: vec![claim(
                "caller migration evidence exceeds velocity target",
                4.0,
                "factor",
                evidence("artifacts/real/migration.json", migration, now),
            )],
        },
    ];
    let bets = vec![MoonshotBetEntry {
        initiative_id: "caller-moonshot".to_string(),
        title: "Caller supplied moonshot".to_string(),
        status: BetStatus::OnTrack,
        progress_percent: 90,
        blockers: vec![],
        projected_completion: "2026-Q2".to_string(),
    }];

    let (_, report) = build_category_shift_report(now, "trace-real", &dimensions, &bets).unwrap();

    assert_eq!(report.dimensions.len(), 3);
    assert_eq!(report.claims.len(), 3);
    assert_eq!(report.bet_status[0].initiative_id, "caller-moonshot");
    assert!(
        report
            .claims
            .iter()
            .any(|claim| claim.summary.contains("caller benchmark evidence"))
    );
    assert!(report.manifest.iter().any(|entry| {
        entry.artifact_path == "artifacts/real/benchmark.json"
            && entry.sha256_hash == sha256_hex(benchmark.as_bytes())
    }));

    let (_, second_report) =
        build_category_shift_report(now, "trace-real", &dimensions, &bets).unwrap();
    assert_eq!(report.report_hash, second_report.report_hash);
}

#[test]
fn category_shift_report_rejects_missing_evidence_content() {
    let now: u64 = 1_000_000;
    let dimensions = vec![CategoryShiftDimensionInput {
        dimension: ReportDimension::EconomicImpact,
        source_name: "real-economics-job".to_string(),
        source_bead: "bd-real-economics".to_string(),
        claims: vec![ClaimInput {
            summary: "missing evidence content must fail closed".to_string(),
            value: 4.2,
            unit: "ratio".to_string(),
            evidence: EvidenceInput {
                artifact_path: "artifacts/real/economics.json".to_string(),
                sha256_hash: sha256_hex(b"{}"),
                generated_at_secs: now.saturating_sub(60),
                content: None,
            },
        }],
    }];

    let err = build_category_shift_report(now, "trace-missing", &dimensions, &[]).unwrap_err();

    assert!(
        matches!(err, CategoryShiftError::EvidenceMissingContent(path) if path == "artifacts/real/economics.json")
    );
}
