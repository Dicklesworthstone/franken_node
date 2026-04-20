use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn stream_corpus_manifest_is_fixture_backed_and_reported() -> TestResult {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus_root = crate_root.join("tests/fixtures/compat_corpus/stream");
    let manifest_path = corpus_root.join("manifest.json");
    let manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
    let cases = manifest
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("stream manifest cases must be an array")?;

    require(
        cases.len() == 20,
        "stream corpus must contain 20 fixture cases",
    )?;
    require(
        manifest
            .get("lockstep")
            .and_then(|lockstep| lockstep.get("harness"))
            .and_then(Value::as_str)
            .is_some_and(|command| command.contains("verify lockstep")),
        "stream corpus manifest must declare lockstep harness execution",
    )?;

    let mut manifest_ids = BTreeSet::new();
    for case in cases {
        let case_id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or("stream fixture case id must be a string")?;
        let fixture_file = case
            .get("file")
            .and_then(Value::as_str)
            .ok_or("stream fixture case file must be a string")?;
        let fixture_path = corpus_root.join(fixture_file);
        require(
            fixture_path.is_file(),
            format!("stream fixture missing: {}", fixture_path.display()),
        )?;
        let fixture_source = fs::read_to_string(&fixture_path)?;
        require(
            fixture_source.contains(case_id),
            format!("stream fixture {} must emit its manifest id", fixture_file),
        )?;
        require(
            manifest_ids.insert(case_id.to_string()),
            format!("duplicate stream fixture id: {case_id}"),
        )?;
    }

    let report_path = crate_root
        .join("../..")
        .join("artifacts/13/compatibility_corpus_results.json");
    let report: Value = serde_json::from_str(&fs::read_to_string(&report_path)?)?;
    let stream_family = report
        .get("api_families")
        .and_then(Value::as_array)
        .and_then(|families| {
            families
                .iter()
                .find(|family| family.get("family").and_then(Value::as_str) == Some("stream"))
        })
        .ok_or("compatibility report must contain stream family")?;
    require(
        stream_family.get("total").and_then(Value::as_u64) == Some(65),
        "stream family total must include the 20 fixture-backed stream cases",
    )?;

    let reported_ids: BTreeSet<String> = report
        .get("per_test_results")
        .and_then(Value::as_array)
        .ok_or("compatibility report per_test_results must be an array")?
        .iter()
        .filter_map(|row| row.get("test_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    for case_id in manifest_ids {
        require(
            reported_ids.contains(&case_id),
            format!("compatibility report missing stream case {case_id}"),
        )?;
    }

    Ok(())
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
