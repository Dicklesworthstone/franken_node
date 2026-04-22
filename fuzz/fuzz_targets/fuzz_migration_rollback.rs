#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::migration::{
    build_rollback_plan, validate_rollback_plan, MigrationRewriteAction, MigrationRewriteEntry,
    MigrationRewriteReport, MigrationRollbackEntry, MigrationRollbackPlan,
    MigrationRollbackValidationError, MigrationRollbackValidationPolicy,
};
use libfuzzer_sys::fuzz_target;

const MAX_ENTRIES: usize = 32;
const MAX_TEXT_CHARS: usize = 1024;
const MAX_RAW_JSON_BYTES: usize = 128 * 1024;
const MAX_POLICY_CONTENT_BYTES: usize = 64 * 1024;

fuzz_target!(|input: RollbackFuzzInput| {
    let policy = rollback_policy(&input.policy);
    let rewrite_report = rewrite_report(&input);
    let generated_plan = build_rollback_plan(&rewrite_report);
    validate_result_shape(validate_rollback_plan(&generated_plan, &policy));
    validate_plan_consistency(&generated_plan, &policy);

    let explicit_plan = explicit_rollback_plan(&input);
    validate_result_shape(validate_rollback_plan(&explicit_plan, &policy));
    validate_plan_consistency(&explicit_plan, &policy);
    json_round_trip(&explicit_plan, &policy);

    fuzz_raw_rollback_json(&input.raw_json, &policy);
});

fn rollback_policy(input: &PolicyFuzz) -> MigrationRollbackValidationPolicy {
    MigrationRollbackValidationPolicy {
        max_entries: usize::from(input.max_entries % 64),
        max_content_bytes_per_entry: usize::from(input.max_content_kib)
            .saturating_mul(1024)
            .min(MAX_POLICY_CONTENT_BYTES),
        allow_absolute_paths: input.allow_absolute_paths,
    }
}

fn rewrite_report(input: &RollbackFuzzInput) -> MigrationRewriteReport {
    let rollback_entries = rollback_entries(input);
    let entries = rollback_entries
        .iter()
        .enumerate()
        .map(|(index, entry)| MigrationRewriteEntry {
            id: format!("mig-rewrite-{index:03}"),
            path: Some(entry.path.clone()),
            action: rewrite_action(input.selector),
            detail: bounded_text(&input.detail, "detail"),
            applied: input.apply_mode,
        })
        .collect::<Vec<_>>();

    MigrationRewriteReport {
        schema_version: schema_version(input.schema_selector),
        project_path: bounded_project_path(&input.project),
        generated_at_utc: "2026-04-21T00:00:00Z".to_string(),
        apply_mode: input.apply_mode,
        package_manifests_scanned: entries.len(),
        rewrites_planned: entries.len(),
        rewrites_applied: if input.apply_mode { entries.len() } else { 0 },
        manual_review_items: usize::from(input.selector % 8),
        entries,
        rollback_entries,
    }
}

fn explicit_rollback_plan(input: &RollbackFuzzInput) -> MigrationRollbackPlan {
    let entries = rollback_entries(input);
    let entry_count = if input.force_count_mismatch {
        entries
            .len()
            .saturating_add(usize::from(input.count_delta).saturating_add(1))
    } else {
        entries.len()
    };

    MigrationRollbackPlan {
        schema_version: schema_version(input.schema_selector),
        project_path: bounded_project_path(&input.project),
        generated_at_utc: "2026-04-21T00:00:00Z".to_string(),
        apply_mode: input.apply_mode,
        entry_count,
        entries,
    }
}

fn rollback_entries(input: &RollbackFuzzInput) -> Vec<MigrationRollbackEntry> {
    input
        .entries
        .iter()
        .take(MAX_ENTRIES)
        .enumerate()
        .map(|(index, entry)| MigrationRollbackEntry {
            path: rollback_path(index, entry, input.selector),
            original_content: bounded_text(&entry.original_content, "original"),
            rewritten_content: bounded_text(&entry.rewritten_content, "rewritten"),
        })
        .collect()
}

fn rollback_path(index: usize, entry: &EntryFuzz, selector: u8) -> String {
    match selector % 8 {
        0 if entry.allow_empty_path => String::new(),
        1 => format!("/tmp/{}", bounded_text(&entry.path, "rollback.js")),
        2 => format!("..{}", bounded_text(&entry.path, "/rollback.js")),
        3 => format!("nested/../{}", bounded_text(&entry.path, "rollback.js")),
        4 => format!("C:\\{}", bounded_text(&entry.path, "rollback.js")),
        _ => format!("src/{index}/{}", bounded_text(&entry.path, "rollback.js")),
    }
}

fn bounded_project_path(raw: &str) -> String {
    format!("/tmp/franken-node-fuzz/{}", bounded_text(raw, "project"))
}

fn bounded_text(raw: &str, fallback: &str) -> String {
    let mut output = raw
        .chars()
        .filter(|value| !value.is_control())
        .take(MAX_TEXT_CHARS)
        .collect::<String>();
    if output.is_empty() {
        output.push_str(fallback);
    }
    output
}

fn schema_version(selector: u8) -> String {
    if selector % 7 == 0 {
        "0.0.0-fuzz".to_string()
    } else {
        "1.0.0".to_string()
    }
}

fn rewrite_action(selector: u8) -> MigrationRewriteAction {
    match selector % 10 {
        0 => MigrationRewriteAction::PinNodeEngine,
        1 => MigrationRewriteAction::RewritePackageScript,
        2 => MigrationRewriteAction::RewriteCommonJsRequire,
        3 => MigrationRewriteAction::RewriteEsmImport,
        4 => MigrationRewriteAction::ModuleGraphDiscovery,
        5 => MigrationRewriteAction::ManualModuleReview,
        6 => MigrationRewriteAction::ManualScriptReview,
        7 => MigrationRewriteAction::ManifestReadError,
        8 => MigrationRewriteAction::ManifestParseError,
        _ => MigrationRewriteAction::NoPackageManifest,
    }
}

fn validate_plan_consistency(
    plan: &MigrationRollbackPlan,
    policy: &MigrationRollbackValidationPolicy,
) {
    let validation = validate_rollback_plan(plan, policy);
    if validation.is_ok() {
        assert_eq!(plan.schema_version, "1.0.0");
        assert_eq!(plan.entry_count, plan.entries.len());
        assert!(plan.entries.len() <= policy.max_entries);
        for entry in &plan.entries {
            assert!(!entry.path.trim().is_empty());
            assert!(
                policy.allow_absolute_paths
                    || (!entry.path.starts_with('/')
                        && !entry.path.starts_with('\\')
                        && !entry
                            .path
                            .as_bytes()
                            .get(1)
                            .is_some_and(|separator| *separator == b':'))
            );
            assert!(!entry.path.split(['/', '\\']).any(|segment| segment == ".."));
            assert!(
                entry
                    .original_content
                    .len()
                    .saturating_add(entry.rewritten_content.len())
                    <= policy.max_content_bytes_per_entry
            );
        }
    }
}

fn validate_result_shape(result: Result<(), MigrationRollbackValidationError>) {
    match result {
        Ok(()) => {}
        Err(MigrationRollbackValidationError::UnsupportedSchemaVersion { found }) => {
            assert_ne!(found, "1.0.0");
        }
        Err(MigrationRollbackValidationError::EntryCountMismatch { declared, actual }) => {
            assert_ne!(declared, actual);
        }
        Err(MigrationRollbackValidationError::TooManyEntries { actual, max }) => {
            assert!(actual > max);
        }
        Err(MigrationRollbackValidationError::EmptyPath { .. }) => {}
        Err(MigrationRollbackValidationError::AbsolutePath { path, .. }) => {
            assert!(
                path.starts_with('/')
                    || path.starts_with('\\')
                    || path
                        .as_bytes()
                        .get(1)
                        .is_some_and(|separator| *separator == b':')
            );
        }
        Err(MigrationRollbackValidationError::ParentTraversal { path, .. }) => {
            assert!(path.split(['/', '\\']).any(|segment| segment == ".."));
        }
        Err(MigrationRollbackValidationError::EntryContentTooLarge {
            content_bytes, max, ..
        }) => {
            assert!(content_bytes > max);
        }
    }
}

fn json_round_trip(plan: &MigrationRollbackPlan, policy: &MigrationRollbackValidationPolicy) {
    if let Ok(rendered) = serde_json::to_string(plan) {
        if let Ok(decoded) = serde_json::from_str::<MigrationRollbackPlan>(&rendered) {
            assert_eq!(&decoded, plan);
            validate_result_shape(validate_rollback_plan(&decoded, policy));
        }
    }
}

fn fuzz_raw_rollback_json(bytes: &[u8], policy: &MigrationRollbackValidationPolicy) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    if let Ok(plan) = serde_json::from_slice::<MigrationRollbackPlan>(bytes) {
        validate_result_shape(validate_rollback_plan(&plan, policy));
        json_round_trip(&plan, policy);
    }
}

#[derive(Arbitrary, Debug)]
struct RollbackFuzzInput {
    project: String,
    detail: String,
    entries: Vec<EntryFuzz>,
    policy: PolicyFuzz,
    selector: u8,
    schema_selector: u8,
    count_delta: u8,
    force_count_mismatch: bool,
    apply_mode: bool,
    raw_json: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct PolicyFuzz {
    max_entries: u8,
    max_content_kib: u8,
    allow_absolute_paths: bool,
}

#[derive(Arbitrary, Debug)]
struct EntryFuzz {
    path: String,
    original_content: String,
    rewritten_content: String,
    allow_empty_path: bool,
}
