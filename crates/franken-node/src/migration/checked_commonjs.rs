//! Format-preserving CommonJS candidates for checked migration.
//!
//! No file renaming or package-type change accompanies checked apply, so ESM
//! conversion would be invalid. Preserve exports, wrapper bindings, cycles and
//! load sites; edit only recognized builtin-specifier literal bytes. node:
//! bypasses require.cache, so runtime comparison remains mandatory. Loader
//! rebinding/cache access is refused before execution, not guessed equivalent.

use super::super::module_specifiers::rewrite_commonjs as rewrite;
use super::super::{MigrationRewriteEntry, MigrationRollbackEntry};
use super::{MigrationRewriteAction as Action, MigrationRewriteReport};
use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags, open};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;
const MAX_PLAN_ENTRIES: usize = 1_000;
const PARSE_TIMEOUT: Duration = Duration::from_secs(2);
const CONVERSION_CONTEXT: &str = "; refused by rewrite:cjs-require-to-esm@1.0.0 precondition:cjs-static-require-no-dynamic-no-cache";

fn modifying(action: Action) -> bool {
    matches!(
        action,
        Action::PinNodeEngine
            | Action::RewritePackageScript
            | Action::RewriteCommonJsRequire
            | Action::RewriteEsmImport
    )
}

fn manual(action: Action) -> bool {
    matches!(
        action,
        Action::ManualModuleReview
            | Action::ManualScriptReview
            | Action::ManifestReadError
            | Action::ManifestParseError
            | Action::NoPackageManifest
    )
}

// Only conversion limitations can be superseded by a new successful syntax
// analysis. Dynamic loading, cache access, mixed modules, parse failures and
// unknown/new diagnostics retain their original manual-review barrier.
fn conversion_only(detail: &str) -> bool {
    detail
        .strip_suffix(CONVERSION_CONTEXT)
        .is_some_and(|reason| {
            matches!(
                reason,
                "parser-backed CommonJS rewrite coverage mismatch; manual migration required"
                    | "CommonJS export assignment detected; manual ESM export migration required"
            )
        })
}

struct Correction {
    before: String,
    result: std::result::Result<(String, usize), String>,
}

/// Consume a LIVE dry-run plan while project_path still names its private
/// captured staging directory. Never import an external plan for refinement.
/// Complete analysis before changing any plan field. The legacy report can
/// truncate diagnostic rows: missing edit/review coverage must fail closed,
/// never leave a hidden CommonJS-to-ESM edit in the installation inventory.
pub(super) fn refine(plan: &mut MigrationRewriteReport, deadline: Instant) -> Result<()> {
    ensure!(
        !plan.apply_mode
            && plan.rewrites_applied == 0
            && plan.entries.iter().all(|entry| !entry.applied),
        "cannot refine an applied rewrite plan"
    );
    ensure!(
        plan.entries.len() <= MAX_PLAN_ENTRIES
            && plan.rollback_entries.len() <= MAX_PLAN_ENTRIES
            && plan.rewrites_planned == plan.rollback_entries.len(),
        "rewrite plan and preimage inventory disagree"
    );
    ensure!(
        plan.manual_review_items
            == plan
                .entries
                .iter()
                .filter(|entry| manual(entry.action))
                .count(),
        "rewrite review inventory is incomplete or truncated"
    );
    let mut preimages = BTreeMap::new();
    for (index, entry) in plan.rollback_entries.iter().enumerate() {
        ensure!(
            preimages.insert(entry.path.clone(), index).is_none(),
            "duplicate rewrite preimage path"
        );
    }
    let mut actions: BTreeMap<String, Vec<Action>> = BTreeMap::new();
    let mut reviews: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for entry in &plan.entries {
        if modifying(entry.action) {
            let path = entry
                .path
                .as_ref()
                .context("rewrite action has no source path")?;
            ensure!(
                preimages.contains_key(path),
                "rewrite action has no preimage"
            );
            actions.entry(path.clone()).or_default().push(entry.action);
        } else if entry.action == Action::ManualModuleReview {
            let path = entry
                .path
                .as_ref()
                .context("module review has no source path")?;
            reviews.entry(path.clone()).or_default().push(&entry.detail);
        }
    }
    ensure!(
        preimages.keys().all(|path| actions.contains_key(path)),
        "rewrite action inventory is incomplete or truncated"
    );
    let mut targets = BTreeSet::new();
    for (path, actions) in &actions {
        if actions.contains(&Action::RewriteCommonJsRequire) {
            ensure!(
                actions.len() == 1,
                "duplicate or conflicting CommonJS rewrite action"
            );
            targets.insert(path.clone());
        }
    }
    for (path, findings) in &reviews {
        if findings.iter().all(|detail| conversion_only(detail)) && !actions.contains_key(path) {
            targets.insert(path.clone());
        }
    }
    let mut corrections = BTreeMap::new();
    for path in &targets {
        ensure!(
            Instant::now() < deadline,
            "checked CommonJS planning budget exhausted"
        );
        let before = match preimages.get(path) {
            Some(index) => plan.rollback_entries[*index].original_content.clone(),
            None => read_staged_source(Path::new(&plan.project_path), path, deadline)?,
        };
        let result = rewrite(&before, deadline.min(Instant::now() + PARSE_TIMEOUT));
        corrections.insert(path.clone(), Correction { before, result });
    }
    ensure!(
        Instant::now() < deadline,
        "checked CommonJS planning budget exhausted"
    );
    let mut entries: Vec<_> = plan
        .entries
        .iter()
        .filter(|entry| {
            let Some(path) = &entry.path else {
                return true;
            };
            let Some(correction) = corrections.get(path) else {
                return true;
            };
            !(entry.action == Action::RewriteCommonJsRequire
                || (correction.result.is_ok()
                    && entry.action == Action::ManualModuleReview
                    && conversion_only(&entry.detail)))
        })
        .cloned()
        .collect();
    for (path, correction) in &corrections {
        let (action, detail) = match &correction.result {
            Ok((_, 0)) => continue,
            Ok((_, count)) => (
                Action::RewriteCommonJsRequire,
                format!(
                    "normalized {count} CommonJS builtin specifier(s) without changing module format or load order"
                ),
            ),
            Err(reason) => (Action::ManualModuleReview, reason.clone()),
        };
        entries.push(MigrationRewriteEntry {
            id: String::new(),
            path: Some(path.clone()),
            action,
            detail,
            applied: false,
        });
    }
    let retained = plan
        .rollback_entries
        .iter()
        .filter(|entry| !targets.contains(&entry.path))
        .count();
    let added = corrections
        .values()
        .filter(|correction| {
            correction
                .result
                .as_ref()
                .is_ok_and(|(_, count)| *count > 0)
        })
        .count();
    ensure!(
        entries.len() <= MAX_PLAN_ENTRIES && retained + added <= MAX_PLAN_ENTRIES,
        "refined rewrite inventory exceeds the complete-report limit"
    );
    // No fallible analysis after this boundary; move private source bytes into
    // the final plan without making another complete clone of its preimages.
    plan.rollback_entries
        .retain(|entry| !targets.contains(&entry.path));
    for (path, correction) in corrections {
        if let Ok((after, count)) = correction.result
            && count > 0
        {
            plan.rollback_entries.push(MigrationRollbackEntry {
                path,
                original_content: correction.before,
                rewritten_content: after,
            });
        }
    }
    plan.rollback_entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.action.cmp(&right.action))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.id = format!("mig-rewrite-{:03}", index + 1);
    }
    plan.manual_review_items = entries.iter().filter(|entry| manual(entry.action)).count();
    plan.entries = entries;
    plan.rewrites_planned = plan.rollback_entries.len();
    Ok(())
}

fn read_staged_source(root: &Path, name: &str, deadline: Instant) -> Result<String> {
    let relative = Path::new(name);
    ensure!(
        !name.is_empty()
            && name.len() <= 4096
            && !name.contains('\\')
            && !name.chars().any(char::is_control)
            && relative
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
                == name,
        "CommonJS review path must be canonical and project-relative"
    );
    let mut target = root.canonicalize()?;
    for component in relative.components() {
        ensure!(
            ![
                "node_modules",
                ".git",
                ".beads",
                ".migrate-backup",
                ".franken-node",
                ".franken-rewrite"
            ]
            .iter()
            .any(|reserved| component.as_os_str() == *reserved),
            "reserved CommonJS review path"
        );
        target.push(component.as_os_str());
        ensure!(
            !fs::symlink_metadata(&target)?.is_symlink(),
            "CommonJS review path must not traverse a symlink"
        );
    }
    let mut file = File::from(
        open(
            &target,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open captured CommonJS source")?,
    );
    ensure!(
        file.metadata()?.is_file(),
        "CommonJS review requires a regular captured source file"
    );
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 65536];
    loop {
        ensure!(
            Instant::now() < deadline,
            "checked CommonJS planning budget exhausted"
        );
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        ensure!(
            bytes.len() + count <= MAX_SOURCE_BYTES,
            "CommonJS source exceeds 10 MiB"
        );
        bytes.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(bytes).context("captured CommonJS source must be UTF-8")
}

#[cfg(test)]
mod tests {
    use super::super::{
        CheckedRewriteStatus, RewriteCandidate, ValidationEvidence, run_with_evidence,
        run_with_validator,
    };
    use super::*;
    use sha2::Digest;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }
    fn transformed(source: &str, expected: &str, count: usize) {
        let (actual, edits) = rewrite(source, deadline()).unwrap();
        assert_eq!((actual.as_str(), edits), (expected, count));
        assert_eq!(rewrite(&actual, deadline()).unwrap(), (actual, 0));
    }
    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("package.json"),
            r#"{"name":"checked-cjs","engines":{"node":">=20"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("package-lock.json"),
            "{\"lockfileVersion\":3,\"packages\":{\"\":{}}}\n",
        )
        .unwrap();
        root
    }
    fn pair(root: &Path) -> super::super::CheckedRewriteReport {
        run_with_validator(root, RewriteCandidate::validate_node_pair)
    }
    fn planned(root: &Path) -> MigrationRewriteReport {
        super::super::run_rewrite(root, false).unwrap()
    }

    #[test]
    fn multiline_require_mutable_exports_and_wrapper_bindings_are_preserved() {
        transformed(
            "#!/usr/bin/env node\r\n'use strict';\r\nconst {\r\n basename: name\r\n} = require(/* kept */ 'path');\r\nmodule.exports = function (p) { return name(p); };\r\nexports.old = __filename;\n",
            "#!/usr/bin/env node\r\n'use strict';\r\nconst {\r\n basename: name\r\n} = require(/* kept */ 'node:path');\r\nmodule.exports = function (p) { return name(p); };\r\nexports.old = __filename;\n",
            1,
        );
    }

    #[test]
    fn conditional_and_nested_load_sites_are_not_hoisted() {
        transformed(
            "console.log('before');\nfunction lazy(on) { if (on) { const fs = require('fs'); return fs; } }\nmodule.exports = {lazy};\n",
            "console.log('before');\nfunction lazy(on) { if (on) { const fs = require('node:fs'); return fs; } }\nmodule.exports = {lazy};\n",
            1,
        );
    }

    #[test]
    fn comments_strings_regexes_templates_and_other_require_methods_are_not_calls() {
        transformed(
            "/* require('fs') */ const s=\"require('path')\"; const r=/require('os')/; const t=`require('net')`; obj.require('crypto');\nconst actual=require('fs/promises');",
            "/* require('fs') */ const s=\"require('path')\"; const r=/require('os')/; const t=`require('net')`; obj.require('crypto');\nconst actual=require('node:fs/promises');",
            1,
        );
    }

    #[test]
    fn exact_builtin_aliases_only_and_no_export_conversion() {
        let source = "const a=require('test');const b=require('fs/custom');const c=require('./local');const d=require('@org/fs');module.exports={a,b,c,d};";
        transformed(source, source, 0);
        transformed(
            "const p=require(`path/posix`);const b=require('node:buffer');exports.p=p;",
            "const p=require(`node:path/posix`);const b=require('node:buffer');exports.p=p;",
            1,
        );
    }

    #[test]
    fn standalone_and_conditional_builtin_loads_keep_their_positions() {
        transformed(
            "require('fs');\nif (false) require('path');\n",
            "require('node:fs');\nif (false) require('node:path');\n",
            2,
        );
    }

    #[test]
    fn loader_rebinding_cache_aliasing_and_dynamic_scope_refuse_every_edit() {
        for suffix in [
            "const require = custom;",
            "function f(require) { return require('os'); }",
            "const {require} = obj;",
            "const load=require;",
            "require.cache.path={exports:{}};",
            "require.resolve('path');",
            "require(name);",
            "require(`fs/${part}`);",
            r"require('p\x61th');",
            "eval('var require=custom');",
            "with (obj) { require('os'); }",
            "export const value=1;",
            r"const requ\u0069re=custom;",
            "createRequire('/tmp/a.cjs');",
            "import('node:fs');",
        ] {
            assert!(
                rewrite(&format!("const path=require('path');{suffix}"), deadline()).is_err(),
                "{suffix}"
            );
        }
    }

    #[test]
    fn parse_and_budget_failures_never_produce_partial_candidates() {
        assert!(rewrite("const p=require('path');const broken=;", deadline()).is_err());
        assert!(rewrite("require('path');", Instant::now()).is_err());
        assert!(rewrite(&" ".repeat(MAX_SOURCE_BYTES + 1), deadline()).is_err());
    }

    #[test]
    fn primary_apply_preserves_commonjs_format_load_order_and_exact_preimages() {
        let source = "#!/usr/bin/env node\n'use strict';\nconsole.log('before', this === module.exports);\nmodule.exports = function(on) {\n if (!on) return 'off';\n require('late');\n const {\n  basename\n } = require(\n 'path'\n );\n return basename(__filename);\n};\nconsole.log(module.exports(false));\nconsole.log(module.exports(true));\n";
        let expected = source.replace("'path'", "'node:path'");
        for (name, module_package) in [("case.test.js", false), ("case.test.cjs", true)] {
            let root = project();
            if module_package {
                fs::write(
                    root.path().join("package.json"),
                    r#"{"name":"checked-cjs","type":"module","engines":{"node":">=20"}}"#,
                )
                .unwrap();
            }
            let manifest = fs::read_to_string(root.path().join("package.json")).unwrap();
            fs::create_dir_all(root.path().join("node_modules/late")).unwrap();
            fs::write(
                root.path().join("node_modules/late/index.js"),
                "console.log('loaded');module.exports='late';\n",
            )
            .unwrap();
            fs::write(root.path().join(name), source).unwrap();
            let execute = || {
                std::process::Command::new("node")
                    .arg(name)
                    .current_dir(root.path())
                    .output()
                    .unwrap()
            };
            let before = execute();
            assert!(before.status.success(), "{before:?}");
            assert_eq!(
                before.stdout,
                format!("before true\noff\nloaded\n{name}\n").into_bytes()
            );
            let plan = planned(root.path());
            assert_eq!(
                (
                    plan.rewrites_planned,
                    plan.rewrites_applied,
                    plan.manual_review_items
                ),
                (1, 0, 0)
            );
            assert_eq!(plan.rollback_entries[0].rewritten_content, expected);
            assert_eq!(fs::read_to_string(root.path().join(name)).unwrap(), source);
            assert!(!root.path().join(".migrate-backup").join(name).exists());

            let applied = super::super::run_rewrite(root.path(), true).unwrap();
            assert_eq!(
                (
                    applied.rewrites_planned,
                    applied.rewrites_applied,
                    applied.manual_review_items
                ),
                (1, 1, 0)
            );
            assert_eq!(applied.rollback_entries, plan.rollback_entries);
            assert_eq!(fs::read_to_string(root.path().join(name)).unwrap(), expected);
            assert_eq!(
                fs::read_to_string(root.path().join(".migrate-backup").join(name)).unwrap(),
                source
            );
            assert_eq!(
                fs::read_to_string(root.path().join("package.json")).unwrap(),
                manifest
            );
            let after = execute();
            assert!(after.status.success(), "{after:?}");
            assert_eq!(after.stdout, before.stdout);
            assert_eq!(after.stderr, before.stderr);
            let repeated = super::super::run_rewrite(root.path(), true).unwrap();
            assert_eq!(
                (
                    repeated.rewrites_planned,
                    repeated.rewrites_applied,
                    repeated.manual_review_items
                ),
                (0, 0, 0)
            );
        }
    }

    // Real Node/Node executions of the production checked pipeline establish
    // candidate planning/installation behavior, not native Franken parity.
    #[test]
    fn checked_multiline_require_and_function_exports_install_with_exact_backups() {
        let root = project();
        let source = "const {\n basename\n} = require(\n'path'\n);\nmodule.exports = function(p) { return basename(p); };\nconsole.log(module.exports('/a/answer'));\n";
        fs::write(root.path().join("case.test.cjs"), source).unwrap();
        fs::set_permissions(
            root.path().join("case.test.cjs"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(planned(root.path()).manual_review_items, 0);
        let report = pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Applied, "{report:#?}");
        let rewrite = report.rewrite.as_ref().unwrap();
        assert_eq!(
            (
                rewrite.rewrites_planned,
                rewrite.rewrites_applied,
                rewrite.manual_review_items
            ),
            (1, 1, 0)
        );
        assert_eq!(
            rewrite.rollback_entries[0].rewritten_content,
            source.replace("'path'", "'node:path'")
        );
        assert_eq!(
            fs::read_to_string(root.path().join(".migrate-backup/case.test.cjs")).unwrap(),
            source
        );
        assert_eq!(
            fs::metadata(root.path().join("case.test.cjs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(report.validation.as_ref().unwrap().passed, 1);
        assert_eq!(pair(root.path()).status, CheckedRewriteStatus::Unchanged);
    }

    #[test]
    fn checked_lazy_load_order_and_commonjs_wrapper_observations_are_preserved() {
        let root = project();
        fs::create_dir_all(root.path().join("node_modules/late")).unwrap();
        fs::write(
            root.path().join("node_modules/late/index.js"),
            "console.log('loaded');module.exports='late';",
        )
        .unwrap();
        let source = "console.log('before',this === module.exports);\nfunction load(on) {\n if (!on) return 'off';\n const value = require('late');\n const path = require('path');\n return value + ':' + path.basename(__filename);\n}\nconsole.log(load(false));\nconsole.log(load(true));\n";
        fs::write(root.path().join("case.test.cjs"), source).unwrap();
        let report = pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Applied, "{report:#?}");
        let expected = b"before true\noff\nloaded\nlate:case.test.cjs\n";
        let row = &report.validation.as_ref().unwrap().cases[0];
        assert_eq!(row.reference, row.native);
        assert_eq!(
            row.reference.as_ref().unwrap().stdout.sha256,
            hex::encode(sha2::Sha256::digest(expected))
        );
        assert_eq!(
            fs::read_to_string(root.path().join("case.test.cjs")).unwrap(),
            source.replace("'path'", "'node:path'")
        );
    }

    #[test]
    fn unsupported_export_conversion_becomes_a_measured_unchanged_plan() {
        let root = project();
        let source =
            "module.exports = function() { return 42; };\nconsole.log(module.exports());\n";
        fs::write(root.path().join("case.test.cjs"), source).unwrap();
        assert_eq!(planned(root.path()).manual_review_items, 0);
        let report = pair(root.path());
        assert_eq!(
            report.status,
            CheckedRewriteStatus::Unchanged,
            "{report:#?}"
        );
        assert_eq!(report.validation.as_ref().unwrap().passed, 1);
        assert_eq!(report.rewrite.as_ref().unwrap().manual_review_items, 0);
        assert_eq!(
            fs::read_to_string(root.path().join("case.test.cjs")).unwrap(),
            source
        );
        assert!(!root.path().join(".migrate-backup/case.test.cjs").exists());
    }

    #[test]
    fn dependency_cache_injection_is_measured_and_rejected_not_declared_equivalent() {
        let root = project();
        fs::create_dir_all(root.path().join("node_modules/shim")).unwrap();
        fs::write(
            root.path().join("node_modules/shim/index.js"),
            "require.cache.path={exports:{marker:'injected'}};",
        )
        .unwrap();
        let source = "const shim = require('shim');\nconst path = require('path');\nconsole.log(path.marker || 'native');\n";
        fs::write(root.path().join("case.test.cjs"), source).unwrap();
        let report = pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
        assert_eq!(report.validation.as_ref().unwrap().verdict, "FAIL");
        assert!(
            report.validation.as_ref().unwrap().cases[0]
                .divergences
                .contains(&"stdout:byte_mismatch".into())
        );
        assert_eq!(
            fs::read_to_string(root.path().join("case.test.cjs")).unwrap(),
            source
        );
        assert_eq!(report.rewrite.as_ref().unwrap().rewrites_applied, 0);
        assert!(!root.path().join(".migrate-backup/case.test.cjs").exists());
    }

    #[test]
    fn shadowed_loader_and_genuine_dynamic_review_still_block_every_runtime() {
        for source in [
            "function load(require) {\n const path = require('path');\n return path;\n}\nconsole.log(42);\n",
            "const name='path';\nconst path=require(name);\nconsole.log(path.sep);\n",
            "const path=require('path');import('node:fs');\n",
        ] {
            let root = project();
            fs::write(root.path().join("case.test.cjs"), source).unwrap();
            let report = run_with_validator(root.path(), |_| {
                panic!("unresolved loader must block execution")
            });
            assert_eq!(report.status, CheckedRewriteStatus::Rejected, "{report:#?}");
            assert!(report.validation.is_none());
            assert!(report.rewrite.as_ref().unwrap().manual_review_items > 0);
            assert_eq!(
                fs::read_to_string(root.path().join("case.test.cjs")).unwrap(),
                source
            );
        }
    }

    #[test]
    fn mixed_monorepo_retains_nearest_package_type_and_esm_cjs_interoperation() {
        let root = project();
        fs::write(
            root.path().join("package.json"),
            r#"{"name":"root","type":"module","engines":{"node":">=20"}}"#,
        )
        .unwrap();
        fs::create_dir(root.path().join("pkg")).unwrap();
        let package = r#"{"name":"nested","type":"commonjs","engines":{"node":">=20"}}"#;
        fs::write(root.path().join("pkg/package.json"), package).unwrap();
        let source = "const {\n basename\n} = require('path');\nmodule.exports = function(p) { return basename(p); };\n";
        fs::write(root.path().join("pkg/answer.js"), source).unwrap();
        fs::write(
            root.path().join("case.test.mjs"),
            "import answer from './pkg/answer.js';\nconsole.log(answer('/a/answer'));\n",
        )
        .unwrap();
        let report = pair(root.path());
        assert_eq!(report.status, CheckedRewriteStatus::Applied, "{report:#?}");
        assert_eq!(
            fs::read_to_string(root.path().join("pkg/package.json")).unwrap(),
            package
        );
        assert_eq!(
            fs::read_to_string(root.path().join("pkg/answer.js")).unwrap(),
            source.replace("'path'", "'node:path'")
        );
        assert_eq!(report.validation.as_ref().unwrap().passed, 1);
    }

    #[test]
    fn full_product_admission_can_install_a_commonjs_candidate_without_format_conversion() {
        let root = project();
        let source = "const {\n basename\n} = require('path');\nmodule.exports = function(p) { return basename(p); };\nconsole.log(module.exports('/a/answer'));\n";
        fs::write(root.path().join("case.test.cjs"), source).unwrap();
        let bun = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|path| path.is_absolute())
            .map(|path| path.join("bun"))
            .find(|path| path.is_file())
            .expect("real Bun is required");
        // Explicit Node/Bun/Node roles prove planner/admission orchestration,
        // never successful execution on a native Franken implementation.
        let report = run_with_evidence(root.path(), |candidate| {
            candidate
                .validate_node_bun_node(&bun)
                .map(|report| ValidationEvidence::Product(Box::new(report)))
        });
        assert_eq!(report.status, CheckedRewriteStatus::Applied, "{report:#?}");
        assert!(report.validation.is_none());
        assert_eq!(report.product_validation.as_ref().unwrap().passed, 1);
        assert!(
            report.product_validation.as_ref().unwrap().cases[0]
                .bun
                .is_some()
        );
        assert_eq!(
            fs::read_to_string(root.path().join("case.test.cjs")).unwrap(),
            source.replace("'path'", "'node:path'")
        );
    }

    #[test]
    fn incomplete_or_applied_plan_cannot_keep_a_hidden_legacy_conversion() {
        let root = project();
        fs::write(
            root.path().join("case.test.cjs"),
            "const p = require('path');\nconsole.log(p.sep);\n",
        )
        .unwrap();
        let original = planned(root.path());
        assert_eq!(original.rewrites_planned, 1);
        for mutate in [
            (|plan: &mut MigrationRewriteReport| plan.entries.clear())
                as fn(&mut MigrationRewriteReport),
            |plan| plan.rollback_entries.push(plan.rollback_entries[0].clone()),
            |plan| plan.entries.push(plan.entries[0].clone()),
            |plan| plan.manual_review_items += 1,
            |plan| plan.apply_mode = true,
        ] {
            let mut plan = original.clone();
            mutate(&mut plan);
            let before = plan.clone();
            assert!(refine(&mut plan, deadline()).is_err());
            assert_eq!(plan, before);
        }
    }

    #[test]
    fn staged_manual_source_paths_cannot_escape_or_follow_links() {
        let root = project();
        fs::write(root.path().join("source.cjs"), "module.exports = 42;").unwrap();
        symlink("source.cjs", root.path().join("alias.cjs")).unwrap();
        for path in [
            "../source.cjs",
            "./source.cjs",
            "alias.cjs",
            ".git/source.cjs",
            "source.cjs/../source.cjs",
        ] {
            assert!(
                read_staged_source(root.path(), path, deadline()).is_err(),
                "{path}"
            );
        }
        assert_eq!(
            read_staged_source(root.path(), "source.cjs", deadline()).unwrap(),
            "module.exports = 42;"
        );
    }
}
