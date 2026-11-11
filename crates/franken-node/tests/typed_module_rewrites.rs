#![cfg(target_os = "linux")]

//! Real public migration APIs, not a copied planner or a stand-in engine.
//! Node/Bun runs establish reference behavior; deliberate native failures
//! establish refusal and exact candidate capture, not native compatibility.

use frankenengine_node::migration::{self, run_rewrite, validation_suite};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn project(kind: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        serde_json::json!({
            "name":"typed-migration", "type":kind, "engines":{"node":">=22"}
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        "{\"lockfileVersion\":3,\"packages\":{\"\":{}}}\n",
    )
    .unwrap();
    root
}

#[test]
fn all_typed_extensions_use_specifier_only_migration_under_commonjs_package() {
    let root = project("commonjs");
    let source = "import type { Stats } from 'fs';\nconst identity = <T,>(value: T): T => value;\nconst answer: number = identity(42);\n";
    for name in ["input.ts", "view.tsx", "module.mts", "common.cts"] {
        fs::write(root.path().join(name), source).unwrap();
    }
    let dry = run_rewrite(root.path(), false).unwrap();
    assert_eq!(dry.rewrites_planned, 4, "{dry:#?}");
    assert_eq!(dry.manual_review_items, 0);
    for name in ["input.ts", "view.tsx", "module.mts", "common.cts"] {
        assert_eq!(fs::read_to_string(root.path().join(name)).unwrap(), source);
    }
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_applied, 4, "{report:#?}");
    assert_eq!(report.manual_review_items, 0);
    assert_eq!(report.rollback_entries.len(), 4);
    for name in ["input.ts", "view.tsx", "module.mts", "common.cts"] {
        assert_eq!(
            fs::read_to_string(root.path().join(name)).unwrap(),
            source.replacen("'fs'", "'node:fs'", 1)
        );
        assert_eq!(
            fs::read_to_string(root.path().join(".migrate-backup").join(name)).unwrap(),
            source
        );
    }
    let repeated = run_rewrite(root.path(), true).unwrap();
    assert_eq!(repeated.rewrites_applied, 0);
    assert_eq!(repeated.manual_review_items, 0);
}

#[test]
fn typed_package_scripts_migrate_without_losing_guest_arguments_or_policy_barriers() {
    let root = project("module");
    let mut scripts = serde_json::Map::new();
    for extension in ["ts", "mts", "cts", "tsx"] {
        let entry = format!("entry.{extension}");
        fs::write(
            root.path().join(&entry),
            "const answer: number = 42; console.log(answer);\n",
        )
        .unwrap();
        scripts.insert(
            extension.into(),
            format!("bun {entry} --mode 'test value'").into(),
        );
    }
    scripts.insert("loader".into(), "node --loader ts-node/esm entry.ts".into());
    scripts.insert(
        "environment".into(),
        "NODE_OPTIONS='--require ./hook.cjs' node entry.ts".into(),
    );
    scripts.insert("declaration".into(), "bun types.d.ts".into());
    fs::write(
        root.path().join("types.d.ts"),
        "declare const answer: number;\n",
    )
    .unwrap();
    let manifest =
        serde_json::json!({"name":"typed-scripts","engines":{"node":">=22"},"scripts":scripts});
    fs::write(root.path().join("package.json"), manifest.to_string()).unwrap();
    let report = run_rewrite(root.path(), true).unwrap();
    let actual: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("package.json")).unwrap()).unwrap();
    for extension in ["ts", "mts", "cts", "tsx"] {
        assert_eq!(
            actual["scripts"][extension],
            format!("franken-node run --console-only entry.{extension} -- --mode 'test value'")
        );
    }
    for name in ["loader", "environment", "declaration"] {
        assert_eq!(actual["scripts"][name], manifest["scripts"][name]);
    }
    assert_eq!(report.manual_review_items, 3, "{report:#?}");
    assert_eq!(
        report
            .entries
            .iter()
            .filter(|entry| entry.action == migration::MigrationRewriteAction::RewritePackageScript)
            .count(),
        4
    );
}

#[test]
fn typed_package_graph_discovers_runtime_sources_and_ignores_types_and_text() {
    let root = project("module");
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::write(
        root.path().join("package.json"),
        serde_json::json!({
            "name":"typed-graph", "type":"module", "engines":{"node":">=22"},
            "scripts":{"start":"bun entry.ts"}
        })
        .to_string(),
    )
    .unwrap();
    for (name, source) in [
        (
            "entry.ts",
            "import type { Shape } from './types.ts';\nimport {\n value\n} from './value.mts';\nexport { other } from './other.cts';\nimport './nested';\nconst later = import('./dynamic.ts');\nconst text = \"require('./text.ts')\";\n",
        ),
        ("value.mts", "export const value: number = 42;\n"),
        ("other.cts", "export const other: number = 1;\n"),
        (
            "nested/index.tsx",
            "export const view = <span title=\"require('../attribute.ts')\"/>;\n",
        ),
        ("dynamic.ts", "export const later: boolean = true;\n"),
        ("types.ts", "export interface Shape { name: string }\n"),
        ("text.ts", "throw new Error('text-is-not-a-module');\n"),
        (
            "attribute.ts",
            "throw new Error('attribute-is-not-a-module');\n",
        ),
    ] {
        fs::write(root.path().join(name), source).unwrap();
    }
    let report = run_rewrite(root.path(), false).unwrap();
    let graph = report
        .entries
        .iter()
        .find(|entry| entry.action == migration::MigrationRewriteAction::ModuleGraphDiscovery)
        .expect("typed source graph");
    for name in [
        "entry.ts",
        "value.mts",
        "other.cts",
        "nested/index.tsx",
        "dynamic.ts",
    ] {
        assert!(graph.detail.contains(name), "{graph:#?}");
    }
    for name in ["types.ts", "text.ts", "attribute.ts"] {
        assert!(!graph.detail.contains(name), "{graph:#?}");
    }
    assert!(
        graph.detail.contains("5 JavaScript/TypeScript/JSX file(s)"),
        "{graph:#?}"
    );
    assert_eq!(report.rewrites_applied, 0);
}

#[test]
fn ambiguous_typed_graph_reports_manual_review_without_partial_discovery() {
    let root = project("module");
    fs::write(
        root.path().join("package.json"),
        serde_json::json!({
            "name":"ambiguous-typed-graph", "type":"module", "engines":{"node":">=22"},
            "scripts":{"start":"bun entry.ts"}
        })
        .to_string(),
    )
    .unwrap();
    let source = "const value = identity<import('./types.ts').Value>(import('./live.ts'));\n";
    for (name, content) in [
        ("entry.ts", source),
        ("types.ts", "export type Value = string;\n"),
        ("live.ts", "export const live: boolean = true;\n"),
    ] {
        fs::write(root.path().join(name), content).unwrap();
    }
    let report = run_rewrite(root.path(), false).unwrap();
    assert!(report.manual_review_items > 0, "{report:#?}");
    assert!(report.entries.iter().any(|entry| {
        entry.action == migration::MigrationRewriteAction::ManualModuleReview
            && entry.detail.contains("manual module graph review")
            && entry.detail.contains("ambiguous")
    }));
    assert!(
        !report.entries.iter().any(|entry| {
            entry.action == migration::MigrationRewriteAction::ModuleGraphDiscovery
        })
    );
    assert_eq!(
        fs::read_to_string(root.path().join("entry.ts")).unwrap(),
        source
    );
    assert_eq!(report.rewrites_applied, 0);
}

#[test]
fn tsx_components_keep_jsx_text_type_annotations_and_attributes() {
    let root = project("module");
    let source = "import { basename } from 'path';\ntype Props = { name: string };\nexport const View = (p: Props) => <p title=\"import('fs')\">import f from 'fs';{basename(p.name)}</p>;\n";
    fs::write(root.path().join("view.tsx"), source).unwrap();
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.manual_review_items, 0, "{report:#?}");
    assert_eq!(report.rewrites_applied, 1);
    assert_eq!(
        fs::read_to_string(root.path().join("view.tsx")).unwrap(),
        source.replacen("'path'", "'node:path'", 1)
    );
}

#[test]
fn typed_rollback_restores_exact_bytes_and_executable_permissions() {
    use migration::rollback::{self, RollbackStatus};
    let root = project("module");
    let source = "#!/usr/bin/env node\nimport type { Stats } from 'fs';\nconst n: number = 42;\n";
    let path = root.path().join("main.mts");
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run_rewrite(root.path(), true).unwrap().rewrites_applied, 1);
    let history = rollback::run(root.path(), None, false);
    assert_eq!(history.status, RollbackStatus::History);
    let restored = rollback::run(root.path(), Some(&history.history[0].transaction_id), true);
    assert_eq!(restored.status, RollbackStatus::RolledBack, "{restored:#?}");
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn commonjs_interop_ambient_modules_and_computed_imports_remain_review_only() {
    let root = project("module");
    let sources = [
        ("module.cts", "import fs = require('fs'); export = fs;"),
        (
            "ambient.d.ts",
            "import type { Stats } from 'fs'; declare module 'fs' { interface Extra {} }",
        ),
        (
            "dynamic.ts",
            "import type { Stats } from 'fs'; const module = import(name);",
        ),
    ];
    for (name, source) in sources {
        fs::write(root.path().join(name), source).unwrap();
    }
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_applied, 0, "{report:#?}");
    assert!(report.manual_review_items >= 3);
    assert!(report.rollback_entries.is_empty());
    for (name, source) in sources {
        assert_eq!(fs::read_to_string(root.path().join(name)).unwrap(), source);
        assert!(!root.path().join(".migrate-backup").join(name).exists());
    }
}

#[test]
fn audit_counts_mts_and_cts_and_javascript_cannot_gain_a_typed_grammar() {
    let root = project("module");
    for name in ["input.ts", "view.tsx", "module.mts", "common.cts"] {
        fs::write(root.path().join(name), "// typed input").unwrap();
    }
    let audit = migration::run_audit(root.path()).unwrap();
    assert_eq!(audit.summary.ts_files, 4);
    assert_eq!(audit.summary.js_files, 0);
    let source = "import fs from 'fs'; const value: number = 42;";
    fs::write(root.path().join("invalid.js"), source).unwrap();
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_applied, 0);
    assert!(report.manual_review_items > 0);
    assert_eq!(
        fs::read_to_string(root.path().join("invalid.js")).unwrap(),
        source
    );
}

#[test]
fn node_and_bun_execute_original_and_installed_typed_sources_with_equal_outputs() {
    let root = project("commonjs");
    fs::write(root.path().join("module.mts"), "import type { Stats } from 'fs';\nimport {basename} from 'path';\nconst path: string = '/a/b'; console.log(basename(path));\n").unwrap();
    fs::write(
        root.path().join("common.cts"),
        "import type { Stats } from 'fs';\nconst n: number = 42; console.log(n);\n",
    )
    .unwrap();
    let run = || {
        ["module.mts", "common.cts"].map(|name| {
            ["node", "bun"].map(|runtime| {
                let mut command = Command::new(runtime);
                if runtime == "node" {
                    command
                        .arg("--experimental-strip-types")
                        .env("NODE_NO_WARNINGS", "1");
                }
                let output = command
                    .arg(name)
                    .current_dir(root.path())
                    .output()
                    .expect("real Node and Bun required");
                assert!(
                    output.status.success(),
                    "{runtime} {name}: {:?}",
                    output.stderr
                );
                (output.stdout, output.stderr)
            })
        })
    };
    let before = run();
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_applied, 2, "{report:#?}");
    assert_eq!(report.manual_review_items, 0);
    assert_eq!(before, run());
    assert_eq!(before[0][0].0, b"b\n");
    assert_eq!(before[0][0], before[0][1]);
    assert_eq!(before[1][0].0, b"42\n");
    assert_eq!(before[1][0], before[1][1]);
}

#[test]
fn declarations_are_not_coverage_and_jsx_test_counterparts_cannot_be_omitted() {
    use validation_suite::rewrite_candidate::RewriteCandidate;
    let root = project("module");
    fs::create_dir(root.path().join("test")).unwrap();
    for name in [
        "test/types.d.ts",
        "test/sample.test.d.ts",
        "test/types.d.mts",
        "test/types.d.cts",
    ] {
        fs::write(
            root.path().join(name),
            "export interface Item {value:number}",
        )
        .unwrap();
    }
    assert!(
        validation_suite::run_project(root.path(), Path::new("/absent/native"))
            .unwrap_err()
            .to_string()
            .contains("no tests discovered")
    );
    for name in ["a.test.tsx", "b.spec.jsx", "c.test.mts", "d.test.cts"] {
        fs::write(root.path().join(name), "// captured entrypoint").unwrap();
    }
    let captured =
        RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(30)).unwrap();
    assert_eq!(
        captured.test_inventory().unwrap(),
        ["a.test.tsx", "b.spec.jsx", "c.test.mts", "d.test.cts"].map(std::path::PathBuf::from)
    );
    let other = project("module");
    fs::write(other.path().join("c.test.mts"), "// only one counterpart").unwrap();
    assert!(
        validation_suite::run_project_comparison(
            root.path(),
            Some(other.path()),
            Path::new("/absent/native"),
            false
        )
        .unwrap_err()
        .to_string()
        .contains("test inventories differ")
    );
}

#[test]
fn explicit_manifests_accept_jsx_and_refuse_declaration_entrypoints() {
    use validation_suite::rewrite_candidate::RewriteCandidate;
    let root = project("module");
    fs::create_dir(root.path().join(".franken-node")).unwrap();
    for name in [
        "view.tsx",
        "view.jsx",
        "types.d.ts",
        "types.d.mts",
        "types.d.cts",
    ] {
        fs::write(root.path().join(name), "// captured file").unwrap();
        fs::write(
            root.path().join(".franken-node/migration-tests.json"),
            serde_json::json!({
                "schema_version":"franken-node/migration-tests/v1", "tests":[name]
            })
            .to_string(),
        )
        .unwrap();
        let captured =
            RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(30));
        if name.starts_with("view") {
            assert_eq!(
                captured.unwrap().test_inventory().unwrap(),
                [std::path::PathBuf::from(name)]
            );
        } else {
            assert!(captured.err().unwrap().to_string().contains("declaration"));
        }
    }
}
