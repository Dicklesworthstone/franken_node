#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::migration::{
    build_rollback_plan, default_rollback_validation_policy, render_rewrite_report, run_rewrite,
    validate_rollback_plan,
};
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static PROJECT_LOCK: Mutex<()> = Mutex::new(());

fuzz_target!(|input: FuzzInput| {
    let Ok(_guard) = PROJECT_LOCK.lock() else {
        return;
    };

    let project = std::env::temp_dir().join("franken_node_p4_migration_rewrite_fuzz");
    if !prepare_project(&project, &input) {
        return;
    }

    let package_before = match std::fs::read_to_string(project.join("package.json")) {
        Ok(content) => content,
        Err(_) => return,
    };
    let source_before = match std::fs::read_to_string(project.join("src/index.js")) {
        Ok(content) => content,
        Err(_) => return,
    };

    let Ok(report) = run_rewrite(&project, false) else {
        return;
    };
    assert_eq!(report.schema_version, "1.0.0");
    assert!(!report.apply_mode);
    assert_eq!(report.rewrites_applied, 0);
    assert_eq!(report.package_manifests_scanned, 1);

    let package_after = match std::fs::read_to_string(project.join("package.json")) {
        Ok(content) => content,
        Err(_) => return,
    };
    let source_after = match std::fs::read_to_string(project.join("src/index.js")) {
        Ok(content) => content,
        Err(_) => return,
    };
    assert_eq!(package_after, package_before);
    assert_eq!(source_after, source_before);

    let mut last_id = "";
    for entry in &report.entries {
        assert!(!entry.id.is_empty());
        assert!(entry.id.starts_with("mig-rewrite-"));
        assert!(!entry.applied);
        assert!(entry.id.as_str() > last_id);
        last_id = &entry.id;
        if let Some(path) = &entry.path {
            assert!(!path.is_empty());
            assert!(!Path::new(path).is_absolute());
            assert!(!path.contains('\\'));
            assert!(!path.split('/').any(|segment| segment == ".."));
        }
    }

    for entry in &report.rollback_entries {
        assert!(!entry.path.is_empty());
        assert!(!Path::new(&entry.path).is_absolute());
        assert!(!entry.path.contains('\\'));
        assert!(!entry.path.split('/').any(|segment| segment == ".."));
        assert_ne!(entry.original_content, entry.rewritten_content);
        if entry.path == "package.json" {
            assert!(serde_json::from_str::<serde_json::Value>(&entry.original_content).is_ok());
            assert!(serde_json::from_str::<serde_json::Value>(&entry.rewritten_content).is_ok());
        }
    }

    let plan = build_rollback_plan(&report);
    assert_eq!(plan.entry_count, report.rollback_entries.len());
    assert_eq!(plan.entries, report.rollback_entries);
    assert!(validate_rollback_plan(&plan, &default_rollback_validation_policy()).is_ok());
    assert!(serde_json::to_string(&report).is_ok());
    assert!(serde_json::to_string(&plan).is_ok());
    assert!(render_rewrite_report(&report).contains("mode: dry-run"));
});

fn prepare_project(project: &Path, input: &FuzzInput) -> bool {
    if std::fs::create_dir_all(project.join("src")).is_err() {
        return false;
    }

    let source = source_fixture(input);
    let mut manifest = json!({
        "name": "franken-node-migration-rewrite-fuzz",
        "version": "1.0.0",
        "scripts": {
            "start": script_fixture(input),
            "already": "franken-node src/index.js"
        }
    });

    if input.include_node_engine {
        manifest["engines"] = json!({ "node": ">=20 <23" });
    }
    match input.package_type % 3 {
        0 => manifest["type"] = json!("module"),
        1 => manifest["type"] = json!("commonjs"),
        _ => {}
    }
    if input.include_risky_script {
        manifest["scripts"]["postinstall"] = json!("node scripts/install.js");
    }

    let package_json = match serde_json::to_string_pretty(&manifest) {
        Ok(content) => format!("{content}\n"),
        Err(_) => return false,
    };

    std::fs::write(project.join("package.json"), package_json).is_ok()
        && std::fs::write(project.join("src/index.js"), source).is_ok()
}

fn script_fixture(input: &FuzzInput) -> &'static str {
    match input.script_variant % 8 {
        0 => "node src/index.js",
        1 => "bun src/index.js --watch",
        2 => "env NODE_OPTIONS='--trace-warnings' node \"src/index.js\"",
        3 => "pnpm exec -- node src/index.js",
        4 => "yarn node src/index.js",
        5 => "node -e \"console.log(1)\"",
        6 => "npm run build",
        _ => "franken-node src/index.js",
    }
}

fn source_fixture(input: &FuzzInput) -> String {
    let builtin = builtin_specifier(input.builtin_selector);
    let local = local_specifier(input.local_selector);
    match input.source_variant % 7 {
        0 => format!("const api = require(\"{builtin}\");\nconsole.log(api);\n"),
        1 => format!(
            "const {{ readFile }} = require(\"{builtin}\");\nmodule.exports = {{ readFile }};\n"
        ),
        2 => format!("import api from \"{builtin}\";\nexport default api;\n"),
        3 => format!("import local from \"{local}\";\nexport {{ local }};\n"),
        4 => format!(
            "import fs from \"{builtin}\";\nconst path = require(\"path\");\nexport const sep = path.sep;\n"
        ),
        5 => "const dynamic = require(process.env.MODULE_NAME);\nmodule.exports = dynamic;\n"
            .to_string(),
        _ => "console.log('migration rewrite fuzz');\n".to_string(),
    }
}

fn builtin_specifier(selector: u8) -> &'static str {
    match selector % 8 {
        0 => "fs",
        1 => "path",
        2 => "node:crypto",
        3 => "url",
        4 => "node:os",
        5 => "stream",
        6 => "events",
        _ => "buffer",
    }
}

fn local_specifier(selector: u8) -> &'static str {
    match selector % 6 {
        0 => "./dep",
        1 => "./dep.js",
        2 => "../shared/util",
        3 => "@scope/package",
        4 => "plain-package",
        _ => "./nested/index",
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    script_variant: u8,
    source_variant: u8,
    package_type: u8,
    builtin_selector: u8,
    local_selector: u8,
    include_node_engine: bool,
    include_risky_script: bool,
}
