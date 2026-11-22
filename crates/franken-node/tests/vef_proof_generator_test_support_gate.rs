use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use syn::{Attribute, Item, Type, Visibility};
use tempfile::TempDir;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn has_test_support_only_cfg(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let tokens = attr
            .meta
            .require_list()
            .map(|list| list.tokens.to_string().replace(' ', ""))
            .unwrap_or_default();
        tokens == "any(test,feature=\"test-support\")"
            || tokens == "any(feature=\"test-support\",test)"
            || tokens == "feature=\"test-support\""
    })
}

fn type_mentions_test_proof_backend(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .iter()
            .any(|seg| seg.ident == "TestProofBackend"),
        _ => false,
    }
}

fn verify_test_proof_backend_source_gating(source: &str) -> Result<usize, String> {
    let parsed = syn::parse_file(source).map_err(|err| format!("parse source: {err}"))?;
    let mut gated_items = 0_usize;

    for item in &parsed.items {
        match item {
            Item::Struct(item_struct) if item_struct.ident == "TestProofBackend" => {
                if !has_test_support_only_cfg(&item_struct.attrs) {
                    return Err(
                        "struct TestProofBackend is missing #[cfg(any(test, feature = \"test-support\"))]"
                            .to_string(),
                    );
                }
                gated_items += 1;
            }
            Item::Impl(item_impl) if type_mentions_test_proof_backend(&item_impl.self_ty) => {
                if !has_test_support_only_cfg(&item_impl.attrs) {
                    return Err(
                        "impl for TestProofBackend is missing #[cfg(any(test, feature = \"test-support\"))]"
                            .to_string(),
                    );
                }
                gated_items += 1;
            }
            Item::Use(item_use) if matches!(item_use.vis, Visibility::Public(_)) => {
                if use_tree_mentions_ident(&item_use.tree, "TestProofBackend")
                    && !has_test_support_only_cfg(&item_use.attrs)
                {
                    return Err(
                        "public re-export of TestProofBackend is missing #[cfg(any(test, feature = \"test-support\"))]"
                            .to_string(),
                    );
                }
            }
            _ => {}
        }
    }

    if gated_items == 0 {
        return Err("TestProofBackend definition was not found in proof_generator.rs".to_string());
    }
    Ok(gated_items)
}

fn use_tree_mentions_ident(tree: &syn::UseTree, target: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            path.ident == target || use_tree_mentions_ident(&path.tree, target)
        }
        syn::UseTree::Name(name) => name.ident == target,
        syn::UseTree::Rename(rename) => rename.ident == target || rename.rename == target,
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_mentions_ident(item, target)),
    }
}

fn write_probe_crate(
    root: &Path,
    crate_name: &str,
    target_dir: &Path,
    package_dependency: &str,
    source: &str,
) -> PathBuf {
    let probe_dir = root.join(crate_name);
    let src_dir = probe_dir.join("src");
    fs::create_dir_all(&src_dir).expect("create probe src directory");
    let dependency_clause = if package_dependency.is_empty() {
        format!(
            "path = {:?}, default-features = false",
            env!("CARGO_MANIFEST_DIR")
        )
    } else {
        format!(
            "path = {:?}, default-features = false, {}",
            env!("CARGO_MANIFEST_DIR"),
            package_dependency
        )
    };
    fs::write(
        probe_dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"vef-proof-generator-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nfrankenengine-node = {{ {dependency_clause} }}\n",
        ),
    )
    .expect("write probe Cargo.toml");
    fs::write(src_dir.join("main.rs"), source).expect("write probe main.rs");
    target_dir.to_path_buf()
}

fn cargo_check(probe_dir: &Path, target_dir: &Path) -> Output {
    Command::new("cargo")
        .arg("check")
        .arg("--quiet")
        .current_dir(probe_dir)
        .env("CARGO_TARGET_DIR", target_dir)
        .output()
        .expect("run cargo check for probe crate")
}

#[test]
fn test_proof_backend_requires_test_support_feature() {
    let manifest_path = crate_dir().join("Cargo.toml");
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(&manifest_path).expect("read Cargo.toml"))
            .expect("parse Cargo.toml");
    let features = manifest["features"]
        .as_table()
        .expect("Cargo.toml [features] table");

    for production_umbrella in ["default", "extended-surfaces"] {
        let enabled = features[production_umbrella].as_array().expect("feature list");
        assert!(
            !enabled
                .iter()
                .any(|entry| entry.as_str() == Some("test-support")),
            "`{production_umbrella}` must never enable `test-support`"
        );
    }
    assert!(
        features.contains_key("test-support"),
        "Cargo.toml must declare explicit opt-in `test-support` feature"
    );

    let proof_generator_path = crate_dir().join("src/vef/proof_generator.rs");
    let source = fs::read_to_string(&proof_generator_path).expect("read src/vef/proof_generator.rs");
    let gated_count = verify_test_proof_backend_source_gating(&source)
        .expect("production proof_generator.rs must gate TestProofBackend behind test-support");
    assert!(
        gated_count >= 4,
        "expected struct + impl blocks for TestProofBackend to be cfg-gated, found {gated_count}"
    );

    let vef_mod_source =
        fs::read_to_string(crate_dir().join("src/vef/mod.rs")).expect("read src/vef/mod.rs");
    let vef_mod_ast = syn::parse_file(&vef_mod_source).expect("parse src/vef/mod.rs");
    for item in &vef_mod_ast.items {
        if let Item::Use(item_use) = item
            && matches!(item_use.vis, Visibility::Public(_))
            && use_tree_mentions_ident(&item_use.tree, "TestProofBackend")
        {
            assert!(
                has_test_support_only_cfg(&item_use.attrs),
                "src/vef/mod.rs must not re-export TestProofBackend without test-support cfg"
            );
        }
    }

    // Negative control: unguarded TestProofBackend must be rejected.
    let unguarded = "pub struct TestProofBackend { name: String }\n";
    let err = verify_test_proof_backend_source_gating(unguarded)
        .expect_err("unguarded TestProofBackend must fail the gate");
    assert!(err.contains("TestProofBackend"), "{err}");

    #[cfg(feature = "test-support")]
    {
        let backend = frankenengine_node::vef::proof_generator::TestProofBackend::new();
        assert!(format!("{backend:?}").contains("test-hash"));
    }

    if std::env::var_os("FRANKEN_RUN_SUBPROCESS_CARGO_CHECK").is_some() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let target_dir = temp_dir.path().join("target");
        let probe_source = r#"
use frankenengine_node::vef::proof_generator::TestProofBackend;

fn main() {
    let _ = TestProofBackend::new();
}
"#;
        let production_target = write_probe_crate(
            temp_dir.path(),
            "probe-production",
            &target_dir,
            "",
            probe_source,
        );
        let production_output =
            cargo_check(&temp_dir.path().join("probe-production"), &production_target);
        assert!(
            !production_output.status.success(),
            "production surface should not expose TestProofBackend"
        );
        let production_stderr = String::from_utf8_lossy(&production_output.stderr);
        assert!(
            production_stderr.contains("TestProofBackend"),
            "unexpected compile failure: {production_stderr}"
        );

        let feature_target = write_probe_crate(
            temp_dir.path(),
            "probe-feature",
            &target_dir,
            "features = [\"test-support\"]",
            probe_source,
        );
        let feature_output = cargo_check(&temp_dir.path().join("probe-feature"), &feature_target);
        assert!(
            feature_output.status.success(),
            "test-support feature should expose TestProofBackend: {}",
            String::from_utf8_lossy(&feature_output.stderr)
        );
    }
}
