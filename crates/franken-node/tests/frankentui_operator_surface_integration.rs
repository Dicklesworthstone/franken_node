use assert_cmd::Command;

#[test]
fn doctor_verbose_human_output_is_routed_through_frankentui_surface() {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assert = command
        .args([
            "doctor",
            "--verbose",
            "--trace-id",
            "trace-frankentui-operator-surface",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is utf8");
    assert!(stdout.contains("franken-node doctor:"));
    assert!(stdout.contains("trace_id=trace-frankentui-operator-surface"));
    assert!(stdout.contains("structured logs:"));

    let main_source = include_str!("../src/main.rs");
    assert!(
        main_source.contains("fn render_operator_surface_with_frankentui"),
        "doctor output must pass through the FrankenTUI surface helper"
    );
    assert!(
        main_source.contains("frankentui::Buffer::new"),
        "the operator surface helper must call the FrankenTUI buffer surface"
    );
    assert!(
        main_source.contains("emit_operator_surface_output(\n                    \"doctor\""),
        "doctor human output must emit via the FrankenTUI surface path"
    );
    assert!(
        !main_source
            .contains("println!(\"{}\", render_doctor_report_human(&report, args.verbose))"),
        "doctor human output must not bypass FrankenTUI with a direct println"
    );
}

#[test]
fn frankentui_dependency_is_workspace_relative_not_absolute() {
    let workspace_manifest = include_str!("../../../Cargo.toml");
    let crate_manifest = include_str!("../Cargo.toml");

    assert!(
        workspace_manifest.contains(
            r#"frankentui = { package = "ftui", path = "../../../dp/frankentui/crates/ftui""#
        ),
        "workspace manifest must own the FrankenTUI dependency through a relative path"
    );
    assert!(
        crate_manifest.contains("frankentui.workspace = true"),
        "crate manifest must consume the workspace-relative FrankenTUI dependency"
    );
    assert!(
        !workspace_manifest.contains(r#"path = "/dp/frankentui"#)
            && !crate_manifest.contains(r#"path = "/dp/frankentui"#),
        "FrankenTUI dependency paths must not be absolute"
    );
}

#[test]
fn fsqlite_crates_io_patches_are_workspace_relative_not_absolute() {
    let workspace_manifest = include_str!("../../../Cargo.toml");

    for (package, relative_patch, absolute_patch) in [
        (
            "fsqlite",
            r#"fsqlite = { path = "../frankensqlite/crates/fsqlite""#,
            r#"fsqlite = { path = "/dp/frankensqlite"#,
        ),
        (
            "fsqlite-core",
            r#"fsqlite-core = { path = "../frankensqlite/crates/fsqlite-core""#,
            r#"fsqlite-core = { path = "/dp/frankensqlite"#,
        ),
        (
            "fsqlite-types",
            r#"fsqlite-types = { path = "../frankensqlite/crates/fsqlite-types""#,
            r#"fsqlite-types = { path = "/dp/frankensqlite"#,
        ),
        (
            "fsqlite-error",
            r#"fsqlite-error = { path = "../frankensqlite/crates/fsqlite-error""#,
            r#"fsqlite-error = { path = "/dp/frankensqlite"#,
        ),
    ] {
        assert!(
            workspace_manifest.contains(relative_patch),
            "{package} crates.io patch must use the sibling frankensqlite checkout"
        );
        assert!(
            !workspace_manifest.contains(absolute_patch),
            "{package} crates.io patch must not point at a machine-local /dp path"
        );
    }
}
