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
        workspace_manifest
            .contains(r#"frankentui = { package = "ftui", path = "../frankentui/crates/ftui""#),
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

/// bd-3mj98 / bd-6n2xv: this guard used to require the OPPOSITE — that the
/// workspace carry a `[patch.crates-io]` for each `fsqlite*` crate pointing at
/// the sibling checkout, and that the crate's dev-dependency point there too. It
/// did its job and failed when those were removed, so it is rewritten rather
/// than deleted, and its original intent (never a machine-local `/dp/...` path)
/// is preserved.
///
/// The rule changed because binding fsqlite to a *development checkout* is what
/// broke the workspace. `/dp/frankensqlite` is mid-migration from a sync to an
/// async `Connection` under an unchanged 0.1.19 version, so:
///
///  * the `[patch]` silently handed that unreleased API to
///    `sqlmodel-frankensqlite`, whose 33 sync call sites met Futures, taking out
///    every default-feature build in this workspace; and
///  * the crate's own dev-dependency handed it to franken_node's storage tests,
///    which are written against the sync surface.
///
/// Identical version number, incompatible content — no version-consistency check
/// can see that. The published crate is the only stable binding.
#[test]
fn fsqlite_is_consumed_from_crates_io_not_a_development_checkout() {
    let workspace_manifest = include_str!("../../../Cargo.toml");
    let crate_manifest = include_str!("../Cargo.toml");

    for package in ["fsqlite", "fsqlite-core", "fsqlite-types", "fsqlite-error"] {
        assert!(
            !workspace_manifest.contains(&format!(r#"{package} = {{ path = "#)),
            "{package} must not be re-pointed by a workspace [patch.crates-io] entry; \
             patching a sibling development checkout over the published crate is what \
             broke the build under bd-3mj98"
        );
    }

    assert!(
        crate_manifest.contains(r#"fsqlite = { version = "0.1.19""#),
        "crate fsqlite dev-dependency must come from crates.io"
    );
    assert!(
        !crate_manifest.contains(r#"fsqlite = { path = "#),
        "crate fsqlite dev-dependency must not be a path dependency on a checkout"
    );

    // Original intent, kept: never a machine-local absolute path.
    assert!(
        !workspace_manifest.contains(r#"path = "/dp/frankensqlite"#)
            && !crate_manifest.contains(r#"path = "/dp/frankensqlite"#),
        "frankensqlite paths must never be machine-local /dp paths"
    );
}
