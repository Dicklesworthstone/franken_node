//! Cross-module integration index for bd-17ds.5.6.
//!
//! This is a live gate over the five bd-17ds.5 subsystem boundaries. Four
//! boundaries are standalone `tests/integration/*` targets, while
//! API -> Security is intentionally tracked in the inline `api::service` tests
//! that closed bd-17ds.5.1.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
struct CargoTarget {
    name_line: &'static str,
    path_line: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct CrossModuleSurface {
    label: &'static str,
    relative_path: &'static str,
    minimum_tests: usize,
    cargo_target: Option<CargoTarget>,
}

const REQUIRED_SURFACES: &[CrossModuleSurface] = &[
    CrossModuleSurface {
        label: "API -> Security",
        relative_path: "crates/franken-node/src/api/service.rs",
        minimum_tests: 10,
        cargo_target: None,
    },
    CrossModuleSurface {
        label: "Connector -> Runtime",
        relative_path: "tests/integration/connector_runtime_integration.rs",
        minimum_tests: 10,
        cargo_target: Some(CargoTarget {
            name_line: "name = \"connector_runtime_integration\"",
            path_line: "path = \"../../tests/integration/connector_runtime_integration.rs\"",
        }),
    },
    CrossModuleSurface {
        label: "Policy -> Observability",
        relative_path: "tests/integration/policy_observability_integration.rs",
        minimum_tests: 10,
        cargo_target: Some(CargoTarget {
            name_line: "name = \"policy_observability_integration\"",
            path_line: "path = \"../../tests/integration/policy_observability_integration.rs\"",
        }),
    },
    CrossModuleSurface {
        label: "Storage -> Migration",
        relative_path: "tests/integration/storage_migration_integration.rs",
        minimum_tests: 10,
        cargo_target: Some(CargoTarget {
            name_line: "name = \"storage_migration_integration\"",
            path_line: "path = \"../../tests/integration/storage_migration_integration.rs\"",
        }),
    },
    CrossModuleSurface {
        label: "Security -> Verifier Economy",
        relative_path: "tests/integration/security_economy_integration.rs",
        minimum_tests: 10,
        cargo_target: Some(CargoTarget {
            name_line: "name = \"security_economy_integration\"",
            path_line: "path = \"../../tests/integration/security_economy_integration.rs\"",
        }),
    },
];

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|err| format!("workspace root must resolve: {}", err))
}

fn read_workspace_file(relative_path: &str) -> Result<String, String> {
    let path = workspace_root()?.join(relative_path);
    fs::read_to_string(&path).map_err(|err| format!("read {}: {}", path.display(), err))
}

fn count_test_attributes(source: &str) -> usize {
    source.matches("#[test]").count()
}

#[test]
fn all_required_cross_module_surfaces_exist() -> Result<(), String> {
    let root = workspace_root()?;

    for surface in REQUIRED_SURFACES {
        let path = root.join(surface.relative_path);
        assert!(
            path.is_file(),
            "{} integration surface must exist at {}",
            surface.label,
            surface.relative_path
        );
    }

    Ok(())
}

#[test]
fn required_cross_module_surfaces_keep_ten_or_more_tests() -> Result<(), String> {
    for surface in REQUIRED_SURFACES {
        let source = read_workspace_file(surface.relative_path)?;
        let test_count = count_test_attributes(&source);

        assert!(
            test_count >= surface.minimum_tests,
            "{} integration surface at {} has {} #[test] functions; expected at least {}",
            surface.label,
            surface.relative_path,
            test_count,
            surface.minimum_tests
        );
    }

    Ok(())
}

#[test]
fn standalone_cross_module_surfaces_are_registered_as_cargo_tests() -> Result<(), String> {
    let cargo_toml = read_workspace_file("crates/franken-node/Cargo.toml")?;

    for surface in REQUIRED_SURFACES {
        let Some(cargo_target) = surface.cargo_target else {
            continue;
        };

        assert!(
            cargo_toml.contains(cargo_target.name_line),
            "{} must be registered as Cargo test target {}",
            surface.label,
            cargo_target.name_line
        );
        assert!(
            cargo_toml.contains(cargo_target.path_line),
            "{} Cargo target must point at {}",
            surface.label,
            surface.relative_path
        );
    }

    Ok(())
}

#[test]
fn this_index_is_registered_as_a_cargo_test() -> Result<(), String> {
    let cargo_toml = read_workspace_file("crates/franken-node/Cargo.toml")?;

    assert!(cargo_toml.contains("name = \"cross_module_integration_index\""));
    assert!(
        cargo_toml.contains("path = \"../../tests/integration/cross_module_integration_index.rs\"")
    );

    Ok(())
}
