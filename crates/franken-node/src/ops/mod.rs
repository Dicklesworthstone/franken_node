pub mod close_condition;
pub mod engine_dispatcher;
#[cfg(feature = "admin-tools")]
pub mod mitigation_synthesis;
pub mod telemetry_bridge;
pub mod tokio_drift_checker;
pub mod validation_broker;

#[cfg(test)]
mod ops_conformance_tests;

#[cfg(test)]
mod tests {
    use super::tokio_drift_checker::{
        check_api_transport_boundary_trigger, check_tokio_drift, format_drift_report,
    };
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn crate_root(cargo_toml: &str) -> TempDir {
        let dir = TempDir::new().expect("temp crate root should be created");
        fs::create_dir_all(dir.path().join("src")).expect("src directory should be created");
        fs::write(dir.path().join("Cargo.toml"), cargo_toml).expect("Cargo.toml should be written");
        dir
    }

    fn write_source(root: &Path, rel_path: &str, source: &str) {
        let path = root.join(rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("source parent should be created");
        }
        fs::write(path, source).expect("source file should be written");
    }

    #[test]
    fn negative_cargo_tokio_dependency_is_reported() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = "1"
"#,
        );
        write_source(dir.path(), "src/lib.rs", "pub fn fixture() {}\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "tokio dependency in [dependencies]")
        );
    }

    #[test]
    fn negative_cargo_tokio_dependency_table_is_reported() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"

[dependencies.tokio]
version = "1"
"#,
        );
        write_source(dir.path(), "src/lib.rs", "pub fn fixture() {}\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result.violations.iter().any(|violation| {
                violation.pattern == "tokio dependency in [dependencies.tokio]"
            })
        );
    }

    #[test]
    fn negative_dev_tokio_runtime_feature_is_reported() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread"] }
"#,
        );
        write_source(dir.path(), "src/lib.rs", "pub fn fixture() {}\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|violation| {
            violation.pattern == "tokio runtime features in [dev-dependencies]"
        }));
    }

    #[test]
    fn negative_tokio_main_attribute_without_exception_is_reported() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_source(
            dir.path(),
            "src/main.rs",
            r#"
#[tokio::main]
async fn main() {}
"#,
        );

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "#[tokio::main]")
        );
    }

    #[test]
    fn negative_bare_exception_marker_does_not_suppress_runtime_builder() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_source(
            dir.path(),
            "src/lib.rs",
            r#"
pub fn build_runtime() {
    // TOKIO_DRIFT_EXCEPTION(): missing bead id
    let _runtime = tokio::runtime::Builder::new_current_thread();
}
"#,
        );

        let result = check_tokio_drift(dir.path());

        assert_eq!(result.exceptions_honored, 0);
        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|violation| {
            violation.pattern == "tokio::runtime::Builder"
                || violation.pattern == "Builder::new_current_thread()"
        }));
    }

    #[test]
    fn negative_exception_without_justification_does_not_suppress_tokio_import() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_source(
            dir.path(),
            "src/lib.rs",
            r#"
// TOKIO_DRIFT_EXCEPTION(bd-ops):
use tokio::runtime::Runtime;
"#,
        );

        let result = check_tokio_drift(dir.path());

        assert_eq!(result.exceptions_honored, 0);
        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "tokio::runtime::Runtime")
        );
    }

    #[test]
    fn negative_api_transport_boundary_is_reported_in_api_tree() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_source(
            dir.path(),
            "src/api/server.rs",
            r#"
pub fn router() {
    let _router = axum::Router::new();
}
"#,
        );

        let result = check_api_transport_boundary_trigger(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "axum::Router")
        );
    }

    #[test]
    fn negative_invalid_api_exception_marker_does_not_suppress_tcp_listener() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_source(
            dir.path(),
            "src/api/server.rs",
            r#"
pub fn bind() {
    // TOKIO_DRIFT_EXCEPTION(bd-ops):
    let _listener = std::net::TcpListener::bind("127.0.0.1:0");
}
"#,
        );

        let result = check_api_transport_boundary_trigger(dir.path());

        assert_eq!(result.exceptions_honored, 0);
        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|violation| {
            violation.pattern == "std::net::TcpListener::bind("
                || violation.pattern == "TcpListener::bind("
        }));
    }

    #[test]
    fn negative_drift_report_renders_failure_summary() {
        let dir = crate_root(
            r#"
[package]
name = "drift-fixture"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_source(
            dir.path(),
            "src/lib.rs",
            "pub fn handle() { let _handle = tokio::runtime::Handle::current(); }\n",
        );

        let result = check_tokio_drift(dir.path());
        let report = format_drift_report(&result);

        assert!(!result.is_clean());
        assert!(report.contains("Status: FAIL"));
        assert!(report.contains("tokio::runtime::Handle"));
    }
}

#[cfg(test)]
mod ops_root_additional_negative_tests {
    use super::tokio_drift_checker::{
        check_api_transport_boundary_trigger, check_tokio_drift, format_drift_report,
    };
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn temp_crate(cargo_toml: &str) -> TempDir {
        let dir = TempDir::new().expect("temp crate root should be created");
        fs::create_dir_all(dir.path().join("src")).expect("src tree should be created");
        fs::write(dir.path().join("Cargo.toml"), cargo_toml).expect("Cargo.toml should be written");
        dir
    }

    fn source(root: &Path, path: &str, body: &str) {
        let full_path = root.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("source parent should be created");
        }
        fs::write(full_path, body).expect("source file should be written");
    }

    fn minimal_manifest() -> &'static str {
        r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"
"#
    }

    #[test]
    fn negative_extern_crate_tokio_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(dir.path(), "src/lib.rs", "extern crate tokio;\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "extern crate tokio")
        );
    }

    #[test]
    fn negative_runtime_new_alias_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/lib.rs",
            "pub fn runtime() { let _runtime = Runtime::new(); }\n",
        );

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "Runtime::new()")
        );
    }

    #[test]
    fn negative_multi_thread_builder_alias_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/lib.rs",
            "pub fn runtime() { let _builder = Builder::new_multi_thread(); }\n",
        );

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "Builder::new_multi_thread()")
        );
    }

    #[test]
    fn negative_tokio_test_attribute_in_production_context_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/lib.rs",
            r#"
#[tokio::test]
async fn accidental_runtime_test() {}
"#,
        );

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "#[tokio::test]")
        );
    }

    #[test]
    fn negative_hyper_server_boundary_in_api_tree_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/api/server.rs",
            "pub fn serve() { let _server = hyper::Server::bind; }\n",
        );

        let result = check_api_transport_boundary_trigger(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "hyper::Server")
        );
    }

    #[test]
    fn negative_tonic_server_boundary_in_api_tree_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/api/grpc.rs",
            "pub fn serve() { let _server = tonic::transport::Server::builder(); }\n",
        );

        let result = check_api_transport_boundary_trigger(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "tonic::transport::Server")
        );
    }

    #[test]
    fn negative_api_boundary_outside_api_tree_does_not_hide_tokio_drift() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/runtime/server.rs",
            "pub fn serve() { let _server = hyper::Server::bind; }\n",
        );
        source(
            dir.path(),
            "src/lib.rs",
            "pub fn handle() { let _handle = tokio::runtime::Handle::current(); }\n",
        );

        let api_result = check_api_transport_boundary_trigger(dir.path());
        let tokio_result = check_tokio_drift(dir.path());

        assert!(api_result.is_clean());
        assert!(!tokio_result.is_clean());
        assert!(
            tokio_result
                .violations
                .iter()
                .any(|violation| violation.pattern == "tokio::runtime::Handle")
        );
    }

    #[test]
    fn negative_failure_report_lists_multiple_patterns() {
        let dir = temp_crate(
            r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = "1"
"#,
        );
        source(
            dir.path(),
            "src/main.rs",
            "#[tokio::main]\nasync fn main() {}\n",
        );

        let result = check_tokio_drift(dir.path());
        let report = format_drift_report(&result);

        assert!(!result.is_clean());
        assert!(report.contains("Status: FAIL"));
        assert!(report.contains("tokio dependency in [dependencies]"));
        assert!(report.contains("#[tokio::main]"));
    }

    #[test]
    fn negative_target_specific_tokio_dependency_is_reported() {
        let dir = temp_crate(
            r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"

[target.'cfg(unix)'.dependencies]
tokio = "1"
"#,
        );
        source(dir.path(), "src/lib.rs", "pub fn clean() {}\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| { violation.pattern == "tokio dependency in [dependencies]" })
        );
    }

    #[test]
    fn negative_target_specific_tokio_dependency_table_is_reported() {
        let dir = temp_crate(
            r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"

[target.'cfg(unix)'.dependencies.tokio]
version = "1"
"#,
        );
        source(dir.path(), "src/lib.rs", "pub fn clean() {}\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|violation| {
            violation.pattern == "tokio dependency in target [dependencies.tokio]"
        }));
    }

    #[test]
    fn negative_dev_dependency_tokio_table_runtime_feature_is_reported() {
        let dir = temp_crate(
            r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"

[dev-dependencies.tokio]
version = "1"
features = ["rt"]
"#,
        );
        source(dir.path(), "src/lib.rs", "pub fn clean() {}\n");

        let result = check_tokio_drift(dir.path());

        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|violation| {
            violation.pattern == "tokio runtime features in [dev-dependencies]"
        }));
    }

    #[test]
    fn negative_target_dependency_exception_gap_does_not_suppress() {
        let dir = temp_crate(
            r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"

[target.'cfg(unix)'.dependencies]
# TOKIO_DRIFT_EXCEPTION(bd-ops.1): reviewed target runtime

tokio = "1"
"#,
        );
        source(dir.path(), "src/lib.rs", "pub fn clean() {}\n");

        let result = check_tokio_drift(dir.path());

        assert_eq!(result.exceptions_honored, 0);
        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| { violation.pattern == "tokio dependency in [dependencies]" })
        );
    }

    #[test]
    fn negative_imported_tcp_listener_boundary_in_api_tree_is_reported() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/api/listener.rs",
            r#"
use std::net::TcpListener;

pub fn bind() {
    let _listener = TcpListener::bind("127.0.0.1:0");
}
"#,
        );

        let result = check_api_transport_boundary_trigger(dir.path());

        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "TcpListener::bind(")
        );
    }

    #[test]
    fn negative_api_boundary_exception_gap_does_not_suppress() {
        let dir = temp_crate(minimal_manifest());
        source(
            dir.path(),
            "src/api/server.rs",
            r#"
// TOKIO_DRIFT_EXCEPTION(bd-ops.2): reviewed boundary

pub fn router() {
    let _router = axum::Router::new();
}
"#,
        );

        let result = check_api_transport_boundary_trigger(dir.path());

        assert_eq!(result.exceptions_honored, 0);
        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| violation.pattern == "axum::Router")
        );
    }

    #[test]
    fn negative_valid_exception_for_tokio_source_does_not_mask_cargo_drift() {
        let dir = temp_crate(
            r#"
[package]
name = "ops-root-negative"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = "1"
"#,
        );
        source(
            dir.path(),
            "src/main.rs",
            r#"
// TOKIO_DRIFT_EXCEPTION(bd-ops.3): temporary audited bootstrap
#[tokio::main]
async fn main() {}
"#,
        );

        let result = check_tokio_drift(dir.path());

        assert_eq!(result.exceptions_honored, 1);
        assert!(!result.is_clean());
        assert!(
            result
                .violations
                .iter()
                .any(|violation| { violation.pattern == "tokio dependency in [dependencies]" })
        );
    }
}
