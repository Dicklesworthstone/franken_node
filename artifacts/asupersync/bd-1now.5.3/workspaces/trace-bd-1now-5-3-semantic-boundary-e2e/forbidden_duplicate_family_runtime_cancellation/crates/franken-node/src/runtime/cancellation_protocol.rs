pub struct RuntimeCancellationProtocol;

impl RuntimeCancellationProtocol {
    pub const FORBIDDEN_PATH: &'static str =
        "crates/franken-node/src/runtime/cancellation_protocol.rs";
    pub const CANONICAL_PATH: &'static str =
        "crates/franken-node/src/control_plane/cancellation_protocol.rs";

    pub fn is_exact_runtime_duplicate_fixture_path(path: &str) -> bool {
        path == Self::FORBIDDEN_PATH
    }
}

#[cfg(test)]
mod runtime_cancellation_duplicate_tests {
    use super::RuntimeCancellationProtocol;

    fn duplicate_family_violations(source: &str) -> Vec<&'static str> {
        let mut violations = Vec::new();

        if source.contains("RuntimeCancellationProtocol") {
            violations.push("runtime_duplicate_family");
        }
        if source.contains("control_plane::cancellation_protocol") {
            violations.push("control_plane_alias");
        }
        if source.contains("franken_engine::scheduler_internal") {
            violations.push("internal_scheduler_boundary");
        }
        if source.contains("tokio::spawn") {
            violations.push("async_spawn_boundary");
        }
        if source.contains("std::thread::spawn") {
            violations.push("thread_spawn_boundary");
        }
        if source.contains("unsafe") {
            violations.push("unsafe_boundary");
        }
        violations
    }

    #[test]
    fn negative_runtime_duplicate_path_is_forbidden() {
        assert!(
            RuntimeCancellationProtocol::is_exact_runtime_duplicate_fixture_path(
                RuntimeCancellationProtocol::FORBIDDEN_PATH
            )
        );
    }

    #[test]
    fn negative_canonical_control_plane_path_is_not_runtime_duplicate() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_runtime_duplicate_fixture_path(
                RuntimeCancellationProtocol::CANONICAL_PATH
            )
        );
    }

    #[test]
    fn negative_empty_path_is_not_accepted_as_duplicate_fixture() {
        assert!(!RuntimeCancellationProtocol::is_exact_runtime_duplicate_fixture_path(""));
    }

    #[test]
    fn negative_padded_runtime_path_is_rejected() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_runtime_duplicate_fixture_path(
                " crates/franken-node/src/runtime/cancellation_protocol.rs "
            )
        );
    }

    #[test]
    fn negative_parent_escape_runtime_path_is_rejected() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_runtime_duplicate_fixture_path(
                "crates/franken-node/src/runtime/../runtime/cancellation_protocol.rs"
            )
        );
    }

    #[test]
    fn negative_artifact_prefixed_runtime_path_is_rejected() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_runtime_duplicate_fixture_path(
                "artifacts/asupersync/crates/franken-node/src/runtime/cancellation_protocol.rs"
            )
        );
    }

    #[test]
    fn negative_duplicate_marker_is_reported() {
        let violations = duplicate_family_violations("pub struct RuntimeCancellationProtocol;");

        assert_eq!(violations, vec!["runtime_duplicate_family"]);
    }

    #[test]
    fn negative_control_plane_alias_is_reported() {
        let violations =
            duplicate_family_violations("use crate::control_plane::cancellation_protocol;");

        assert_eq!(violations, vec!["control_plane_alias"]);
    }

    #[test]
    fn negative_internal_scheduler_boundary_is_reported() {
        let violations =
            duplicate_family_violations("use franken_engine::scheduler_internal::Queue;");

        assert_eq!(violations, vec!["internal_scheduler_boundary"]);
    }

    #[test]
    fn negative_multiple_runtime_boundary_violations_are_reported_in_order() {
        let violations = duplicate_family_violations(
            "pub struct RuntimeCancellationProtocol; unsafe fn run() { tokio::spawn(f()); }",
        );

        assert_eq!(
            violations,
            vec![
                "runtime_duplicate_family",
                "async_spawn_boundary",
                "unsafe_boundary"
            ]
        );
    }
}

impl RuntimeCancellationProtocol {
    pub const FORBIDDEN_DUPLICATE_PATH: &'static str =
        "crates/franken-node/src/runtime/cancellation_protocol.rs";
    pub const CANONICAL_CONTROL_PLANE_PATH: &'static str =
        "crates/franken-node/src/control_plane/cancellation_protocol.rs";

    pub fn is_exact_forbidden_duplicate_path(path: &str) -> bool {
        path == Self::FORBIDDEN_DUPLICATE_PATH
    }
}

#[cfg(test)]
fn runtime_cancellation_trace_violations(source: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();

    if !source.contains("RuntimeCancellationProtocol") {
        violations.push("missing_runtime_cancellation_marker");
    }
    if source.contains("control_plane") {
        violations.push("control_plane_boundary");
    }
    if source.contains("unsafe") {
        violations.push("unsafe_boundary");
    }
    if source.contains("tokio::spawn") {
        violations.push("async_spawn_boundary");
    }
    if source.contains("std::thread::spawn") {
        violations.push("thread_spawn_boundary");
    }
    if source.contains(".unwrap()") {
        violations.push("unwrap_boundary");
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::{RuntimeCancellationProtocol, runtime_cancellation_trace_violations};

    #[test]
    fn detects_forbidden_runtime_duplicate_path() {
        assert!(
            RuntimeCancellationProtocol::is_exact_forbidden_duplicate_path(
                RuntimeCancellationProtocol::FORBIDDEN_DUPLICATE_PATH
            )
        );
    }

    #[test]
    fn negative_rejects_empty_path_as_forbidden_duplicate() {
        assert!(!RuntimeCancellationProtocol::is_exact_forbidden_duplicate_path(""));
    }

    #[test]
    fn negative_rejects_canonical_control_plane_path_as_runtime_duplicate() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_forbidden_duplicate_path(
                RuntimeCancellationProtocol::CANONICAL_CONTROL_PLANE_PATH
            )
        );
    }

    #[test]
    fn negative_rejects_whitespace_padded_runtime_duplicate_path() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_forbidden_duplicate_path(
                " crates/franken-node/src/runtime/cancellation_protocol.rs "
            )
        );
    }

    #[test]
    fn negative_rejects_parent_directory_escape_to_runtime_duplicate() {
        assert!(
            !RuntimeCancellationProtocol::is_exact_forbidden_duplicate_path(
                "crates/franken-node/src/control_plane/../runtime/cancellation_protocol.rs"
            )
        );
    }

    #[test]
    fn negative_empty_trace_reports_missing_runtime_marker() {
        assert_eq!(
            runtime_cancellation_trace_violations(""),
            vec!["missing_runtime_cancellation_marker"]
        );
    }

    #[test]
    fn negative_control_plane_boundary_is_reported() {
        let source = "pub struct RuntimeCancellationProtocol; mod control_plane {}";

        assert_eq!(
            runtime_cancellation_trace_violations(source),
            vec!["control_plane_boundary"]
        );
    }

    #[test]
    fn negative_thread_spawn_boundary_is_reported() {
        let source =
            "pub struct RuntimeCancellationProtocol; fn run() { std::thread::spawn(|| {}); }";

        assert_eq!(
            runtime_cancellation_trace_violations(source),
            vec!["thread_spawn_boundary"]
        );
    }

    #[test]
    fn negative_multiple_forbidden_boundaries_are_reported_in_order() {
        let source = "unsafe fn run() { tokio::spawn(async {}); maybe.unwrap(); }";

        assert_eq!(
            runtime_cancellation_trace_violations(source),
            vec![
                "missing_runtime_cancellation_marker",
                "unsafe_boundary",
                "async_spawn_boundary",
                "unwrap_boundary"
            ]
        );
    }
}
