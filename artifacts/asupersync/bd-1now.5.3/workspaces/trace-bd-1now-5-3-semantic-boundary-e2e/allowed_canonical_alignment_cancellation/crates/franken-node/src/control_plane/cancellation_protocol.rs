pub struct CancellationProtocol;

impl CancellationProtocol {
    pub const CANONICAL_PATH: &'static str =
        "crates/franken-node/src/control_plane/cancellation_protocol.rs";

    pub fn accepts_fixture_path(path: &str) -> bool {
        path == Self::CANONICAL_PATH
    }
}

#[cfg(test)]
mod canonical_path_tests {
    use super::CancellationProtocol;

    #[test]
    fn accepts_canonical_control_plane_cancellation_path() {
        assert!(CancellationProtocol::accepts_fixture_path(
            CancellationProtocol::CANONICAL_PATH
        ));
    }

    #[test]
    fn negative_rejects_empty_path() {
        assert!(!CancellationProtocol::accepts_fixture_path(""));
    }

    #[test]
    fn negative_rejects_whitespace_padded_path() {
        assert!(!CancellationProtocol::accepts_fixture_path(
            " crates/franken-node/src/control_plane/cancellation_protocol.rs "
        ));
    }

    #[test]
    fn negative_rejects_runtime_family_duplicate() {
        assert!(!CancellationProtocol::accepts_fixture_path(
            "crates/franken-node/src/runtime/cancellation_protocol.rs"
        ));
    }

    #[test]
    fn negative_rejects_internal_boundary_probe_path() {
        assert!(!CancellationProtocol::accepts_fixture_path(
            "crates/franken-node/src/control_plane/internal_boundary_probe.rs"
        ));
    }

    #[test]
    fn negative_rejects_parent_directory_escape() {
        assert!(!CancellationProtocol::accepts_fixture_path(
            "crates/franken-node/src/control_plane/../runtime/cancellation_protocol.rs"
        ));
    }

    #[test]
    fn negative_rejects_same_file_under_artifact_root_prefix() {
        assert!(!CancellationProtocol::accepts_fixture_path(
            "artifacts/asupersync/crates/franken-node/src/control_plane/cancellation_protocol.rs"
        ));
    }

    #[test]
    fn negative_rejects_wrong_extension() {
        assert!(!CancellationProtocol::accepts_fixture_path(
            "crates/franken-node/src/control_plane/cancellation_protocol.txt"
        ));
    }
}

#[cfg(test)]
fn cancellation_protocol_trace_violations(source: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();

    if !source.contains("CancellationProtocol") {
        violations.push("missing_cancellation_protocol_marker");
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
    if source.contains("panic!(") {
        violations.push("panic_boundary");
    }
    if source.contains(".unwrap()") {
        violations.push("unwrap_boundary");
    }

    violations
}

#[cfg(test)]
mod trace_violation_tests {
    use super::cancellation_protocol_trace_violations;

    #[test]
    fn negative_empty_trace_reports_missing_marker() {
        let violations = cancellation_protocol_trace_violations("");

        assert_eq!(violations, vec!["missing_cancellation_protocol_marker"]);
    }

    #[test]
    fn negative_wrong_marker_reports_missing_cancellation_protocol() {
        let violations = cancellation_protocol_trace_violations("pub struct CancelProtocol;");

        assert_eq!(violations, vec!["missing_cancellation_protocol_marker"]);
    }

    #[test]
    fn negative_tokio_spawn_boundary_is_rejected() {
        let source = "pub struct CancellationProtocol; fn run() { tokio::spawn(async {}); }";

        let violations = cancellation_protocol_trace_violations(source);

        assert_eq!(violations, vec!["async_spawn_boundary"]);
    }

    #[test]
    fn negative_thread_spawn_boundary_is_rejected() {
        let source = "pub struct CancellationProtocol; fn run() { std::thread::spawn(|| {}); }";

        let violations = cancellation_protocol_trace_violations(source);

        assert_eq!(violations, vec!["thread_spawn_boundary"]);
    }

    #[test]
    fn negative_unsafe_boundary_is_rejected() {
        let source = "pub struct CancellationProtocol; unsafe fn cancel_now() {}";

        let violations = cancellation_protocol_trace_violations(source);

        assert_eq!(violations, vec!["unsafe_boundary"]);
    }

    #[test]
    fn negative_panic_boundary_is_rejected() {
        let source = "pub struct CancellationProtocol; fn cancel_now() { panic!(\"boom\"); }";

        let violations = cancellation_protocol_trace_violations(source);

        assert_eq!(violations, vec!["panic_boundary"]);
    }

    #[test]
    fn negative_unwrap_boundary_is_rejected() {
        let source =
            "pub struct CancellationProtocol; fn cancel_now(x: Option<()>) { x.unwrap(); }";

        let violations = cancellation_protocol_trace_violations(source);

        assert_eq!(violations, vec!["unwrap_boundary"]);
    }

    #[test]
    fn negative_multiple_boundary_violations_are_all_reported_in_order() {
        let source = "unsafe fn cancel_now() { tokio::spawn(async {}); panic!(\"boom\"); }";

        let violations = cancellation_protocol_trace_violations(source);

        assert_eq!(
            violations,
            vec![
                "missing_cancellation_protocol_marker",
                "async_spawn_boundary",
                "unsafe_boundary",
                "panic_boundary"
            ]
        );
    }
}
