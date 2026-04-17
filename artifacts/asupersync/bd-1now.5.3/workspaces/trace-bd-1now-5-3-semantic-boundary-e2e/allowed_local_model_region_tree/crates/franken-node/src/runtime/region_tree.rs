pub struct RegionTree;

impl RegionTree {
    pub const LOCAL_MODEL_PATH: &'static str = "crates/franken-node/src/runtime/region_tree.rs";

    pub fn accepts_local_model_path(path: &str) -> bool {
        path == Self::LOCAL_MODEL_PATH
    }
}

#[cfg(test)]
mod local_model_region_tree_tests {
    use super::RegionTree;

    fn region_tree_fixture_violations(source: &str) -> Vec<&'static str> {
        let mut violations = Vec::new();

        if !source.contains("RegionTree") {
            violations.push("missing_region_tree_marker");
        }
        if source.contains("franken_engine::scheduler_internal") {
            violations.push("internal_boundary_crossing");
        }
        if source.contains("RuntimeCancellationProtocol") {
            violations.push("duplicate_runtime_cancellation_family");
        }
        if source.contains("tokio::spawn") {
            violations.push("async_spawn_boundary");
        }
        if source.contains("unsafe") {
            violations.push("unsafe_boundary");
        }
        violations
    }

    #[test]
    fn accepts_canonical_runtime_region_tree_path() {
        assert!(RegionTree::accepts_local_model_path(
            RegionTree::LOCAL_MODEL_PATH
        ));
    }

    #[test]
    fn negative_rejects_empty_path() {
        assert!(!RegionTree::accepts_local_model_path(""));
    }

    #[test]
    fn negative_rejects_control_plane_region_tree_path() {
        assert!(!RegionTree::accepts_local_model_path(
            "crates/franken-node/src/control_plane/region_tree.rs"
        ));
    }

    #[test]
    fn negative_rejects_region_tree_path_with_parent_escape() {
        assert!(!RegionTree::accepts_local_model_path(
            "crates/franken-node/src/runtime/../control_plane/region_tree.rs"
        ));
    }

    #[test]
    fn negative_rejects_padded_runtime_region_tree_path() {
        assert!(!RegionTree::accepts_local_model_path(
            " crates/franken-node/src/runtime/region_tree.rs "
        ));
    }

    #[test]
    fn negative_rejects_wrong_runtime_fixture_file() {
        assert!(!RegionTree::accepts_local_model_path(
            "crates/franken-node/src/runtime/cancellation_protocol.rs"
        ));
    }

    #[test]
    fn negative_rejects_artifact_root_prefixed_region_tree_path() {
        assert!(!RegionTree::accepts_local_model_path(
            "artifacts/asupersync/crates/franken-node/src/runtime/region_tree.rs"
        ));
    }

    #[test]
    fn negative_empty_source_reports_missing_marker() {
        let violations = region_tree_fixture_violations("");

        assert_eq!(violations, vec!["missing_region_tree_marker"]);
    }

    #[test]
    fn negative_internal_boundary_crossing_is_reported() {
        let violations = region_tree_fixture_violations(
            "pub struct RegionTree; use franken_engine::scheduler_internal::Queue;",
        );

        assert_eq!(violations, vec!["internal_boundary_crossing"]);
    }

    #[test]
    fn negative_duplicate_runtime_cancellation_family_is_reported() {
        let violations = region_tree_fixture_violations(
            "pub struct RegionTree; pub struct RuntimeCancellationProtocol;",
        );

        assert_eq!(violations, vec!["duplicate_runtime_cancellation_family"]);
    }

    #[test]
    fn negative_async_spawn_boundary_is_reported() {
        let violations = region_tree_fixture_violations(
            "pub struct RegionTree; fn run() { tokio::spawn(f()); }",
        );

        assert_eq!(violations, vec!["async_spawn_boundary"]);
    }

    #[test]
    fn negative_multiple_fixture_violations_are_reported_in_order() {
        let violations = region_tree_fixture_violations(
            "unsafe fn run() { tokio::spawn(f()); RuntimeCancellationProtocol; }",
        );

        assert_eq!(
            violations,
            vec![
                "missing_region_tree_marker",
                "duplicate_runtime_cancellation_family",
                "async_spawn_boundary",
                "unsafe_boundary"
            ]
        );
    }
}

impl RegionTree {
    pub const CANONICAL_PATH: &'static str = "crates/franken-node/src/runtime/region_tree.rs";

    pub fn accepts_fixture_path(path: &str) -> bool {
        path == Self::CANONICAL_PATH
    }
}

#[cfg(test)]
fn region_tree_trace_violations(source: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();

    if !source.contains("RegionTree") {
        violations.push("missing_region_tree_marker");
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
    use super::{RegionTree, region_tree_trace_violations};

    #[test]
    fn accepts_canonical_runtime_region_tree_path() {
        assert!(RegionTree::accepts_fixture_path(RegionTree::CANONICAL_PATH));
    }

    #[test]
    fn negative_rejects_empty_path() {
        assert!(!RegionTree::accepts_fixture_path(""));
    }

    #[test]
    fn negative_rejects_whitespace_padded_path() {
        assert!(!RegionTree::accepts_fixture_path(
            " crates/franken-node/src/runtime/region_tree.rs "
        ));
    }

    #[test]
    fn negative_rejects_control_plane_region_tree_path() {
        assert!(!RegionTree::accepts_fixture_path(
            "crates/franken-node/src/control_plane/region_tree.rs"
        ));
    }

    #[test]
    fn negative_rejects_parent_directory_escape() {
        assert!(!RegionTree::accepts_fixture_path(
            "crates/franken-node/src/runtime/../control_plane/region_tree.rs"
        ));
    }

    #[test]
    fn negative_rejects_artifact_root_prefixed_path() {
        assert!(!RegionTree::accepts_fixture_path(
            "artifacts/asupersync/crates/franken-node/src/runtime/region_tree.rs"
        ));
    }

    #[test]
    fn negative_empty_trace_reports_missing_marker() {
        assert_eq!(
            region_tree_trace_violations(""),
            vec!["missing_region_tree_marker"]
        );
    }

    #[test]
    fn negative_control_plane_boundary_is_rejected() {
        let source = "pub struct RegionTree; mod control_plane {}";

        assert_eq!(
            region_tree_trace_violations(source),
            vec!["control_plane_boundary"]
        );
    }

    #[test]
    fn negative_multiple_forbidden_boundaries_are_reported_in_order() {
        let source = "unsafe fn build() { tokio::spawn(async {}); maybe.unwrap(); }";

        assert_eq!(
            region_tree_trace_violations(source),
            vec![
                "missing_region_tree_marker",
                "unsafe_boundary",
                "async_spawn_boundary",
                "unwrap_boundary"
            ]
        );
    }
}
