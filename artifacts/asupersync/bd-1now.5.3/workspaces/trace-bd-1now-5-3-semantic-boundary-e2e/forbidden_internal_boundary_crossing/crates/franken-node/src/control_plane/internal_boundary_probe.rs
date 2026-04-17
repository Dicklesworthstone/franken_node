use franken_engine::scheduler_internal::Queue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalBoundaryProbeViolation {
    EmptyProbe,
    SchedulerInternalImport,
    QueueTypeLeak,
    RuntimeDuplicatePath,
    ParentEscape,
    TokioSpawn,
    ThreadSpawn,
    UnsafeBlock,
}

pub fn probe() {}

pub fn internal_boundary_probe_violations(source: &str) -> Vec<InternalBoundaryProbeViolation> {
    let mut violations = Vec::new();
    let trimmed = source.trim();

    if trimmed.is_empty() {
        violations.push(InternalBoundaryProbeViolation::EmptyProbe);
        return violations;
    }

    if source.contains("franken_engine::scheduler_internal") {
        violations.push(InternalBoundaryProbeViolation::SchedulerInternalImport);
    }

    if source.contains("Queue") {
        violations.push(InternalBoundaryProbeViolation::QueueTypeLeak);
    }

    if source.contains("runtime/cancellation_protocol.rs") {
        violations.push(InternalBoundaryProbeViolation::RuntimeDuplicatePath);
    }

    if source.contains("../") {
        violations.push(InternalBoundaryProbeViolation::ParentEscape);
    }

    if source.contains("tokio::spawn") {
        violations.push(InternalBoundaryProbeViolation::TokioSpawn);
    }

    if source.contains("std::thread::spawn") {
        violations.push(InternalBoundaryProbeViolation::ThreadSpawn);
    }

    if source.contains("unsafe") {
        violations.push(InternalBoundaryProbeViolation::UnsafeBlock);
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::{internal_boundary_probe_violations, InternalBoundaryProbeViolation};

    #[test]
    fn negative_current_fixture_reports_scheduler_internal_import() {
        let source = include_str!("internal_boundary_probe.rs");

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::SchedulerInternalImport)
        );
    }

    #[test]
    fn negative_current_fixture_reports_queue_type_leak() {
        let source = include_str!("internal_boundary_probe.rs");

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::QueueTypeLeak)
        );
    }

    #[test]
    fn negative_empty_probe_is_rejected_without_secondary_noise() {
        assert_eq!(
            internal_boundary_probe_violations("   \n\t"),
            vec![InternalBoundaryProbeViolation::EmptyProbe]
        );
    }

    #[test]
    fn negative_parent_escape_path_is_rejected() {
        let source = r#"const FIXTURE: &str = "../runtime/cancellation_protocol.rs";"#;

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::ParentEscape)
        );
    }

    #[test]
    fn negative_runtime_duplicate_path_is_rejected() {
        let source = r#"const DUPLICATE: &str = "runtime/cancellation_protocol.rs";"#;

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::RuntimeDuplicatePath)
        );
    }

    #[test]
    fn negative_tokio_spawn_boundary_crossing_is_rejected() {
        let source = "pub fn probe() { tokio::spawn(async {}); }";

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::TokioSpawn)
        );
    }

    #[test]
    fn negative_thread_spawn_boundary_crossing_is_rejected() {
        let source = "pub fn probe() { std::thread::spawn(|| ()); }";

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::ThreadSpawn)
        );
    }

    #[test]
    fn negative_unsafe_probe_body_is_rejected() {
        let source = "pub fn probe() { unsafe { core::hint::unreachable_unchecked() } }";

        assert!(
            internal_boundary_probe_violations(source)
                .contains(&InternalBoundaryProbeViolation::UnsafeBlock)
        );
    }

    #[test]
    fn negative_mixed_boundary_violations_are_reported_in_stable_order() {
        let source = r#"
            use franken_engine::scheduler_internal::Queue;
            const DUPLICATE: &str = "../runtime/cancellation_protocol.rs";
            pub fn probe() {
                tokio::spawn(async {});
                std::thread::spawn(|| ());
            }
        "#;

        assert_eq!(
            internal_boundary_probe_violations(source),
            vec![
                InternalBoundaryProbeViolation::SchedulerInternalImport,
                InternalBoundaryProbeViolation::QueueTypeLeak,
                InternalBoundaryProbeViolation::RuntimeDuplicatePath,
                InternalBoundaryProbeViolation::ParentEscape,
                InternalBoundaryProbeViolation::TokioSpawn,
                InternalBoundaryProbeViolation::ThreadSpawn,
            ]
        );
    }

    #[test]
    fn positive_control_plane_only_probe_has_no_violations() {
        let source = "pub fn probe() { crate::control_plane::cancellation_protocol::probe(); }";

        assert!(internal_boundary_probe_violations(source).is_empty());
    }
}
