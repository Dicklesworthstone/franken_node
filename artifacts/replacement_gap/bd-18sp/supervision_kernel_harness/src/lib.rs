#![allow(dead_code)]

pub mod capacity_defaults {
    pub mod aliases {
        pub const MAX_EVENTS: usize = 4096;
    }
}

#[path = "../../../../../crates/franken-node/src/connector/supervision.rs"]
pub mod supervision;

#[cfg(test)]
mod tests {
    use super::supervision::{
        ChildSpec, RestartType, SupervisionClockError, SupervisionError, SupervisionStrategy,
        Supervisor,
    };

    fn child(name: &str) -> ChildSpec {
        ChildSpec {
            name: name.to_string(),
            restart_type: RestartType::Permanent,
            shutdown_timeout_ms: 1_000,
        }
    }

    #[test]
    fn negative_duplicate_child_is_rejected_without_replacing_existing_record() {
        let mut supervisor =
            Supervisor::with_deterministic_clock(SupervisionStrategy::OneForOne, 3, 60_000, 1, 0);
        supervisor.add_child(child("worker")).unwrap();

        let err = supervisor.add_child(child("worker")).unwrap_err();

        assert!(matches!(err, SupervisionError::DuplicateChild { name } if name == "worker"));
        assert_eq!(supervisor.child_count(), 1);
    }

    #[test]
    fn negative_remove_missing_child_is_rejected_without_event_mutation() {
        let mut supervisor =
            Supervisor::with_deterministic_clock(SupervisionStrategy::OneForOne, 3, 60_000, 1, 0);
        let before_events = supervisor.events().len();

        let err = supervisor.remove_child("missing").unwrap_err();

        assert!(matches!(err, SupervisionError::ChildNotFound { name } if name == "missing"));
        assert_eq!(supervisor.events().len(), before_events);
    }

    #[test]
    fn negative_handle_failure_missing_child_is_rejected_without_event_mutation() {
        let mut supervisor =
            Supervisor::with_deterministic_clock(SupervisionStrategy::OneForOne, 3, 60_000, 1, 0);
        let before_events = supervisor.events().len();

        let err = supervisor.handle_failure("missing").unwrap_err();

        assert!(matches!(err, SupervisionError::ChildNotFound { name } if name == "missing"));
        assert_eq!(supervisor.events().len(), before_events);
    }

    #[test]
    fn negative_deterministic_clock_rejects_regression_without_time_mutation() {
        let mut supervisor =
            Supervisor::with_deterministic_clock(SupervisionStrategy::OneForOne, 3, 60_000, 1, 50);

        let err = supervisor.set_clock_ms(49).unwrap_err();

        assert!(matches!(
            err,
            SupervisionClockError::ClockRegression {
                current_ms: 50,
                attempted_ms: 49
            }
        ));
        assert_eq!(supervisor.current_time_ms(), 50);
    }

    #[test]
    fn negative_steady_clock_rejects_manual_advance_without_events() {
        let mut supervisor = Supervisor::new(SupervisionStrategy::OneForOne, 3, 60_000, 1);
        let before_events = supervisor.events().len();

        let err = supervisor.advance_clock_ms(1).unwrap_err();

        assert_eq!(err, SupervisionClockError::ManualControlUnavailable);
        assert_eq!(supervisor.events().len(), before_events);
    }

    #[test]
    fn negative_serde_rejects_unknown_supervision_strategy() {
        let err = serde_json::from_str::<SupervisionStrategy>(r#""one_for_none""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_serde_rejects_child_spec_missing_name() {
        let err = serde_json::from_str::<ChildSpec>(
            r#"{
                "restart_type":"permanent",
                "shutdown_timeout_ms":1000
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn negative_serde_rejects_child_spec_string_timeout() {
        let err = serde_json::from_str::<ChildSpec>(
            r#"{
                "name":"worker",
                "restart_type":"permanent",
                "shutdown_timeout_ms":"1000"
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }
}
