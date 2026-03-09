use frankenengine_node::connector::supervision::{
    ChildSpec, ChildState, RestartType, SupervisionAction, SupervisionEvent, SupervisionStrategy,
    Supervisor,
};

fn make_spec(name: &str) -> ChildSpec {
    ChildSpec {
        name: name.to_string(),
        restart_type: RestartType::Permanent,
        shutdown_timeout_ms: 5_000,
    }
}

#[test]
fn public_api_uses_elapsed_time_for_restart_window_expiry() {
    let mut supervisor =
        Supervisor::with_deterministic_clock(SupervisionStrategy::OneForOne, 2, 1_000, 4, 0);
    supervisor.add_child(make_spec("worker")).unwrap();

    assert!(matches!(
        supervisor.handle_failure("worker").unwrap(),
        SupervisionAction::Restart { .. }
    ));
    assert!(matches!(
        supervisor.handle_failure("worker").unwrap(),
        SupervisionAction::Restart { .. }
    ));
    assert_eq!(supervisor.child_state("worker"), Some(ChildState::Running));

    supervisor.advance_clock_ms(1_001).unwrap();

    assert!(matches!(
        supervisor.handle_failure("worker").unwrap(),
        SupervisionAction::Restart { .. }
    ));

    let health = supervisor.health_status();
    assert_eq!(health.restart_count, 1);
    assert_eq!(health.budget_remaining, 1);
    assert_eq!(health.oldest_restart_age_ms, Some(0));
}

#[test]
fn public_api_can_record_structured_health_reports() {
    let mut supervisor =
        Supervisor::with_deterministic_clock(SupervisionStrategy::OneForOne, 3, 5_000, 4, 250);
    supervisor.add_child(make_spec("worker")).unwrap();
    supervisor.handle_failure("worker").unwrap();

    let health = supervisor.record_health_report();
    let last_event = supervisor.events().last();

    assert_eq!(health.current_time_ms, 250);
    assert!(matches!(
        last_event,
        Some(SupervisionEvent::HealthReport { health: event_health })
            if event_health == &health
    ));
}
