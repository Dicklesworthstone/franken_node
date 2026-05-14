use frankenengine_node::{
    lock_utils,
    security::isolation_rail_router::{
        ISO_003, ISO_004, IsolationRail, RailRouter, RailRouterError,
    },
};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

fn lock_router<'a>(router: &'a Arc<Mutex<RailRouter>>) -> MutexGuard<'a, RailRouter> {
    lock_utils::try_lock(router.as_ref(), "isolation rail router test mutex")
        .expect("isolation rail router test mutex should not be poisoned")
}

#[test]
fn inv_atomic_transition_concurrent_hot_elevation_stress() {
    const WORKLOADS: usize = 64;
    const THREADS: usize = 16;

    let router = Arc::new(Mutex::new(RailRouter::with_default_policy()));
    {
        let mut router_guard = lock_router(&router);
        for idx in 0..WORKLOADS {
            router_guard
                .classify_workload(&format!("atomic-workload-{idx:02}"), 0.1)
                .unwrap();
        }
    }

    let start = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();
    for thread_idx in 0..THREADS {
        let router = Arc::clone(&router);
        let start = Arc::clone(&start);
        handles.push(std::thread::spawn(move || {
            start.wait();
            for step in 0..WORKLOADS {
                let workload_id = format!("atomic-workload-{:02}", (step + thread_idx) % WORKLOADS);
                let target_rail = match (thread_idx + step) % 3 {
                    0 => IsolationRail::Sandboxed,
                    1 => IsolationRail::HardenedSandbox,
                    _ => IsolationRail::FullIsolation,
                };

                let mut router_guard = lock_router(&router);
                let before = router_guard.get_rail(&workload_id).unwrap();
                let result = router_guard.hot_elevate(
                    &workload_id,
                    target_rail,
                    "concurrent atomic transition stress",
                );
                let after = router_guard.get_rail(&workload_id).unwrap();

                assert!(IsolationRail::ALL.contains(&before));
                assert!(IsolationRail::ALL.contains(&after));
                assert!(
                    after >= before,
                    "rail must remain monotonic under concurrent transition stress"
                );

                match result {
                    Ok(event) => {
                        assert_eq!(event.from, before);
                        assert_eq!(event.to, target_rail);
                        assert_eq!(after, target_rail);
                    }
                    Err(
                        RailRouterError::SameRailElevation { .. }
                        | RailRouterError::DowngradeRejected { .. },
                    ) => {
                        assert_eq!(after, before);
                    }
                    Err(err) => {
                        assert!(
                            matches!(
                                err,
                                RailRouterError::SameRailElevation { .. }
                                    | RailRouterError::DowngradeRejected { .. }
                            ),
                            "unexpected transition error: {err}"
                        );
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let router_guard = lock_router(&router);
    assert_eq!(router_guard.workload_count(), WORKLOADS);
    let starts = router_guard
        .audit_log()
        .iter()
        .filter(|entry| entry.event_code == ISO_003)
        .count();
    let completions = router_guard
        .audit_log()
        .iter()
        .filter(|entry| entry.event_code == ISO_004)
        .count();
    assert_eq!(starts, completions);
    assert_eq!(router_guard.elevation_log().len(), completions);

    for idx in 0..WORKLOADS {
        let rail = router_guard
            .get_rail(&format!("atomic-workload-{idx:02}"))
            .unwrap();
        assert!(IsolationRail::ALL.contains(&rail));
        assert!(rail >= IsolationRail::Shared);
    }
}
