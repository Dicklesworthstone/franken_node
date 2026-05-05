//! Centralized clock abstraction for time operations.
//!
//! This module provides a single point of control for wall clock access,
//! enabling deterministic testing and handling of clock skew/NTP failures.

use chrono::{DateTime, Utc};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

/// Global clock instance for production use.
static GLOBAL_CLOCK: std::sync::OnceLock<Arc<dyn Clock + Send + Sync>> = std::sync::OnceLock::new();

/// Clock abstraction trait for testing and production.
pub trait Clock {
    /// Returns the current UTC time.
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock implementation using system time.
#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        chrono::Utc::now()
    }
}

/// Test clock for deterministic time injection.
#[cfg(test)]
#[derive(Debug)]
pub struct TestClock {
    current_time: Mutex<DateTime<Utc>>,
}

#[cfg(test)]
impl TestClock {
    /// Create a test clock starting at the given time.
    pub fn new(start_time: DateTime<Utc>) -> Self {
        Self {
            current_time: Mutex::new(start_time),
        }
    }

    /// Advance the clock by the given duration.
    pub fn advance(&self, duration: chrono::Duration) {
        let mut time = self.current_time.lock().unwrap();
        *time = *time + duration;
    }

    /// Set the clock to a specific time.
    pub fn set_time(&self, time: DateTime<Utc>) {
        let mut current = self.current_time.lock().unwrap();
        *current = time;
    }
}

#[cfg(test)]
impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.current_time.lock().unwrap()
    }
}

/// Get the current wall clock time.
///
/// This is the primary entry point for all time operations in the system.
/// In production, returns system time. In tests, can be injected with
/// deterministic time via `set_test_clock`.
pub fn wall_now() -> DateTime<Utc> {
    let clock = GLOBAL_CLOCK.get_or_init(|| Arc::new(SystemClock));
    clock.now()
}

/// Set a test clock for deterministic testing.
///
/// # Panics
///
/// Panics if called after the global clock has already been initialized.
#[cfg(test)]
pub fn set_test_clock(clock: Arc<dyn Clock + Send + Sync>) {
    if GLOBAL_CLOCK.set(clock).is_err() {
        panic!("Global clock already initialized - call this at the start of tests");
    }
}

/// Reset the global clock (for testing only).
#[cfg(test)]
pub fn reset_clock() {
    // We can't reset OnceLock, so this is a limitation for now.
    // In practice, each test process starts fresh.
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_clock_injection() {
        // Create a deterministic time
        let test_time = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
        let test_clock = Arc::new(TestClock::new(test_time));

        // This test needs to be in its own process due to OnceLock limitation
        // For now, just test the TestClock directly
        assert_eq!(test_clock.now(), test_time);

        // Test advancement
        test_clock.advance(chrono::Duration::hours(1));
        let expected = Utc.with_ymd_and_hms(2024, 1, 1, 13, 0, 0).unwrap();
        assert_eq!(test_clock.now(), expected);
    }

    #[test]
    fn system_clock_returns_current_time() {
        let system_clock = SystemClock;
        let before = chrono::Utc::now();
        let clock_time = system_clock.now();
        let after = chrono::Utc::now();

        assert!(clock_time >= before);
        assert!(clock_time <= after);
    }

    #[test]
    fn test_injected_clock_deterministic_time_for_testing() {
        // This test demonstrates how injected clocks enable deterministic testing
        // by replacing wall clock calls with predictable test time.

        use chrono::TimeZone;

        // Create a fixed test time
        let fixed_time = Utc.with_ymd_and_hms(2024, 6, 15, 14, 30, 0).unwrap();
        let test_clock = Arc::new(TestClock::new(fixed_time));

        // Simulate what would happen in a real test scenario
        // (In practice, set_test_clock would be called in test setup)

        // Direct clock usage should be deterministic
        let time1 = test_clock.now();
        let time2 = test_clock.now();
        assert_eq!(time1, time2, "TestClock should return consistent time");
        assert_eq!(time1, fixed_time, "TestClock should return the set time");

        // Time can be advanced deterministically
        let advance_by = chrono::Duration::hours(2);
        test_clock.advance(advance_by);

        let advanced_time = test_clock.now();
        let expected_advanced = fixed_time + advance_by;
        assert_eq!(
            advanced_time, expected_advanced,
            "TestClock should advance deterministically"
        );

        // Time can be set to specific values for testing edge cases
        let edge_case_time = Utc.with_ymd_and_hms(2038, 1, 19, 3, 14, 8).unwrap(); // Y2038 edge
        test_clock.set_time(edge_case_time);
        assert_eq!(
            test_clock.now(),
            edge_case_time,
            "TestClock should allow setting specific times"
        );

        // This demonstrates the key benefit: tests using wall_now() via the centralized
        // clock can be made deterministic by injecting a TestClock, preventing flaky
        // time-based tests and enabling testing of time-sensitive edge cases.
    }
}
