#![forbid(unsafe_code)]

//! Shared production identities and operator containment for the standalone
//! migration executables. Normal library compilation keeps the production
//! controller implementation shared without duplicating its inline test graph
//! into each executable's test target.

#[path = "../../crates/franken-node/src/schema_versions.rs"]
mod identities;
pub use identities::*;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../../crates/franken-node/src/capacity_defaults.rs"]
mod capacity_defaults;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../../crates/franken-node/src/security/constant_time.rs"]
pub(crate) mod constant_time;
#[cfg(target_os = "linux")]
mod security {
    pub(crate) use crate::constant_time;
}

#[cfg(target_os = "linux")]
#[path = "../../crates/franken-node/src/runtime/safe_mode.rs"]
pub mod safe_mode;
#[cfg(target_os = "linux")]
pub mod runtime {
    pub use crate::safe_mode;
}

// The controller's actionable diagnostic is an error-display dependency, not
// a second controller schema or admission policy. Preserve the product's
// message/fix-command shape without importing the entire application crate.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ActionableError {
    message: String,
    fix_command: String,
}

#[cfg(target_os = "linux")]
impl ActionableError {
    fn new(message: impl Into<String>, fix_command: impl Into<String>) -> Self {
        Self { message: message.into(), fix_command: fix_command.into() }
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for ActionableError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}\nfix_command={}", self.message, self.fix_command)
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for ActionableError {}
