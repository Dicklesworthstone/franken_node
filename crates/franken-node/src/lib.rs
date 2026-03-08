#![forbid(unsafe_code)]
extern crate self as frankenengine_node;

#[cfg(feature = "extended-surfaces")]
pub mod api;
#[cfg(feature = "extended-surfaces")]
pub mod claims;
pub mod config;
#[cfg(feature = "extended-surfaces")]
pub mod conformance;
pub mod connector;
pub mod control_plane;
#[cfg(feature = "extended-surfaces")]
pub mod encoding;
#[cfg(feature = "extended-surfaces")]
pub mod extensions;
#[cfg(feature = "extended-surfaces")]
pub mod federation;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod migration;
pub mod observability;
pub mod ops;
#[cfg(feature = "extended-surfaces")]
pub mod perf;
#[cfg(feature = "extended-surfaces")]
pub mod policy;
#[cfg(feature = "extended-surfaces")]
pub mod registry;
pub mod remote;
#[cfg(feature = "extended-surfaces")]
pub mod repair;
pub mod replay;
#[cfg(feature = "extended-surfaces")]
#[path = "control_plane/root_pointer.rs"]
pub mod root_pointer;
pub mod runtime;
#[cfg(feature = "extended-surfaces")]
pub mod sdk;
pub mod security;
pub mod storage;
pub mod supply_chain;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod tools;
#[cfg(feature = "extended-surfaces")]
pub mod verifier_economy;
