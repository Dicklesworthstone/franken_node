//! Execute the exact native RemoteCap HTTP implementation and its focused
//! transport regressions without rebuilding unrelated inline test modules.
#![cfg(all(feature = "engine", feature = "http-client"))]

pub use frankenengine_node::{bounded_read, config, ops};

#[path = "../src/security/remote_cap_http.rs"]
mod remote_cap_http;
