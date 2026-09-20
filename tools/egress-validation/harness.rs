//! Focused compilation of the production egress policy/provider dependency
//! closure and the repository's registered integration tests. No policy, DNS,
//! TLS, filesystem or flow-control implementation is substituted here.
//!
//! Only unrelated CLI configuration is omitted: build.rs selects the exact
//! network config declarations/default implementation from config.rs. This
//! target proves the egress subsystem, not the complete node binary or VM.
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/production_egress.rs"));
