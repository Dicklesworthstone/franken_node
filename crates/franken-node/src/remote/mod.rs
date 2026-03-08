//! Remote-control primitives for network-bound operations.

#[cfg(feature = "extended-surfaces")]
pub mod computation_registry;
#[cfg(feature = "extended-surfaces")]
pub mod eviction_saga;
#[cfg(feature = "extended-surfaces")]
pub mod idempotency;
#[cfg(feature = "extended-surfaces")]
pub mod idempotency_store;
#[cfg(feature = "extended-surfaces")]
pub mod remote_bulkhead;
pub mod virtual_transport_faults;
