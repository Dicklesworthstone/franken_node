// Quick compilation test for validation_readiness flight recorder changes
use std::collections::BTreeMap;
use chrono::{DateTime, Utc};

#[allow(unused_imports)]
use crates::franken_node::ops::validation_readiness::*;
#[allow(unused_imports)]
use crates::franken_node::ops::validation_broker::{
    ValidationProofStatus, ValidationReceipt, ValidationFlightRecorderRef,
};
#[allow(unused_imports)]
use crates::franken_node::ops::validation_recovery_planner::{
    RecoveryDecision, RecoveryAction, recovery_decision_for_exit,
};

fn main() {
    println!("Compilation test complete");
}