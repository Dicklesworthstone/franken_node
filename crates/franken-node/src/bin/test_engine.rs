#!/usr/bin/env cargo run --bin test-engine

//! Test engine binary for engine dispatcher integration tests
//!
//! This binary mimics the behavior of the franken-engine for testing purposes.
//! It spawns a background child process that sleeps, then exits immediately,
//! leaving the child as a descendant process. This tests whether the engine
//! dispatcher properly reaps child processes that hold file descriptors.

use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    // Spawn a background sleep process (mimics the shell script's `(sleep 5) &`)
    let _child = Command::new("sleep")
        .arg("5")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn background sleep process");

    // Print output that the test expects to see
    println!("parent-exited");

    // Small delay to ensure the background process is started
    thread::sleep(Duration::from_millis(10));

    // Exit with success code (mimics shell script's `exit 0`)
    std::process::exit(0);
}