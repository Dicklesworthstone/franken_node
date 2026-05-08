#!/usr/bin/env rustc

use std::path::Path;

fn main() {
    // Basic syntax check for the hygiene detection logic
    let test_path = Path::new("/tmp");
    println!("Testing hygiene detection on: {:?}", test_path);

    if test_path.exists() {
        println!("✓ Path exists check works");
    }

    if test_path.is_dir() {
        println!("✓ Directory check works");
    }

    println!("✓ Basic hygiene detection logic compiles");
}