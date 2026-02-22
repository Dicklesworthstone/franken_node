#!/usr/bin/env bash
set -euo pipefail
rustc --edition=2024 --test crates/franken-node/src/connector/operator_intelligence.rs -o /tmp/operator_intelligence_tests
/tmp/operator_intelligence_tests --nocapture
