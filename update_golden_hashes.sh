#!/bin/bash
# Script to capture golden hash values and update the schema_versions_byte_layout_golden.rs file

echo "Running schema version tests to capture golden hash values..."

# Run the test and capture output
TEST_OUTPUT=$(RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- env CARGO_TARGET_DIR=/tmp/franken-tgt-cc3 cargo test schema_versions_byte_layout_golden --package frankenengine-node 2>&1)

echo "Test output:"
echo "$TEST_OUTPUT"

# Extract the actual hash values from the test failure output
# The test will fail because we have placeholder values, but it will show the actual values

ENTRY_COUNT_HASH=$(echo "$TEST_OUTPUT" | grep -A 1 "Hash to copy:" | grep "sha256:" | head -1 | tr -d ' ')
CRITICAL_CONSTANTS_HASH=$(echo "$TEST_OUTPUT" | grep -A 1 "CRITICAL CONSTANTS" | grep "sha256:" | head -1 | tr -d ' ')
STRUCTURE_HASH=$(echo "$TEST_OUTPUT" | grep -A 1 "Structure hash:" | grep "sha256:" | head -1 | tr -d ' ')

echo ""
echo "Extracted hash values:"
echo "Entry count hash: $ENTRY_COUNT_HASH"
echo "Critical constants hash: $CRITICAL_CONSTANTS_HASH"
echo "Structure hash: $STRUCTURE_HASH"

# Update the file if we found valid hashes
if [[ -n "$ENTRY_COUNT_HASH" && "$ENTRY_COUNT_HASH" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Updating entry count hash..."
    sed -i "s/sha256:0000000000000000000000000000000000000000000000000000000000000000/$ENTRY_COUNT_HASH/" crates/franken-node/src/schema_versions_byte_layout_golden.rs
fi

if [[ -n "$CRITICAL_CONSTANTS_HASH" && "$CRITICAL_CONSTANTS_HASH" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Updating critical constants hash..."
    sed -i "s/sha256:1111111111111111111111111111111111111111111111111111111111111111/$CRITICAL_CONSTANTS_HASH/" crates/franken-node/src/schema_versions_byte_layout_golden.rs
fi

if [[ -n "$STRUCTURE_HASH" && "$STRUCTURE_HASH" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Updating structure hash..."
    sed -i "s/sha256:2222222222222222222222222222222222222222222222222222222222222222/$STRUCTURE_HASH/" crates/franken-node/src/schema_versions_byte_layout_golden.rs
fi

echo "Golden hash update complete. Re-run the test to verify."