#!/usr/bin/env bash
# Regenerate the Verifier-SDK cross-implementation conformance fixture
#   sdk/verifier/tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle
# deterministically, from checked-in inputs, via the REAL `franken-node incident
# bundle` CLI (bd-reality-20260923-26n9r.7 D3 / .14).
#
# Why this exists: the fixture used to be an unreproducible blob — the evidence
# that produced it was never checked in and there was no regeneration script, so
# when the bundle wire format evolves nobody can re-derive it. The bundle is
# deterministic (created_at is derived from the timeline, bundle_id is
# deterministic, Ed25519 signing is deterministic), so given the checked-in
# evidence + the RFC 8032 s7.1 TEST 1 seed the output is byte-reproducible. The
# SDK test (sdk/verifier/tests/cli_incident_bundle.rs) then verifies it under
# that test vector's PUBLISHED public key — an anchor independent of the bundle.
#
# Usage:
#   scripts/regen_cli_incident_bundle_fixture.sh            # builds via cargo run
#   FRANKEN_NODE_BIN=/path/to/franken-node scripts/regen... # uses a prebuilt bin
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX_DIR="$REPO_ROOT/sdk/verifier/tests/fixtures/cli_incident_bundle"
EVIDENCE="$FIX_DIR/INC-SDK-FIXTURE-1.evidence.json"
SEED_HEX="$FIX_DIR/rfc8032_test1_seed.hex"
OUT="$FIX_DIR/INC-SDK-FIXTURE-1.fnbundle"
ID="INC-SDK-FIXTURE-1"

work="$(mktemp -d)"   # ephemeral; left for the OS to reap (no rm -rf by design)

# RFC 8032 s7.1 TEST 1 secret scalar -> raw 32-byte key file (the len==32 branch
# of the CLI signing-key parser).
tr -d '[:space:]' < "$SEED_HEX" | xxd -r -p > "$work/seed.key"

if [ -n "${FRANKEN_NODE_BIN:-}" ]; then
  RUN=("$FRANKEN_NODE_BIN")
else
  RUN=(cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p frankenengine-node --bin franken-node --)
fi

# The CLI writes <slug>.fnbundle into the CWD; run it in the scratch dir.
( cd "$work" && "${RUN[@]}" incident bundle --id "$ID" \
    --evidence-path "$EVIDENCE" --verify --receipt-signing-key "$work/seed.key" )

produced="$(cd "$work" && ls -1 ./*.fnbundle | head -1)"
cp "$work/$produced" "$OUT"
echo "regenerated $OUT from $EVIDENCE"

# Emit the fixture between markers so a remote/offloaded run can retrieve it
# from stdout without copying files back off the build host.
echo "=====FNBUNDLE_BEGIN====="
cat "$OUT"
echo
echo "=====FNBUNDLE_END====="
