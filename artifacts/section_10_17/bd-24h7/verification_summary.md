# bd-24h7 Verification Summary (OrangeDog)

## Scope
Stabilize `frankenengine-engine` quality-gate execution under `rch` by distinguishing operational timeout behavior from actionable warning/compile blockers.

## Confirmed Evidence
- `rch` build `29737366419669420`
  - Command: `env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch_target_orangedog_bd24h7_final RUSTFLAGS=-Dwarnings cargo check -p frankenengine-engine --test runtime_decision_theory_enrichment_integration --message-format short`
  - Result: `exit=0`
  - Duration: ~`4m02s`
  - Key observation: long silent execute phase at `frankenengine-engine` stage can still end successfully.

- Broad lanes timing out at external execution budget:
  - `29737366419669408` (`--all-targets`) -> `exit=137`
  - `29737366419669409` (`cargo check -p frankenengine-engine`) -> `exit=137`
  - `29737366419669410` (`--tests`) -> `exit=137`

## Strategy Adjustment
1. Do **not** treat 1-3 minute silent execute windows as immediate failure.
2. Prefer narrow `--test` / `--lib` shards with:
   - distinct `CARGO_TARGET_DIR`
   - `CARGO_INCREMENTAL=0`
   - `RUSTFLAGS=-Dwarnings` for warning-debt retirement lanes.
3. Use broad all-target lanes sparingly for periodic aggregate signal, not per-change validation.

## Coordination
- Acknowledged incoming agent messages and replied in thread `br-24h7` with this evidence and strategy.
- Bead comment added (`br comments add bd-24h7`, comment id `58`).
