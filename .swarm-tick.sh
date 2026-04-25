#!/usr/bin/env bash
# Orchestrator tick script for franken_node swarm.
# Produces structured single-screen output; the orchestrator agent then
# dispatches prompts / runs cleanups based on it.

set -u

PROJECT=franken_node
PROJECT_DIR=/data/projects/franken_node
STALE_BEAD_MIN=${STALE_BEAD_MIN:-1440}
TMUX=/usr/bin/tmux

echo "====== TICK $(date -u +%FT%TZ) ======"

# --- 1. Disk -----------------------------------------------------------------
USE=$(command df --output=pcent "$PROJECT_DIR" | tail -1 | tr -dc 0-9)
AVAIL_G=$(command df -BG --output=avail "$PROJECT_DIR" | tail -1 | tr -dc 0-9)
echo "DISK: used=${USE}% avail=${AVAIL_G}G"

# --- 2+3. Bead summary + Ready work (single br ready call) ------------------
echo "READY:"
br ready 2>/dev/null | command grep -E '^[0-9]+\. \[' | head -8 | sed 's/^/  /'

# --- 4. Pane state (panes 2..7; 1 is user) ----------------------------------
echo "PANES:"
# Discover active window of the franken_node session
WIN=$($TMUX list-windows -t "$PROJECT" -F '#{window_index}' 2>/dev/null | head -1)
WIN=${WIN:-1}
$TMUX list-panes -t "${PROJECT}:${WIN}" -F '#{pane_index} #{pane_id} #{pane_current_command}' 2>/dev/null | while read IDX PANEID CMD; do
    [ "$IDX" = "1" ] && continue
    TAIL=$($TMUX capture-pane -p -S -20 -t "$PANEID" 2>/dev/null)
    FP=$(printf '%s' "$TAIL" | command md5sum | cut -c1-8)
    RL="OK"; WORK="I"
    if printf '%s' "$TAIL" | command grep -qE "You've hit your (usage )?limit|hit your limit|You've hit|rate.?limit|usage limit"; then RL="RL"; fi
    if printf '%s' "$TAIL" | command grep -qE "esc to interrupt|• Working|✻|✺|✶|⏺|Running…|\([0-9]+m [0-9]+s\)|\([0-9]+s\)|\(thinking\)"; then WORK="W"; fi
    # Last non-empty line for signal
    LAST=$(printf '%s' "$TAIL" | awk 'NF' | tail -1 | cut -c1-70)
    echo "  pane=$IDX id=$PANEID cmd=$CMD fp=$FP rl=$RL work=$WORK last=\"$LAST\""
done

# --- 5. Build artifact inventory (lightweight: ls only) ----------------------
echo "RCH_TARGETS:"
for D in "$PROJECT_DIR"/.rch-target-*; do
    [ -d "$D" ] || continue
    NAME=$(basename "$D")
    MTIME_MIN=$(( ( $(date +%s) - $(stat -c %Y "$D") ) / 60 ))
    echo "  dir=$NAME idle_min=$MTIME_MIN"
done

# --- 6. Stalled in-progress beads — DISABLED (br DB lock contention) --------
echo "STALLED_IN_PROGRESS: (skipped to avoid br DB lock contention)"

# --- 7. Git activity ---------------------------------------------------------
echo "COMMITS_LAST_HOUR:"
command git -C "$PROJECT_DIR" log --since='1 hour ago' --oneline --format='  %cr %h %s' 2>/dev/null | head -10
echo "COMMITS_LAST_6H_COUNT:"
command git -C "$PROJECT_DIR" log --since='6 hours ago' --oneline 2>/dev/null | wc -l

echo "====== TICK END ======"
