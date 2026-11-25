#!/usr/bin/env bash
# Stop the Anvil chain started by anvil-up.sh.
set -euo pipefail

PIDFILE="${1:-/tmp/cipherlayer-anvil.pid}"

if [ -f "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE")"
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    echo "Anvil (pid $PID) stopped."
  else
    echo "No running Anvil at pid $PID."
  fi
  rm -f "$PIDFILE"
else
  echo "No pidfile ($PIDFILE) — nothing to stop."
fi
