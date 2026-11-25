#!/usr/bin/env bash
# Start a local Anvil development chain (chain-id 31337) in the background.
set -euo pipefail

PORT="${1:-8545}"
PIDFILE="${2:-/tmp/cipherlayer-anvil.pid}"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "Anvil already running (pid $(cat "$PIDFILE"), port $PORT)."
  exit 0
fi

command -v anvil >/dev/null 2>&1 || { echo "anvil not found — install Foundry (https://getfoundry.sh)" >&2; exit 1; }

anvil --port "$PORT" --chain-id 31337 --silent &
echo $! > "$PIDFILE"

# Wait for RPC readiness.
for _ in $(seq 1 50); do
  if curl -s -X POST "http://127.0.0.1:$PORT" -H 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' | grep -q '0x7a69'; then
    echo "Anvil up on http://127.0.0.1:$PORT (chain-id 31337, pid $(cat "$PIDFILE"))."
    exit 0
  fi
  sleep 0.2
done

echo "Anvil failed to become ready on port $PORT." >&2
exit 1
