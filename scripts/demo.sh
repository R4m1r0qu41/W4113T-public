#!/usr/bin/env bash
# Vertical-slice demonstration (BP §13). Requires a running Anvil (make anvil-up).
# Uses a fresh audit log under ./data/ so repeated runs stay legible.
set -euo pipefail
cd "$(dirname "$0")/.."

export CIPHERLAYER_RPC_URL="${CIPHERLAYER_RPC_URL:-http://127.0.0.1:8545}"
export CIPHERLAYER_AUDIT_LOG="${CIPHERLAYER_AUDIT_LOG:-./data/demo-audit-log.jsonl}"

mkdir -p data
rm -f "$CIPHERLAYER_AUDIT_LOG"

cargo run -q -p cipherlayer-cli -- demo

echo
echo "Audit log kept at: $CIPHERLAYER_AUDIT_LOG"
echo "Verify any time:   CIPHERLAYER_AUDIT_LOG=$CIPHERLAYER_AUDIT_LOG cargo run -q -p cipherlayer-cli -- audit verify"
