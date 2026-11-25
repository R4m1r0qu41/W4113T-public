#!/usr/bin/env bash
# Observer-side verification (read-only, safe to automate/CI — carries zero
# spend authority). Independently confirms a tx hash produced by the
# originator-side harness against a public Sepolia RPC, and writes a
# verified evidence artifact next to the raw one, mirroring Arrow's
# `lifecycle run` + `artifact hash` pair.
#
# Usage: ./verify-artifact.sh <tx_hash> [rpc_url]
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root (tools/metamask-lifecycle-harness -> wallet)

tx_hash="${1:?usage: verify-artifact.sh <tx_hash> [rpc_url]}"
rpc="${2:-${CIPHERLAYER_SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}}"
out_dir="docs/test/evidence"
mkdir -p "$out_dir"

if [[ ! "$tx_hash" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
  echo "Not a well-formed tx hash: $tx_hash" >&2
  exit 1
fi

echo "Querying ${rpc} for receipt of ${tx_hash}..."
receipt="$(curl -s -X POST "$rpc" \
  -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"${tx_hash}\"]}")"

result="$(echo "$receipt" | jq -c '.result')"
if [[ "$result" == "null" || -z "$result" ]]; then
  echo "No receipt yet (still pending, or wrong network). Raw response:" >&2
  echo "$receipt" >&2
  exit 1
fi

status_hex="$(echo "$result" | jq -r '.status')"
block_hex="$(echo "$result" | jq -r '.blockNumber')"
from_addr="$(echo "$result" | jq -r '.from')"
to_addr="$(echo "$result" | jq -r '.to')"
status="reverted"; [[ "$status_hex" == "0x1" ]] && status="success"
block_dec=$(( block_hex ))

chain_id="$(curl -s -X POST "$rpc" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' | jq -r '.result')"
chain_dec=$(( chain_id ))
if [[ "$chain_dec" != "11155111" ]]; then
  echo "REFUSED: RPC reports chain id ${chain_dec}, expected Sepolia (11155111). Not writing an artifact." >&2
  exit 1
fi

out_file="${out_dir}/metamask-sepolia-lifecycle-${tx_hash:2:12}.json"
jq -n \
  --arg schema "cipherlayer-metamask-lifecycle.v1" \
  --arg tx "$tx_hash" \
  --arg from "$from_addr" \
  --arg to "$to_addr" \
  --arg status "$status" \
  --arg rpc "$rpc" \
  --argjson chain_id "$chain_dec" \
  --argjson block "$block_dec" \
  --arg verified_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schema: $schema, network: "sepolia", chain_id: $chain_id, tx_hash: $tx,
    from: $from, to: $to, status: $status, block_number: $block,
    rpc_used: $rpc, verified_at: $verified_at, role: "observer"}' \
  > "$out_file"

echo "Verified. Artifact written: ${out_file}"
cat "$out_file"
echo
echo "Hash of artifact (for the RFC-style 'artifact hash' step):"
shasum -a 256 "$out_file"
