#!/usr/bin/env zsh
# Load a Sepolia test key into the current shell for the CipherLayer external
# signer (CL-WAL-010, ADR-011). Adapted from Arrow's load-*-key.zsh.
#
#   source ./load-cipherlayer-test-key.zsh
#
# The key is pasted (never echoed), verified to derive to the expected
# address, exported for THIS SHELL ONLY as CIPHERLAYER_EXTERNAL_SIGNER_KEY,
# and the raw input is unset. Nothing is written to disk. Use a dedicated
# testnet account — never a key that also holds mainnet value.
#
# Set CIPHERLAYER_EXTERNAL_SIGNER_FROM to your test account before sourcing,
# or accept the default below (the account from the first lifecycle run).

expected="${CIPHERLAYER_EXTERNAL_SIGNER_FROM:-0x7cD33930465A2258B89A25B59A1ACd5aa033932E}"

if ! command -v cast >/dev/null 2>&1; then
  echo "cast is not available on PATH (install Foundry)." >&2
  return 1 2>/dev/null || exit 1
fi

echo -n "Paste Sepolia test private key for ${expected}, then press Enter: "
stty -echo
IFS= read -r raw_key
stty echo
echo

key="$(printf '%s' "$raw_key" | tr -d '[:space:]')"
key="${key#0x}"; key="${key#0X}"

if [[ ${#key} -ne 64 || ! "$key" =~ '^[0-9A-Fa-f]{64}$' ]]; then
  echo "Invalid private key (length/charset). The key was not printed." >&2
  unset raw_key key
  return 1 2>/dev/null || exit 1
fi

derived="$(cast wallet address "0x${key}")"
if [[ "${derived:l}" != "${expected:l}" ]]; then
  echo "MISMATCH: derived ${derived}, expected ${expected}. The key was not exported." >&2
  unset raw_key key derived
  return 1 2>/dev/null || exit 1
fi

export CIPHERLAYER_EXTERNAL_SIGNER_KEY="$key"
export CIPHERLAYER_EXTERNAL_SIGNER_FROM="$expected"
export CIPHERLAYER_SEPOLIA_RPC="${CIPHERLAYER_SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}"

unset raw_key key derived
echo "OK: CIPHERLAYER_EXTERNAL_SIGNER_KEY exported for this shell."
echo "  from: ${CIPHERLAYER_EXTERNAL_SIGNER_FROM}"
echo "  rpc:  ${CIPHERLAYER_SEPOLIA_RPC}"
echo "Unset with: unset CIPHERLAYER_EXTERNAL_SIGNER_KEY"
