#!/usr/bin/env bash
# Verify documented prerequisites. Fails loudly; installs nothing.
set -euo pipefail

ok=1
need() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '  ok       %-7s %s\n' "$1" "$($1 --version 2>/dev/null | head -1)"
  else
    printf '  MISSING  %-7s %s\n' "$1" "$2"
    ok=0
  fi
}

echo "CipherLayer Wallet prerequisites:"
need cargo "install Rust via https://rustup.rs (stable >= 1.85)"
need rustc "install Rust via https://rustup.rs"
need anvil "install Foundry via https://getfoundry.sh"
need forge "install Foundry via https://getfoundry.sh"
need cast  "install Foundry via https://getfoundry.sh"
need git   "install Xcode command-line tools or git"

if [ "$ok" -ne 1 ]; then
  echo "Missing prerequisites — install them and re-run 'make bootstrap'." >&2
  exit 1
fi
echo "All prerequisites present."
