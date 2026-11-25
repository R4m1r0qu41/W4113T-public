#!/usr/bin/env bash
# Serve the MetaMask lifecycle harness page on localhost only.
# MetaMask's injected provider is unavailable on file:// pages in most
# configurations, so this is a plain static server bound to 127.0.0.1 —
# never 0.0.0.0, this page must not be reachable from the network.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${CIPHERLAYER_MM_HARNESS_PORT:-8931}"

echo "Serving MetaMask lifecycle harness at http://127.0.0.1:${PORT}/index.html"
echo "Ctrl-C to stop. Originator-side: keep this tab focused; every send"
echo "requires the approval phrase here AND a confirmation inside MetaMask."
python3 -m http.server "$PORT" --bind 127.0.0.1
