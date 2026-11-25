# exports/ — published contract surface

Release artifacts siblings pin (consumer-side `imports/wallet/PIN.json` + read-only copies; Arrow/Tarquin convention per register AC-001).

| Bundle | Version | Contents |
|---|---|---|
| `browser-connect-v0.1/` | 0.1.0 | browser-wallet protocol doc (now describing protocol v0.4, ADR-019) + envelope, signing-request/response, dapp-permission, wallet-capability, **rpc-query** (new, v0.4) schemas + SHA256SUMS. The `v0.1` directory name is the export-channel identifier, not the protocol version — refreshed in place across ADR-013/014/019 as the live protocol advanced 0.1 → 0.3 → 0.4, per the frozen-copy-per-release convention below. |

Files are frozen copies of the working sources (`../schemas/`, `../docs/architecture/browser-wallet-protocol.md`) per release; consumers pin by commit + checksum.
