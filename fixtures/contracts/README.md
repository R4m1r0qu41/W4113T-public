# Fixture contracts

Minimal Solidity contracts for the vertical-slice demo and integration tests. **Local development only** — never deploy these anywhere that matters.

- `src/TestToken.sol` — minimal ERC-20 (`CLT`), mints 1,000,000 tokens to the deployer.
- `src/TestSpender.sol` — sample spender with a `pull(token, from, amount)` that exercises `transferFrom`.

## Committed artifacts

`artifacts/*.json` are **committed, trimmed build artifacts** (creation bytecode + ABI) that the CLI demo and integration tests embed via `include_str!`. Committing them keeps `make demo` reproducible without requiring a solc download at demo time. The full `out/` and `cache/` directories stay untracked (`.gitignore`).

Rebuild procedure after editing a contract:

```bash
cd fixtures/contracts
forge build
python3 - <<'EOF'
import json
for name in ['TestToken', 'TestSpender']:
    with open(f'out/{name}.sol/{name}.json') as f:
        art = json.load(f)
    trimmed = {
        'contractName': name,
        'source': f'src/{name}.sol',
        'solc': '0.8.24',
        'note': 'Committed build artifact for the demo/tests. Rebuild: forge build, then this script (see README.md).',
        'bytecode': art['bytecode']['object'],
        'abi': art['abi'],
    }
    with open(f'artifacts/{name}.json', 'w') as f:
        json.dump(trimmed, f, indent=1)
EOF
```

Solc is pinned (`foundry.toml`: 0.8.24) so the committed bytecode is reproducible.
