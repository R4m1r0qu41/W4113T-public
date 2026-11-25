#!/usr/bin/env bash
# Tier-0 offline invariant checks (CipherLayer review loop, family guide §7).
# Deterministic, no network, no model: every check here either holds
# mechanically or the codebase regressed. Folded into `make ci`; also called
# standalone by the root family-review.sh orchestrator.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
ok()  { echo "  OK   $1"; }
bad() { echo "  FAIL $1"; fail=1; }

echo "== wallet family-invariants =="

# 1. No runtime/secret files tracked in git.
tracked_data="$(git ls-files | grep -E '^data/|(^|/)\.env$' || true)"
if [ -z "$tracked_data" ]; then
  ok "no runtime/.env files tracked (data/, .env)"
else
  bad "runtime files tracked in git: $tracked_data"
fi

# 2. No non-Anvil private-key-shaped literal outside the vault crate /
# .env.example / tests (ADR-005: only the 10 public Anvil dev keys may exist
# in code; this heuristically flags anything that LOOKS like a real one).
hit="$(git grep -nIE '(private_?key|secret)[^=]{0,20}[:=][[:space:]]*"?0x[0-9a-fA-F]{64}' -- . \
  ':!crates/cipherlayer-vault/**' ':!.env.example' ':!**/tests/**' 2>/dev/null || true)"
if [ -z "$hit" ]; then
  ok "no key-shaped literal outside the vault crate / .env.example / tests"
else
  bad "possible key literal outside allowed paths:"
  echo "$hit"
fi

# 3. Vault has exactly one public constructor (no bypass constructor).
ctor_count="$(awk '/^impl Vault \{/,/^\}/' crates/cipherlayer-vault/src/lib.rs | grep -c 'pub fn.*-> Self')"
if [ "$ctor_count" = "1" ]; then
  ok "Vault has exactly one constructor"
else
  bad "Vault has $ctor_count constructors (expected 1) — a bypass constructor may have been added"
fi

# 4. Vault Debug output redacts key material.
if grep -q '"<redacted>"' crates/cipherlayer-vault/src/lib.rs; then
  ok "Vault Debug impl redacts key material"
else
  bad "Vault Debug impl no longer redacts key material"
fi

# 5. Every pinned wire schema is deny-by-default at the top level.
schema_fail=0
for f in schemas/*.v1.json; do
  ap="$(jq -r '.additionalProperties' "$f" 2>/dev/null)"
  if [ "$ap" != "false" ]; then
    bad "schema $f is not additionalProperties:false at top level"
    schema_fail=1
  fi
done
[ "$schema_fail" = "0" ] && ok "all schemas/*.v1.json are additionalProperties:false"

# 6. No unsafe Rust anywhere in the workspace.
unsafe_hit="$(find crates -name '*.rs' -path '*/src/*' -exec grep -lE '\bunsafe\s*(\{|fn|impl|trait)' {} + 2>/dev/null || true)"
if [ -z "$unsafe_hit" ]; then
  ok "no unsafe Rust in the workspace"
else
  bad "unsafe Rust found in: $unsafe_hit"
fi

if [ "$fail" = "0" ]; then
  echo "wallet family-invariants: PASS"
else
  echo "wallet family-invariants: FAIL" >&2
fi
exit "$fail"
