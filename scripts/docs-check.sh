#!/usr/bin/env bash
# Verify the required documentation set exists (prompt §9), that relative
# markdown links in README.md resolve, that ADR status/date lines and matrix
# status values are well-formed, and that the matrix header date is current.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=0
require() {
  if [ ! -f "$1" ]; then echo "MISSING doc: $1"; missing=1; fi
}

require README.md
require CLAUDE.md
require AGENTS.md
require CONTRIBUTING.md
require SECURITY.md
require LICENSE
require docs/architecture/system-overview.md
require docs/architecture/trust-boundaries.md
require docs/architecture/data-flow.md
require docs/architecture/signing-state-machine.md
require docs/architecture/browser-wallet-protocol.md
require docs/threat-model/threat-model.md
require docs/threat-model/abuse-cases.md
require docs/requirements/requirements-matrix.md
require docs/requirements/ambiguities-and-conflicts.md
require docs/security/security-claims-register.md
require docs/security/prototype-limitations.md
require docs/legal/legal-and-regulatory-issues.md
require docs/roadmap/implementation-roadmap.md
require docs/testing/test-strategy.md
require docs/source/CipherLayer_Web3_Stack_Unified_Scope_v1_0.md
require docs/source/Cipherlayer_Web3_Browser_Full_Project_Scope_v0.1.md
for n in 001 002 003 004 005 006 007 008 009 010; do
  ls docs/adr/ADR-${n}-*.md >/dev/null 2>&1 || { echo "MISSING ADR-${n}"; missing=1; }
done

# Relative links in README.md must resolve.
grep -o '](\([^)#]*\))' README.md | sed 's/](\(.*\))/\1/' | while read -r link; do
  case "$link" in
    http*|mailto*) continue ;;
    # Cross-repo sibling references (../browser/, ../scam-guard/) resolve on
    # the operator's machine but not in an isolated CI checkout of one repo —
    # they are intentionally external, not in-repo links.
    ../*) continue ;;
    *) [ -e "$link" ] || echo "BROKEN link in README.md: $link" ;;
  esac
done | tee /tmp/cipherlayer-docs-links.txt
if [ -s /tmp/cipherlayer-docs-links.txt ]; then missing=1; fi

# --- Versioned-document rules (replace hand-maintained headers) ------------
# 1. ADR status: first word from the allowed set, plus a **Date:** line.
for f in docs/adr/ADR-*.md; do
  head12=$(sed -n '1,12p' "$f")
  status=$(printf '%s\n' "$head12" | sed -n 's/^\*\*Status:\*\* *\([A-Za-z]*\).*/\1/p' | head -1)
  case "$status" in
    Proposed|Accepted|Superseded|Deprecated|Rejected) ;;
    *) echo "ADR status missing or not in {Proposed,Accepted,Superseded,Deprecated,Rejected}: $f"; missing=1 ;;
  esac
  printf '%s\n' "$head12" | grep -Eq '\*\*Date:\*\* *[0-9]{4}-[0-9]{2}-[0-9]{2}' \
    || { echo "ADR has no '**Date:** YYYY-MM-DD' line: $f"; missing=1; }
done

# 2. Requirements matrix: every row's status starts with a legend value, row
#    IDs are unique, and the header version/date line is present.
matrix=docs/requirements/requirements-matrix.md
bad=$(grep -E '^\| CL-[A-Z]+-[0-9]+ ' "$matrix" \
  | awk -F'|' '{ id=$2; st=$7; gsub(/^ +| +$/,"",id); gsub(/^ +| +$/,"",st);
      split(st, w, /[ ;(,]/);
      if (w[1] !~ /^(done|partial|doc|open|deferred)$/) print id ": status \"" st "\"" }')
if [ -n "$bad" ]; then
  echo "Matrix rows with a status outside {done,partial,doc,open,deferred}:"; echo "$bad"; missing=1
fi
dups=$(grep -oE '^\| CL-[A-Z]+-[0-9]+ ' "$matrix" | sort | uniq -d)
if [ -n "$dups" ]; then echo "Duplicate matrix IDs: $dups"; missing=1; fi
hdr=$(grep -m1 -E '^\*\*Version:\*\* *[0-9]+\.[0-9]+' "$matrix" || true)
if [ -z "$hdr" ]; then
  echo "Matrix header lacks '**Version:** N.N · **Dates:** ...'"; missing=1
else
  # 3. The newest date in the header must not be older than the last change to
  #    the file: git commit date when clean, today when modified. Skipped on
  #    shallow clones (CI), where every file looks last-touched at HEAD.
  hdr_date=$(printf '%s\n' "$hdr" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort | tail -1)
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ] || ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "docs-check: shallow clone, matrix header date check skipped"
  elif [ -n "$(git status --porcelain -- "$matrix")" ]; then
    if [ -z "$hdr_date" ] || [ "$hdr_date" \< "$(date +%F)" ]; then
      echo "Matrix is modified but its header date (${hdr_date:-none}) is not today ($(date +%F))."; missing=1
    fi
  else
    last=$(git log -1 --format=%cs -- "$matrix")
    if [ -n "$last" ] && { [ -z "$hdr_date" ] || [ "$hdr_date" \< "$last" ]; }; then
      echo "Matrix header date (${hdr_date:-none}) is older than its last commit ($last): update Version/Dates."; missing=1
    fi
  fi
fi

if [ "$missing" -ne 0 ]; then
  echo "docs-check FAILED." >&2
  exit 1
fi
echo "docs-check passed: required documents present, README links resolve."
