#!/usr/bin/env bash
# Shared helpers for the ectobase chart golden tests. Source this file.
# NOTE: intentionally does NOT `set -e`/`set -u` — this file is sourced by test
# scripts (e.g. tests/render.sh) that rely on running ALL checks and accumulating
# failures; a leaked errexit would abort them on the first non-zero command.
CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$CHART/../../.." && pwd)"
export CHART REPO

# Strip helm's "# Source:" lines, leading "---"/blank lines, trailing whitespace,
# and trailing blank lines, so a --show-only render can be diffed against the raw
# source manifest.
normalize() {
  grep -v '^# Source: ' \
    | awk 'BEGIN{s=0} { if (s==0 && ($0=="---" || $0=="")) next; s=1; print }' \
    | sed -e 's/[[:space:]]*$//' \
    | awk '{ lines[NR]=$0 } END { last=NR; while (last>0 && lines[last]=="") last--; for (i=1;i<=last;i++) print lines[i] }'
}

# render_show_only <template-rel-path> <values-file>
# <values-file> is resolved relative to $CHART if it is not an absolute path.
render_show_only() {
  local values="$2"
  [[ "$values" != /* ]] && values="$CHART/$values"
  helm template ectobase "$CHART" --namespace ectobase-system -f "$values" --show-only "$1"
}
