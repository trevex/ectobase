#!/usr/bin/env bash
# Shared helpers for the ectobase chart golden tests. Source this file.
set -euo pipefail
CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$CHART/../../.." && pwd)"
export CHART REPO

# Strip helm's "# Source:" lines, leading "---"/blank lines, and trailing whitespace,
# so a --show-only render can be diffed against the raw source manifest.
normalize() {
  grep -v '^# Source: ' \
    | awk 'BEGIN{s=0} { if (s==0 && ($0=="---" || $0=="")) next; s=1; print }' \
    | sed -e 's/[[:space:]]*$//'
}

# render_show_only <template-rel-path> <values-file>
render_show_only() {
  helm template ectobase "$CHART" --namespace ectobase-system -f "$2" --show-only "$1"
}
