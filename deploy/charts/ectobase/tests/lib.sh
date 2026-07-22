#!/usr/bin/env bash
# Shared helpers for the ectobase chart golden tests. Source this file.
# NOTE: intentionally does NOT `set -e`/`set -u` — this file is sourced by test
# scripts (e.g. tests/render.sh) that rely on running ALL checks and accumulating
# failures; a leaked errexit would abort them on the first non-zero command.

# Resolve paths robustly regardless of the caller's CWD or how BASH_SOURCE is spelled
# (a relative dirname was CWD-fragile). Prefer git top-level; fall back to the fixed
# structural offset (tests/ -> ectobase -> charts -> deploy -> repo).
_self_dir="$(dirname "${BASH_SOURCE[0]}")"
REPO="$(git -C "$_self_dir" rev-parse --show-toplevel 2>/dev/null || (cd "$_self_dir/../../../.." && pwd))"
CHART="$REPO/deploy/charts/ectobase"
unset _self_dir
export REPO CHART

# normalize: strip helm "# Source:" lines, leading "---"/blank lines, per-line trailing
# whitespace, and trailing blank lines. For SINGLE-document, content-level diffs.
normalize() {
  grep -v '^# Source: ' \
    | awk 'BEGIN{s=0} { if (s==0 && ($0=="---" || $0=="")) next; s=1; print }' \
    | sed -e 's/[[:space:]]*$//' \
    | awk '{ l[NR]=$0 } END { last=NR; while (last>0 && l[last]=="") last--; for (i=1;i<=last;i++) print l[i] }'
}

# doc_hashes: split a YAML stream into documents (on lines that are exactly "---"),
# strip helm "# Source:" lines, normalize each document (per-line trailing-ws strip;
# drop leading/trailing blank lines), and emit a SORTED sha256 per document.
#
# Helm renders resources sorted by Kind, so a multi-document template's concatenation
# order differs from the source file even when every resource is byte-identical. Hashing
# per document and sorting gives an ORDER-INDEPENDENT set comparison of the resources.
doc_hashes() {
  grep -v '^# Source: ' \
  | awk 'BEGIN{buf=""}
         /^---[[:space:]]*$/ { sub(/[ \t\n]+$/,"",buf); if (buf!="") printf "%s\0", buf; buf=""; next }
         { line=$0; sub(/[[:space:]]+$/,"",line); if (line=="" && buf=="") next; buf=buf line "\n" }
         END { sub(/[ \t\n]+$/,"",buf); if (buf!="") printf "%s\0", buf }' \
  | while IFS= read -r -d '' doc; do printf '%s' "$doc" | sha256sum | cut -d' ' -f1; done \
  | sort
}

# render_show_only <template-rel-path> <values-file>
# <values-file> is resolved relative to $CHART if it is not an absolute path.
render_show_only() {
  local values="$2"
  [[ "$values" != /* ]] && values="$CHART/$values"
  helm template ectobase "$CHART" --namespace ectobase-system -f "$values" --show-only "$1"
}

# assert_docs_equal <template-rel-path> <values-file> <source-manifest>
# Order-independent per-document comparison of a rendered template against a source
# manifest. <source-manifest> is resolved relative to $REPO if not absolute. Prints the
# hash diff (empty on success) and returns diff's exit status.
assert_docs_equal() {
  local tpl="$1" values="$2" src="$3"
  [[ "$src" != /* ]] && src="$REPO/$src"
  diff <(render_show_only "$tpl" "$values" | doc_hashes) <(doc_hashes < "$src")
}
