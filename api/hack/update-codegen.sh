#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$SCRIPT_DIR/.."

(cd "$PROJECT_DIR" && go mod download k8s.io/code-generator)
CODEGEN_PKG=$(cd "$PROJECT_DIR" && go list -m -f '{{.Dir}}' k8s.io/code-generator)
# shellcheck disable=SC1091
source "${CODEGEN_PKG}/kube_codegen.sh"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_DIR}/boilerplate.go.txt" \
    "${PROJECT_DIR}"
