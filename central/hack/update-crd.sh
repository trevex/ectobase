#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
controller-gen crd paths=./apis/platform/v1alpha1/... output:crd:artifacts:config=./config/crd
