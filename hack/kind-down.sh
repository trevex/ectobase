#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-xdp-e2e}"
kind delete cluster --name "$NAME"
