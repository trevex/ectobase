#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-xdp-e2e}"
kind get clusters | grep -qx "$NAME" || kind create cluster --name "$NAME"
