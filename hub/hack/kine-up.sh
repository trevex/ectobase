#!/usr/bin/env bash
# Copyright 2026 ectobase contributors
# SPDX-License-Identifier: Apache-2.0
#
# Bring up kine (etcd-v3 shim) backed by Postgres, for the aggregated
# apiserver durability proof (kine/Postgres as the ONLY storage, no etcd).
# Idempotent: tears down any prior instances first.
set -euo pipefail

KINE_IMAGE="${KINE_IMAGE:-rancher/kine:v0.13.0}"
PG_IMAGE="${PG_IMAGE:-postgres:16}"

docker rm -f hub-pg hub-kine >/dev/null 2>&1 || true

docker run -d --name hub-pg -e POSTGRES_PASSWORD=kine -e POSTGRES_DB=kine -p 5432:5432 "$PG_IMAGE" >/dev/null
# wait for postgres
for i in $(seq 1 30); do docker exec hub-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done

docker run -d --name hub-kine --network host "$KINE_IMAGE" \
  --endpoint "postgres://postgres:kine@127.0.0.1:5432/kine?sslmode=disable" --listen-address 127.0.0.1:2379 >/dev/null
sleep 3
echo "kine on http://127.0.0.1:2379 (Postgres-backed, image=$KINE_IMAGE)"
