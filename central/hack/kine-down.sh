#!/usr/bin/env bash
# Copyright 2026 ectobase contributors
# SPDX-License-Identifier: Apache-2.0
#
# Tear down the kine + Postgres containers started by kine-up.sh.
docker rm -f central-kine central-pg 2>/dev/null || true
