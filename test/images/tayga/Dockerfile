# Userspace NAT64 gateway (Tayga) for containerlab. entrypoint.sh does the
# runtime wiring; README.md documents the env vars it needs.
#
# The base is pinned right here — Renovate's Dockerfile manager bumps this FROM
# line directly. buildx resolves it per-platform, so this builds amd64 and arm64.
FROM debian:13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tayga iptables iproute2 iputils-ping procps \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
