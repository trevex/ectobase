# Custom kind node image that makes the node's kubelet Node InternalIP its
# BGP-fabric /64 address, established before kubelet (see fabric-preboot.sh).
#
# Spike scope: identity only (dummy0 + node-ip). FRR/BGP is added in a later
# layer once the node-ip-survives-restart property is proven.
ARG BASE=kindest/node:v1.35.0
FROM ${BASE}

COPY fabric-preboot.sh /usr/local/bin/fabric-preboot.sh
COPY fabric-preboot.service /etc/systemd/system/fabric-preboot.service
RUN chmod +x /usr/local/bin/fabric-preboot.sh \
 && systemctl enable fabric-preboot.service
