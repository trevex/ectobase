# Custom kind node image that makes the node's kubelet Node InternalIP its
# BGP-fabric /64 address, established before kubelet (see fabric-preboot.sh).
#
# Spike scope: identity only (dummy0 + node-ip). FRR/BGP is added in a later
# layer once the node-ip-survives-restart property is proven.
ARG BASE=kindest/node:v1.35.0
FROM ${BASE}

# FRR makes the node its OWN BGP speaker (replacing the shared-netns sidecar): it
# announces the node's underlay /64 over unnumbered eBGP to the ToR(s). Same FRR
# config the sidecar used, now baked in and started by fabric-preboot.
RUN apt-get update \
 && apt-get install -y --no-install-recommends frr \
 && rm -rf /var/lib/apt/lists/*

COPY fabric-preboot.sh /usr/local/bin/fabric-preboot.sh
COPY fabric-preboot.service /etc/systemd/system/fabric-preboot.service
RUN chmod +x /usr/local/bin/fabric-preboot.sh \
 && sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons \
 && systemctl enable fabric-preboot.service
