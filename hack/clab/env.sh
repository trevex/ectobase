# shellcheck shell=bash
# Central clab-fabric constants — the SINGLE source of truth for the topology + scenario, sourced by
# hack/clab-up.sh, hack/multicluster-e2e.sh, hack/clab/cilium-up.sh. Grep found these duplicated
# across the scripts + hack/clab/ipv6-fabric.clab.yml. All overridable via the environment.
export CLAB_FABRIC_REFLECTOR6="${CLAB_FABRIC_REFLECTOR6:-fd00:db8:0:1::1}"   # k01 CP fabric loopback (reflector + apiserver)
export CLAB_REFLECTOR_PORT="${CLAB_REFLECTOR_PORT:-1338}"
export CLAB_DATAPLANE_PORT="${CLAB_DATAPLANE_PORT:-1337}"
export CLAB_VNI="${CLAB_VNI:-100}"
export CLAB_OVERLAY_IP_A="${CLAB_OVERLAY_IP_A:-10.0.0.1}"
export CLAB_OVERLAY_IP_C="${CLAB_OVERLAY_IP_C:-10.0.0.3}"
export CLAB_IMAGE_FLOWPLANE="${CLAB_IMAGE_FLOWPLANE:-ghcr.io/trevex/ectobase/flowplane:dev}"
export CLAB_IMAGE_NETPLANE="${CLAB_IMAGE_NETPLANE:-ghcr.io/trevex/ectobase/netplane:dev}"
export CLAB_IMAGE_KINDNODE="${CLAB_IMAGE_KINDNODE:-ghcr.io/trevex/ectobase/kind-node-fabric:dev}"
export CILIUM_VERSION="${CILIUM_VERSION:-1.20.0-rc.0}"
export CLAB_KIND_CENTRAL="${CLAB_KIND_CENTRAL:-k01}"
export CLAB_KIND_COMPUTE="${CLAB_KIND_COMPUTE:-k02}"
export CLAB_NODE_A="${CLAB_NODE_A:-k01-control-plane}"
export CLAB_NODE_C="${CLAB_NODE_C:-k02-control-plane}"

# PATH-robust root escalation. containerlab, sysctl, iptables, and the host bpffs sweep need root,
# but docker/kind/kubectl/helm run as the invoking user (docker-group + user kubeconfig). So the
# harness runs as the USER and self-sudos ONLY the privileged bits (mirrors bpf-cleanup.sh). On
# NixOS the real setuid sudo is /run/wrappers/bin/sudo; a PATH-shadowed bare `sudo` can break, so
# resolve it explicitly. Empty when already root. Use as: ${CLAB_SUDO} containerlab deploy ...
if [ "$(id -u)" -eq 0 ]; then
  export CLAB_SUDO=""
elif [ -x /run/wrappers/bin/sudo ]; then
  export CLAB_SUDO=/run/wrappers/bin/sudo
else
  export CLAB_SUDO=sudo
fi
