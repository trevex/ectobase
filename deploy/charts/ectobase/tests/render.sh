#!/usr/bin/env bash
# Golden + validation suite for the ectobase chart. Exit non-zero on any failure.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib.sh"
cd "$REPO"

fail=0
ok()   { echo "PASS: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

# 1) eBPF render == the current kustomize manifests (order-independent per-resource;
#    helm sorts resources by Kind, so multi-doc templates differ only in order).
declare -A MAP=(
  [namespace]=namespace
  [rbac]=rbac
  [agent-kubeconfig]=agent-kubeconfig
  [kubevirt-binding]=kubevirt-binding
  [reflector]=reflector
  [controller]=controller
  [agent]=agent
  [cni]=cni
  [dataplane-ebpf]=flowplane
)
for tpl in "${!MAP[@]}"; do
  src="config/deploy/${MAP[$tpl]}.yaml"
  if assert_docs_equal "templates/$tpl.yaml" "$DIR/values/ebpf-clab.yaml" "$src" >/dev/null; then
    ok "ebpf render $tpl == $src"
  else
    bad "ebpf render $tpl != $src"
  fi
done

# 2) CRDs: 8 with installCRDs, 0 without.
n=$(render_show_only templates/crds.yaml "$DIR/values/ebpf-clab.yaml" | grep -c "kind: CustomResourceDefinition")
[ "$n" = "8" ] && ok "installCRDs renders 8 CRDs" || bad "installCRDs rendered $n CRDs (want 8)"

# 3) DPDK renders under dpdk, not under ebpf.
render_show_only templates/dataplane-dpdk.yaml "$DIR/values/dpdk-clab.yaml" | grep -q "flowplane-dpdk serve" \
  && ok "dpdk datapath renders under dataplane=dpdk" || bad "dpdk datapath did not render"
render_show_only templates/dataplane-ebpf.yaml "$DIR/values/dpdk-clab.yaml" >/dev/null 2>&1 \
  && bad "ebpf datapath rendered under dataplane=dpdk" || ok "ebpf datapath absent under dataplane=dpdk"

# 4) Negative validation cases must FAIL helm template.
neg() {
  local desc="$1"; shift
  if helm template ectobase deploy/charts/ectobase --namespace ectobase-system "$@" >/dev/null 2>&1; then
    bad "expected rejection: $desc"
  else
    ok "rejected: $desc"
  fi
}
neg "unknown key"                  --set bogusKey=1
neg "bad dataplane enum"           --set dataplane=bogus
neg "bad env enum"                 --set env=bogus
neg "blueGreen without dpdk"       --set blueGreen.enabled=true
neg "dpdk+clab wide lcores"        --set dataplane=dpdk,env=clab,dpdk.lcores=0-3
neg "dpdk+hw no hugepages"         --set dataplane=dpdk,env=hw,dpdk.hugepages=false
neg "dpdk+hw no vfio"              --set dataplane=dpdk,env=hw,dpdk.hugepages=true

# 4b) ebpf on hw: renders valid, and omits the clab-only FLOWPLANE_SKB_MODE env.
helm template ectobase deploy/charts/ectobase --namespace ectobase-system -f "$DIR/values/ebpf-hw.yaml" >/dev/null 2>&1 \
  && ok "ebpf-hw renders" || bad "ebpf-hw failed to render"
render_show_only templates/dataplane-ebpf.yaml "$DIR/values/ebpf-hw.yaml" | grep -q "FLOWPLANE_SKB_MODE" \
  && bad "ebpf-hw should omit FLOWPLANE_SKB_MODE" || ok "ebpf-hw omits FLOWPLANE_SKB_MODE"

# 5) helm lint clean.
helm lint deploy/charts/ectobase >/dev/null 2>&1 && ok "helm lint" || bad "helm lint"

exit $fail
