{{- define "ectobase.validate" -}}
{{- if and (eq .Values.dataplane "dpdk") (eq .Values.env "hw") -}}
  {{- if not .Values.dpdk.hugepages -}}
    {{- fail "invalid values: dpdk.hugepages must be true when dataplane=dpdk and env=hw (a DPDK HW node needs hugepages to boot). Set dpdk.hugepages: true." -}}
  {{- end -}}
  {{- if not .Values.dpdk.vfioDevices -}}
    {{- fail "invalid values: dpdk.vfioDevices must list at least one device when dataplane=dpdk and env=hw. Set dpdk.vfioDevices: [{name: <resource>, count: <n>}]." -}}
  {{- end -}}
{{- end -}}
{{- if and (eq .Values.dataplane "dpdk") (eq .Values.env "clab") -}}
  {{- if ne .Values.dpdk.lcores "0" -}}
    {{- fail "invalid values: dpdk.lcores must be \"0\" when dataplane=dpdk and env=clab (a single lcore, to avoid pinning busy poll-mode cores per node on the shared clab host). Set dpdk.lcores: \"0\"." -}}
  {{- end -}}
{{- end -}}
{{- if .Values.blueGreen.enabled -}}
  {{- if ne .Values.dataplane "dpdk" -}}
    {{- fail "invalid values: blueGreen.enabled=true requires dataplane=dpdk (blue-green is DPDK-only; eBPF hot-swaps in place). Set dataplane: dpdk or blueGreen.enabled: false." -}}
  {{- end -}}
{{- end -}}
{{- if .Values.tier1Failover.enabled -}}
  {{- if and .Values.tier1Failover.watchdog.enabled (not .Values.tier1Failover.watchdog.device) -}}
    {{- fail "invalid values: tier1Failover.watchdog.enabled=true requires tier1Failover.watchdog.device (e.g. /dev/watchdog). Set tier1Failover.watchdog.device or set watchdog.enabled: false." -}}
  {{- end -}}
{{- end -}}
{{- if .Values.broker.enabled -}}
  {{- if not .Values.broker.clusterName -}}
    {{- fail "invalid values: broker.enabled=true requires broker.clusterName (this cluster's ClusterPool name, e.g. k02). Set broker.clusterName or set broker.enabled: false." -}}
  {{- end -}}
{{- end -}}
{{- end -}}
