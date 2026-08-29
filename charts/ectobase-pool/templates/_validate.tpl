{{- define "ectobase-pool.validate" -}}
{{- if .Values.tier1Failover.enabled -}}
  {{- if and .Values.tier1Failover.watchdog.enabled (not .Values.tier1Failover.watchdog.device) -}}
    {{- fail "invalid values: tier1Failover.watchdog.enabled=true requires tier1Failover.watchdog.device (e.g. /dev/watchdog). Set tier1Failover.watchdog.device or set watchdog.enabled: false." -}}
  {{- end -}}
{{- end -}}
{{- if not .Values.broker.clusterName -}}
  {{- fail "invalid values: broker.clusterName is required (this cluster's ClusterPool name, e.g. k02). Set broker.clusterName." -}}
{{- end -}}
{{- end -}}
