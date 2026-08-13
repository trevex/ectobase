{{- define "ectobase-pool.labels" -}}
app.kubernetes.io/part-of: ectobase
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "ectobase-pool.name" -}}ectobase-pool{{- end -}}

{{/*
Default pod resource requests (scheduling hints + Burstable QoS). Requests only — no limits, so
the datapath's conntrack growth is never OOM-killed and no busy-poll worker is CPU-throttled.
*/}}
{{- define "ectobase-pool.resources" -}}
requests:
  cpu: 50m
  memory: 64Mi
{{- end -}}
