{{/*
Expand the name of the chart.
*/}}
{{- define "ectobase-dispatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all objects in the chart.
*/}}
{{- define "ectobase-dispatch.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ectobase-dispatch
{{- end }}

{{/*
Default pod resource requests (scheduling hints + Burstable QoS). Requests only — no limits, so
nothing is throttled or OOM-killed on a lab node; set limits per your cluster if desired.
*/}}
{{- define "ectobase-dispatch.resources" -}}
requests:
  cpu: 50m
  memory: 64Mi
{{- end -}}
