{{- define "ectobase-pool.labels" -}}
app.kubernetes.io/part-of: ectobase
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "ectobase-pool.name" -}}ectobase-pool{{- end -}}
