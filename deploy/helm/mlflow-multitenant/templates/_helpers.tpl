{{/*
Expand the name of the chart.
*/}}
{{- define "mlflow-multitenant.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mlflow-multitenant.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if not $name }}
{{ . | toYaml | fail }}
{{- end }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "mlflow-multitenant.keycloakJob.fullname" -}}
{{ include "mlflow-multitenant.fullname" . }}-configure-keycloak
{{- end -}}

{{- define "mlflow-multitenant.minioJob.fullname" -}}
{{ include "mlflow-multitenant.fullname" . }}-configure-minio
{{- end -}}


{{- define "mlflow-multitenant.tenant.fullname" -}}
{{ include "mlflow-multitenant.fullname" (index . 0) }}-{{ (index .  1).id }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mlflow-multitenant.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mlflow-multitenant.labels" -}}
helm.sh/chart: {{ include "mlflow-multitenant.chart" . }}
{{ include "mlflow-multitenant.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mlflow-multitenant.tenant.labels" -}}
{{ include "mlflow-multitenant.labels" (index . 0) }}
mlflow-multitenant.meln5674.github.com/tenant: {{ (index . 1).id }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mlflow-multitenant.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mlflow-multitenant.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{- define "mlflow-multitenant.tenant.selectorLabels" -}}
{{ include "mlflow-multitenant.selectorLabels" (index . 0) }}
mlflow-multitenant.meln5674.github.com/tenant: {{ (index . 1).id }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mlflow-multitenant.serviceAccountName" -}}
{{- if .Values.mlflow.values.serviceAccount.create }}
{{- default (include "mlflow-multitenant.fullname" .) .Values.mlflow.values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.mlflow.values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "mlflow-multitenant.keycloakJob.serviceAccountName" -}}
{{- if .Values.keycloakJob.serviceAccount.create }}
{{- default (include "mlflow-multitenant.keycloakJob.fullname" .) .Values.keycloakJob.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.keycloakJob.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "mlflow-multitenant.minioJob.serviceAccountName" -}}
{{- if .Values.minioJob.serviceAccount.create }}
{{- default (include "mlflow-multitenant.minioJob.fullname" .) .Values.minioJob.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.minioJob.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Templates for merging values and values templates for mlflow templates
*/}}
{{- define "mlflow-multitenant.mergeValuesAndTemplate" -}}
{{- $dot := index . 0 }}
{{- $values := index . 1 | default (dict) | deepCopy }}
{{- $template := index . 2 | default "" }}
{{- $templateValues := tpl $template $dot | fromYaml }}
{{- with $templateValues.Error }}
{{ fail . }}
{{- end }}
{{- with mergeOverwrite $values $templateValues }}
{{- . | toYaml }}
{{- end }}
{{- end -}}

{{- define "mlflow-multitenant.values" -}}
{{ include "mlflow-multitenant.mergeValuesAndTemplate" (list . .Values.mlflow.values .Values.mlflow.valuesTemplate) }}
{{- end }}

{{- define "mlflow-multitenant.tenantValues" -}}
{{- $dot := index . 0 }}
{{- $tenant := index . 1 }}
{{- $values := include "mlflow-multitenant.values" $dot | fromYaml }}
{{- with $values.Error }}
{{ fail . }}
{{- end }}
{{- $tenantValues := include "mlflow-multitenant.mergeValuesAndTemplate" (list $dot $tenant.values $tenant.valuesTemplate) | fromYaml }}
{{- with $tenantValues.Error }}
{{ fail . }}
{{- end }}
{{- mergeOverwrite $values $tenantValues | toYaml }}
{{- end }}

{{- define "mlflow-multitenant.externalURL" -}}
{{- $oauth2Proxy := index .Values "oauth2-proxy" -}}
https://{{ $oauth2Proxy.ingress.hostname }}
{{- end -}}
