{{/*
Expand the name of the chart.
*/}}
{{- define "mlflow-oidc-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mlflow-oidc-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mlflow-oidc-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mlflow-oidc-proxy.labels" -}}
helm.sh/chart: {{ include "mlflow-oidc-proxy.chart" . }}
{{ include "mlflow-oidc-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mlflow-oidc-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mlflow-oidc-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mlflow-oidc-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mlflow-oidc-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "mlflow-oidc-proxy.secretName" -}}
{{ .Values.credentials.existingSecret.name | default (include "mlflow-oidc-proxy.fullname" .) }}
{{- end -}}

{{- define "mlflow-oidc-proxy.configMapName" -}}
{{ .Values.config.existingConfigMap.name | default (include "mlflow-oidc-proxy.fullname" .) }}
{{- end -}}



{{- define "mlflow-oidc-proxy.robots" -}}
{{- $dot := . }}
{{- $robotMap := dict }}
{{- range $ix, $robot := .Values.config.yaml.robots.robots }}
    {{- $type := $robot.type | default "mtls" }}
    {{- if eq $type "mtls" }}
    {{- $certPath := $robot.certPath | default (printf "/var/run/secrets/robots/%s/tls.crt" $robot.name) }}
    {{- $robotMap = set $robotMap $robot.name (set (deepCopy $robot) "certPath" $certPath) }}
    {{- else if eq $type "token" }}
    {{- $secretTokenPath := $robot.certPath | default (printf "/var/run/secrets/robots/%s/token" $robot.name) }}
    {{- $robotMap = set $robotMap $robot.name (set (deepCopy $robot) "secretTokenPath" $secretTokenPath) }}
    {{- else }}
    {{- printf "Robot %d (%s) has unknown type %s" $ix $robot.name $type | fail }}
    {{- end }}
{{- end }}
{{- if .Values.config.yaml.robots.robotsTemplate }}
    {{- $robotsTplOutput := tpl .Values.config.yaml.robots.robotsTemplate $dot | fromYaml }}
    {{- with $robotsTplOutput.Error }}
        {{- fail . }}
    {{- end }}
    {{- $robotsTplOutput = $robotsTplOutput.robots }}
    {{- range $ix, $robot := $robotsTplOutput }}
        {{- $existingRobot := get $robotMap $robot.name | default dict }}
        {{- $mergedRobot := mergeOverwrite $existingRobot $robot }}
        {{- $type := $mergedRobot.type | default "mtls" }}
        {{- if eq $type "mtls" }}
        {{- $certPath := $mergedRobot.certPath | default (printf "/var/run/secrets/robots/%s/tls.crt" $robot.name) }}
        {{- $mergedRobot = set $mergedRobot "certPath" $certPath }}
        {{- else if eq $type "token" }}
        {{- $secretTokenPath := $mergedRobot.secretTokenPath | default (printf "/var/run/secrets/robots/%s/token" $robot.name) }}
        {{- $mergedRobot = set $mergedRobot "secretTokenPath" $secretTokenPath }}
        {{- end }}
        {{- $robotMap = set $robotMap $mergedRobot.name $mergedRobot }}
    {{- end }}
{{- end }}
{{- (dict "robots" (values $robotMap)) | toJson }}
{{- end }}
