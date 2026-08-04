{{/*
Expand the name of the chart.
*/}}
{{- define "krevopilot-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "krevopilot-agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label.
*/}}
{{- define "krevopilot-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "krevopilot-agent.labels" -}}
helm.sh/chart: {{ include "krevopilot-agent.chart" . }}
app.kubernetes.io/name: {{ include "krevopilot-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: agent
app.kubernetes.io/part-of: kreaterevopilot
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "krevopilot-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "krevopilot-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "krevopilot-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "krevopilot-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Secret name.
*/}}
{{- define "krevopilot-agent.secretName" -}}
{{- default (include "krevopilot-agent.fullname" .) .Values.agent.existingSecret -}}
{{- end -}}

{{/*
Boolean value with a default.

Sprig's `default` treats false as empty, so `default true .flag` can never return false and a
user turning a true-defaulted flag off is silently ignored. This checks for the key instead, so
an explicit false is honoured.

Usage: include "krevopilot-agent.bool" (list <dict> "<key>" <default>)
*/}}
{{- define "krevopilot-agent.bool" -}}
{{- $dict := default dict (index . 0) -}}
{{- $key := index . 1 -}}
{{- $fallback := index . 2 -}}
{{- if hasKey $dict $key -}}
{{- if index $dict $key }}true{{ else }}false{{ end -}}
{{- else -}}
{{- if $fallback }}true{{ else }}false{{ end -}}
{{- end -}}
{{- end -}}

