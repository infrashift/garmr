{{/*
Common helpers for the Garmr chart.
*/}}

{{- define "garmr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "garmr.fullname" -}}
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

{{- define "garmr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "garmr.labels" -}}
helm.sh/chart: {{ include "garmr.chart" . }}
app.kubernetes.io/name: {{ include "garmr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "garmr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "garmr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "garmr.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "garmr.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Port name: "https" when Garmr terminates TLS, so meshes and ingress
controllers that infer protocol from the port name get it right.
*/}}
{{- define "garmr.portName" -}}
{{- if .Values.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end -}}

{{/*
Fail fast on TLS settings that cannot work.
*/}}
{{- define "garmr.validateTLS" -}}
{{- if .Values.tls.enabled -}}
{{- if not .Values.tls.secretName -}}
{{- fail "tls.enabled requires tls.secretName (a Secret with tls.crt and tls.key)" -}}
{{- end -}}
{{- if .Values.mesh.consulConnect.enabled -}}
{{- fail "tls.enabled and mesh.consulConnect.enabled are mutually exclusive: the Connect sidecar terminates mTLS and forwards plain HTTP to Garmr" -}}
{{- end -}}
{{- else if or .Values.tls.secretName .Values.tls.clientCASecretName -}}
{{- /* Certificates without tls.enabled would render a plaintext pod that looks configured for (m)TLS: refuse rather than serve the API in the clear. */ -}}
{{- fail "tls.secretName / tls.clientCASecretName are set but tls.enabled is false: set tls.enabled=true, or remove them to serve plain HTTP" -}}
{{- end -}}
{{- end -}}

{{- define "garmr.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
