{{/*
Expand the name of the chart.
*/}}
{{- define "warmor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "warmor.fullname" -}}
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
{{- define "warmor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "warmor.labels" -}}
helm.sh/chart: {{ include "warmor.chart" . }}
{{ include "warmor.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "warmor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warmor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "warmor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "warmor.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the priority class to use
*/}}
{{- define "warmor.priorityClassName" -}}
{{- if .Values.priorityClass.name }}
{{- .Values.priorityClass.name }}
{{- else }}
{{- include "warmor.fullname" . }}
{{- end }}
{{- end }}

{{- define "warmor.image" -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (.image.tag | default .version) -}}
{{- end -}}
{{- end -}}

{{- define "warmor.validate" -}}
{{- if hasKey .Values.policy "yaml" -}}
{{- fail "policy.yaml is ignored by this chart: compile a binary and use policy.existingConfigMap (or make deploy-audit DRY_RUN=true)" -}}
{{- end -}}
{{- if .Values.webhook.enabled -}}
{{- fail "webhook.enabled is unsupported: no admission webhook handler exists" -}}
{{- end -}}
{{- if and .Values.daemon.auditMode (or .Values.daemon.lsmEnforce .Values.daemon.defaultDeny) -}}
{{- fail "auditMode cannot be combined with lsmEnforce/defaultDeny; select one posture" -}}
{{- end -}}
{{- if and (not .Values.daemon.auditMode) (not .Values.daemon.confirmNodeWidePolicy) -}}
{{- fail "enforcement requires daemon.confirmNodeWidePolicy=true; auto scope includes Warmor/system pods, not selectors" -}}
{{- end -}}
{{- if and .Values.daemon.lsmEnforce (not .Values.daemon.requireLSM) -}}
{{- fail "lsmEnforce requires requireLSM=true to prevent silent degradation" -}}
{{- end -}}
{{- if and .Values.daemon.defaultDeny (not .Values.daemon.lsmEnforce) -}}
{{- fail "defaultDeny requires lsmEnforce=true" -}}
{{- end -}}
{{- if and .Values.controller.enabled .Values.policy.existingConfigMap -}}
{{- fail "controller.enabled and policy.existingConfigMap are mutually exclusive" -}}
{{- end -}}
{{- if .Values.controller.nodeReceipts.enabled -}}
{{- if not .Values.controller.enabled -}}{{- fail "nodeReceipts requires controller.enabled" -}}{{- end -}}
{{- if or (empty .Values.controller.nodeReceipts.audience) (empty .Values.controller.nodeReceipts.tlsSecretName) (empty .Values.controller.nodeReceipts.caConfigMapName) (empty .Values.controller.nodeReceipts.requiredNodes) -}}
{{- fail "nodeReceipts requires dedicated audience, provisioned TLS secret, CA ConfigMap and explicit complete requiredNodes roster" -}}
{{- end -}}
{{- end -}}
{{- if or (ne (index .Values.nodeSelector "kubernetes.io/os") "linux") (ne (index .Values.nodeSelector "kubernetes.io/arch") "amd64") -}}
{{- fail "nodeSelector must retain kubernetes.io/os=linux and kubernetes.io/arch=amd64 (current images)" -}}
{{- end -}}
{{- if and .Values.controller.watchAllNamespaces (not .Values.daemon.confirmNodeWidePolicy) -}}
{{- fail "watchAllNamespaces requires daemon.confirmNodeWidePolicy=true (admin-only single-tenant mode)" -}}
{{- end -}}
{{- end -}}
