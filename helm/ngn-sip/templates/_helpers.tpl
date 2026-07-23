{{/*
Common helpers for the ngn-sip chart.
Cross-service DNS deliberately uses the bare Compose alias as the Service name
(clickhouse, keycloak, ollama, shuffle-backend, kamcmd-relay, ...) so that the
in-cluster URLs baked into images/configs (http://clickhouse:8123, keycloak:8080,
http://ollama:11434, ...) resolve unchanged inside the release namespace.
*/}}

{{- define "ngn-sip.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Chart label value, e.g. ngn-sip-0.1.0 */}}
{{- define "ngn-sip.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every object. Call with the component name:
  {{- include "ngn-sip.labels" (dict "root" . "component" "clickhouse") | nindent 4 }}
*/}}
{{- define "ngn-sip.labels" -}}
helm.sh/chart: {{ include "ngn-sip.chart" .root }}
app.kubernetes.io/name: {{ include "ngn-sip.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: ngn-sip
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Selector labels — the stable subset used by Service selectors and Deployment/
StatefulSet matchLabels. Call with the component name (see ngn-sip.labels).
*/}}
{{- define "ngn-sip.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ngn-sip.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Image pull policy default */}}
{{- define "ngn-sip.pullPolicy" -}}
{{- default "IfNotPresent" .Values.global.imagePullPolicy -}}
{{- end -}}

{{/*
StorageClass value for volumeClaimTemplates / PVCs.
Emits nothing when global.storageClass is "" so the cluster default is used;
on k3s set it to "local-path".
*/}}
{{- define "ngn-sip.storageClass" -}}
{{- if .Values.global.storageClass -}}
storageClassName: {{ .Values.global.storageClass }}
{{- end -}}
{{- end -}}
