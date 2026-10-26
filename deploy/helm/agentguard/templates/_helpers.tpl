{{- define "agentguard.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "agentguard.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "agentguard.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}

{{- define "agentguard.labels" -}}
app.kubernetes.io/name: {{ include "agentguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "agentguard.env" -}}
- { name: AGENTGUARD_ENV, value: production }
- { name: AGENTGUARD_PUBLIC_URL, value: {{ .Values.publicUrl | quote }} }
- { name: AGENTGUARD_DATABASE_URL, valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: database-url } } }
- { name: AGENTGUARD_REDIS_URL, valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: redis-url } } }
- { name: AGENTGUARD_SECRET_KEY, valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: secret-key } } }
- { name: AGENTGUARD_SERVICE_TOKEN, valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: service-token } } }
- { name: AGENTGUARD_API_KEY, valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: gateway-api-key, optional: true } } }
- { name: AGENTGUARD_MODEL_DIR, value: /models/injection-classifier-v1 }
{{- range $k, $v := .Values.env }}
- { name: {{ $k }}, value: {{ $v | quote }} }
{{- end }}
{{- end -}}

{{/* Common pod spec pieces. Args: dict "root" . "name" component "port" port "args" list */}}
{{- define "agentguard.container" -}}
- name: {{ .name }}
  image: {{ include "agentguard.image" .root }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  args: {{ toJson .args }}
  env:
    {{- include "agentguard.env" .root | nindent 4 }}
    - { name: AGENTGUARD_PORT, value: {{ .port | quote }} }
    - { name: AGENTGUARD_HOST, value: "0.0.0.0" }
  ports: [{ name: http, containerPort: {{ .port }} }]
  readinessProbe: { httpGet: { path: /healthz, port: http }, periodSeconds: 10 }
  livenessProbe: { httpGet: { path: /healthz, port: http }, periodSeconds: 20, failureThreshold: 6 }
  securityContext: {{ toJson .root.Values.securityContext }}
  resources: {{ toJson .resources }}
  volumeMounts:
    - { name: tmp, mountPath: /tmp }
    - { name: data, mountPath: /data }
    - { name: config, mountPath: /config, readOnly: true }
    {{- if .root.Values.model.volume }}
    - { name: model, mountPath: /models, readOnly: true }
    {{- end }}
{{- end -}}

{{- define "agentguard.volumes" -}}
- { name: tmp, emptyDir: {} }
- { name: data, emptyDir: {} }
- name: config
  configMap: { name: {{ include "agentguard.fullname" . }}-gateway }
{{- if .Values.model.volume }}
- name: model
  {{- toYaml .Values.model.volume | nindent 2 }}
{{- end }}
{{- end -}}
