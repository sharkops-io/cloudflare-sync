{{- define "cloudflare-sync.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cloudflare-sync.fullname" -}}
{{- if contains (include "cloudflare-sync.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "cloudflare-sync.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "cloudflare-sync.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "cloudflare-sync.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "cloudflare-sync.selector" -}}
app.kubernetes.io/name: {{ include "cloudflare-sync.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The token Secret the reconciler writes, or "" when it writes none. */}}
{{- define "cloudflare-sync.tokenSecret" -}}
{{- with (.Values.config | default dict).tunnel -}}{{- with .tokenSecret -}}{{- .name -}}{{- end -}}{{- end -}}
{{- end -}}

{{- define "cloudflare-sync.tokenSecretNamespace" -}}
{{- $ns := .Release.Namespace -}}
{{- with (.Values.config | default dict).tunnel -}}{{- with .tokenSecret -}}{{- with .namespace -}}{{- $ns = . -}}{{- end -}}{{- end -}}{{- end -}}
{{- $ns -}}
{{- end -}}

{{- define "cloudflare-sync.validate" -}}
{{- if not .Values.apiToken.existingSecret -}}
{{- fail "apiToken.existingSecret is required: a Secret holding the Cloudflare API token" -}}
{{- end -}}
{{- if not .Values.config.accountId -}}
{{- fail "config.accountId is required" -}}
{{- end -}}
{{- if and .Values.cloudflared.enabled (not (include "cloudflare-sync.tokenSecret" .)) -}}
{{- fail "cloudflared.enabled needs config.tunnel.tokenSecret.name: cloudflared runs from the token the reconciler writes there" -}}
{{- end -}}
{{- if and .Values.cloudflared.enabled (ne (include "cloudflare-sync.tokenSecretNamespace" .) .Release.Namespace) -}}
{{- fail "cloudflared.enabled needs config.tunnel.tokenSecret in this release's namespace" -}}
{{- end -}}
{{- end -}}

{{/* The reconciler pod, shared by the CronJob and the on-deploy hook Job. */}}
{{- define "cloudflare-sync.podSpec" -}}
serviceAccountName: {{ include "cloudflare-sync.fullname" . }}
automountServiceAccountToken: {{ ne (include "cloudflare-sync.tokenSecret" .) "" }}
restartPolicy: Never
securityContext:
  {{- toYaml .Values.podSecurityContext | nindent 2 }}
containers:
  - name: cloudflare-sync
    image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    args: ["--config", "/config/config.json"]
    env:
      - name: CLOUDFLARE_API_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.apiToken.existingSecret }}
            key: {{ .Values.apiToken.key }}
      - name: DRY_RUN
        value: {{ ternary "1" "0" .Values.dryRun | quote }}
      - name: VALIDATE
        value: {{ ternary "1" "0" .Values.validate | quote }}
    securityContext:
      {{- toYaml .Values.securityContext | nindent 6 }}
    resources:
      {{- toYaml .Values.resources | nindent 6 }}
    volumeMounts:
      - name: config
        mountPath: /config
        readOnly: true
volumes:
  - name: config
    configMap:
      name: {{ include "cloudflare-sync.fullname" . }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
