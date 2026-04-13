{{- define "pvxs-lab.image" -}}
{{- $r := .Values.dockerRegistry | default "ghcr.io" -}}
{{- $u := .Values.dockerUsername | default "slac-epics" -}}
{{- $name := required "image name is required" .name -}}
{{- $tag := .tag | default "latest" -}}
{{- printf "%s/%s/%s:%s" $r $u $name $tag -}}
{{- end -}}
{{- define "pvxs-lab.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pvxs-lab.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "pvxs-lab.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "pvxs-lab.labels" -}}
app.kubernetes.io/name: {{ include "pvxs-lab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "pvxs-lab.idmService" -}}
{{ include "pvxs-lab.fullname" . }}-idm
{{- end -}}
{{- define "pvxs-lab.pvacmsService" -}}
{{ include "pvxs-lab.fullname" . }}-pvacms
{{- end -}}
{{- define "pvxs-lab.gatewayService" -}}
{{ include "pvxs-lab.fullname" . }}-gateway
{{- end -}}
{{- define "pvxs-lab.testiocService" -}}
{{ include "pvxs-lab.fullname" . }}-testioc
{{- end -}}
{{- define "pvxs-lab.tstiocService" -}}
{{ include "pvxs-lab.fullname" . }}-tstioc
{{- end -}}
{{- define "pvxs-lab.internetService" -}}
{{ include "pvxs-lab.fullname" . }}-internet
{{- end -}}
{{- define "pvxs-lab.itService" -}}
{{ include "pvxs-lab.fullname" . }}-it
{{- end -}}
{{- define "pvxs-lab.mlService" -}}
{{ include "pvxs-lab.fullname" . }}-ml
{{- end -}}
{{- define "pvxs-lab.mlIocService" -}}
{{ include "pvxs-lab.fullname" . }}-ml-ioc
{{- end -}}
{{- define "pvxs-lab.mlGatewayService" -}}
{{ include "pvxs-lab.fullname" . }}-ml-gateway
{{- end -}}
{{- define "pvxs-lab.csStudioLabService" -}}
{{ include "pvxs-lab.fullname" . }}-cs-studio-lab
{{- end -}}
{{- define "pvxs-lab.csStudioMlService" -}}
{{ include "pvxs-lab.fullname" . }}-cs-studio-ml
{{- end -}}
{{- define "pvxs-lab.csStudioInternetService" -}}
{{ include "pvxs-lab.fullname" . }}-cs-studio-internet
{{- end -}}
