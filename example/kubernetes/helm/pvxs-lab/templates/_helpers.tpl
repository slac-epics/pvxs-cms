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

{{/*
EPICS_PVA_AUTH_ISSUER env sourced from the issuer-ids ConfigMap, so authnstd/authnkrb
target the department's own PVACMS via its CERT:CREATE:<issuer> PV. Pass the ConfigMap
key ("LAB_ISSUER" or "ML_ISSUER") as the argument via a dict: {"ctx": ., "key": "LAB_ISSUER"}.
*/}}
{{- define "pvxs-lab.issuerEnv" -}}
- name: EPICS_PVA_AUTH_ISSUER
  valueFrom:
    configMapKeyRef:
      name: {{ include "pvxs-lab.fullname" .ctx }}-issuer-ids
      key: {{ .key }}
{{- end -}}

{{/*
Issuer as a file at /etc/epics/issuer, so interactive login shells (su - <user>,
which reset the environment) recover EPICS_PVA_AUTH_ISSUER via /etc/profile.d/epics-issuer.sh
in the lab_base image. Two parts, both taking {"ctx": ., "key": "LAB_ISSUER"|"ML_ISSUER"}:
  issuerVolume - the ConfigMap volume, placed under `volumes:`
  issuerMount  - the volumeMount, placed under a container's `volumeMounts:`
*/}}
{{- define "pvxs-lab.issuerVolume" -}}
- name: issuer-id
  configMap:
    name: {{ include "pvxs-lab.fullname" .ctx }}-issuer-ids
    items:
      - key: {{ .key }}
        path: issuer
{{- end -}}

{{- define "pvxs-lab.issuerMount" -}}
- name: issuer-id
  mountPath: /etc/epics/issuer
  subPath: issuer
  readOnly: true
{{- end -}}
