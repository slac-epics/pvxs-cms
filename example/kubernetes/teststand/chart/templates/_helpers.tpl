{{/*
Every object is named and labelled for its release, so the two variants can sit in one
namespace at once without adopting each other's objects or, worse, each Service selecting both
servers and spreading one monitor across two different builds of pvxs.
*/}}
{{- define "teststand.serverService" -}}{{ .Release.Name }}-server{{- end -}}
{{- define "teststand.monitorName" -}}{{ .Release.Name }}-monitor{{- end -}}
{{- define "teststand.scriptsConfig" -}}{{ .Release.Name }}-scripts{{- end -}}
{{- define "teststand.supervisorConfig" -}}{{ .Release.Name }}-supervisor{{- end -}}
{{- define "teststand.databasesConfig" -}}{{ .Release.Name }}-databases{{- end -}}
{{- define "teststand.acfConfig" -}}{{ .Release.Name }}-acf{{- end -}}

{{/* Selector labels. Both halves matter: the role and which release it belongs to. */}}
{{- define "teststand.serverSelector" -}}
app: teststand-server
release: {{ .Release.Name }}
{{- end -}}

{{- define "teststand.monitorSelector" -}}
app: teststand-monitor
release: {{ .Release.Name }}
{{- end -}}

{{/* One place that builds an image reference, so there is no second way to spell one. */}}
{{- define "teststand.image" -}}
{{- $name := index .Values.images .role -}}
{{ .Values.dockerRegistry }}/{{ .Values.dockerUsername }}/{{ $name }}:{{ .Values.imageTag }}
{{- end -}}

{{/*
A pod network has no broadcast domain, so the client is given the server by name rather than
left to find it. Its own release's server, never the other one's.
*/}}
{{- define "teststand.zoneEnv" -}}
- name: EPICS_PVA_AUTO_ADDR_LIST
  value: "NO"
- name: EPICS_PVA_ADDR_LIST
  value: {{ include "teststand.serverService" . | quote }}
{{- end -}}

{{- define "teststand.scriptsVolume" -}}
- name: scripts
  configMap:
    name: {{ include "teststand.scriptsConfig" . }}
    defaultMode: 0755
{{- end -}}
