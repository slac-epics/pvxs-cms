{{/* One place that builds an image reference, so there is no second way to spell one. */}}
{{- define "lab.image" -}}
{{- $name := index .Values.images .role -}}
{{ .Values.dockerRegistry }}/{{ .Values.dockerUsername }}/{{ $name }}:{{ .Values.imageTag }}
{{- end -}}

{{/* Service names. Everything that addresses anything goes through these. */}}
{{- define "lab.pvacmsService"  -}}pvxs-lab-pvacms{{- end -}}
{{- define "lab.testiocService" -}}pvxs-lab-testioc{{- end -}}
{{- define "lab.tstiocService"  -}}pvxs-lab-tstioc{{- end -}}
{{- define "lab.facilityService" -}}facility{{- end -}}

{{/*
The laboratory zone's addressing.

THE DIFFERENCE: podman leaves both lists unset here and turns automatic discovery on, so a
workstation finds its IOCs by broadcast. There is no broadcast domain across pods, so the
three places that live in the laboratory are given the IOCs and the certificate manager by
name. The gateway is deliberately absent from this list, which is the same thing the podman
laboratory achieves by having the gateway not answer.
*/}}
{{- define "lab.zoneAddrList" -}}
{{ include "lab.pvacmsService" . }} {{ include "lab.testiocService" . }} {{ include "lab.tstiocService" . }}
{{- end -}}

{{- define "lab.zoneEnv" -}}
- name: EPICS_PVA_AUTO_ADDR_LIST
  value: "NO"
- name: EPICS_PVA_ADDR_LIST
  value: {{ include "lab.zoneAddrList" . | quote }}
{{- end -}}

{{/* The three scripts the podman topology bind-mounts, carried here in a ConfigMap. */}}
{{- define "lab.scriptsVolume" -}}
- name: scripts
  configMap:
    name: lab-scripts
    defaultMode: 0755
{{- end -}}

{{- define "lab.scriptsMount" -}}
- name: scripts
  mountPath: /usr/local/bin/start-pvacms
  subPath: start-pvacms.sh
- name: scripts
  mountPath: /usr/local/bin/start-ioc
  subPath: start-ioc.sh
- name: scripts
  mountPath: /usr/local/bin/start-gateway
  subPath: start-gateway.sh
- name: scripts
  mountPath: /usr/local/bin/start-shell
  subPath: start-shell.sh
{{- end -}}

{{/*
The issuer identifier.

It does not exist until the certificate manager has minted its authority, so the ConfigMap is
not there when the chart is installed and the mount is optional. Mounted rather than written
into the running container, because a pod is replaceable: `krestart <place> pod` and every
rollout produce a new filesystem, and an issuer id poked into the old one goes with it. That
is a difference from podman, where the container persists and writing into it is enough.
*/}}
{{- define "lab.issuerVolume" -}}
- name: issuer
  configMap:
    name: lab-issuer
    optional: true
{{- end -}}

{{- define "lab.issuerMount" -}}
- name: issuer
  mountPath: /etc/epics
{{- end -}}
