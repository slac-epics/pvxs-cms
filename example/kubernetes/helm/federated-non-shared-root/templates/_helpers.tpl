{{- define "lab.image" -}}
{{- $name := index .Values.images .role -}}
{{- if contains "/" $name -}}{{ $name }}{{- else -}}
{{ .Values.dockerRegistry }}/{{ .Values.dockerUsername }}/{{ $name }}:{{ .Values.imageTag }}
{{- end -}}
{{- end -}}

{{/* Every name that is addressed, in one place. */}}
{{- define "lab.labPvacms"   -}}pvxs-lab-pvacms{{- end -}}
{{- define "lab.mlPvacms"    -}}pvxs-lab-ml-pvacms{{- end -}}
{{- define "lab.testioc"     -}}pvxs-lab-testioc{{- end -}}
{{- define "lab.tstioc"      -}}pvxs-lab-tstioc{{- end -}}
{{- define "lab.mlIoc"       -}}pvxs-lab-ml-ioc{{- end -}}
{{- define "lab.labGateway"  -}}pvxs-lab-gateway{{- end -}}
{{- define "lab.mlGateway"   -}}pvxs-lab-ml-gateway{{- end -}}
{{- define "lab.facility"    -}}facility{{- end -}}

{{/*
THE DIFFERENCE: a department in podman finds its own IOCs by broadcast and is given no address
list at all. There is no broadcast domain across pods, so each department names its own. The
department's OWN gateway is deliberately absent from both lists, which is the thing podman
achieves by having the gateway not answer on that segment.
*/}}
{{- define "lab.labZoneEnv" -}}
- name: EPICS_PVA_AUTO_ADDR_LIST
  value: "NO"
- name: EPICS_PVA_ADDR_LIST
  value: "{{ include "lab.labPvacms" . }} {{ include "lab.testioc" . }} {{ include "lab.tstioc" . }}"
{{- end -}}

{{- define "lab.mlZoneEnv" -}}
- name: EPICS_PVA_AUTO_ADDR_LIST
  value: "NO"
- name: EPICS_PVA_ADDR_LIST
  value: "{{ include "lab.mlPvacms" . }} {{ include "lab.mlIoc" . }}"
{{- end -}}

{{/* The issuer identifiers, minted before anything starts and mounted as files because a
     login shell resets the environment. */}}
{{- define "lab.issuerEnv" -}}
- name: LAB_ISSUER
  valueFrom: {configMapKeyRef: {name: lab-issuer-ids, key: LAB_ISSUER}}
- name: ML_ISSUER
  valueFrom: {configMapKeyRef: {name: lab-issuer-ids, key: ML_ISSUER}}
- name: LAB_ISSUER_SKID
  valueFrom: {configMapKeyRef: {name: lab-issuer-ids, key: LAB_ISSUER_SKID}}
- name: ML_ISSUER_SKID
  valueFrom: {configMapKeyRef: {name: lab-issuer-ids, key: ML_ISSUER_SKID}}
{{- end -}}

{{- define "lab.scriptsVolume" -}}
- name: scripts
  configMap: {name: lab-scripts, defaultMode: 0755}
{{- end -}}

{{- define "lab.scriptsMount" -}}
- {name: scripts, mountPath: /usr/local/bin/start-pvacms, subPath: start-pvacms.sh}
- {name: scripts, mountPath: /usr/local/bin/start-ioc, subPath: start-ioc.sh}
- {name: scripts, mountPath: /usr/local/bin/start-gateway, subPath: start-gateway.sh}
- {name: scripts, mountPath: /usr/local/bin/start-shell, subPath: start-shell.sh}
{{- end -}}
