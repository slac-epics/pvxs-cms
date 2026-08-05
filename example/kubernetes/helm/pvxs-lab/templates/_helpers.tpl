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
{{- define "pvxs-lab.certAdminLabService" -}}
{{ include "pvxs-lab.fullname" . }}-cert-admin-lab
{{- end -}}
{{- define "pvxs-lab.certAdminMlService" -}}
{{ include "pvxs-lab.fullname" . }}-cert-admin-ml
{{- end -}}
{{- define "pvxs-lab.certAdminInternetService" -}}
{{ include "pvxs-lab.fullname" . }}-cert-admin-internet
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

{{/*
Both departments' issuer ids, for a pod that carries a user per department and therefore cannot
have one pod-level EPICS_PVA_AUTH_ISSUER: the right answer differs by user, so each user's shell
profile selects one. Three parts, all taking {"ctx": .}:
  issuersEnv    - LAB_ISSUER and ML_ISSUER as environment variables, under `env:`
  issuersVolume - the ConfigMap volume, placed under `volumes:`
  issuersMount  - the volumeMount, placed under a container's `volumeMounts:`
The files are what a login shell reads, via /etc/profile.d/epics-issuers.sh in the lab_base image,
because su - <user> resets the environment.
*/}}
{{- define "pvxs-lab.issuersEnv" -}}
- name: LAB_ISSUER
  valueFrom:
    configMapKeyRef:
      name: {{ include "pvxs-lab.fullname" .ctx }}-issuer-ids
      key: LAB_ISSUER
- name: ML_ISSUER
  valueFrom:
    configMapKeyRef:
      name: {{ include "pvxs-lab.fullname" .ctx }}-issuer-ids
      key: ML_ISSUER
{{- end -}}

{{- define "pvxs-lab.issuersVolume" -}}
- name: issuer-ids
  configMap:
    name: {{ include "pvxs-lab.fullname" .ctx }}-issuer-ids
{{- end -}}

{{- define "pvxs-lab.issuersMount" -}}
- name: issuer-ids
  mountPath: /etc/epics/issuers
  readOnly: true
{{- end -}}

{{/*
Health probes for a certificate manager container.

supervisord is the container's process 1 and stays up whatever happens to the
programs under it, so a certificate manager that has died still reports the pod
as Running and Ready. That is not a theoretical concern: it hid a crash-looping
certificate manager during debugging, and the Service kept sending requests to
a pod that could not answer them.

The check is a TCP connect to the plain PVAccess port, which the certificate
manager listens on whenever it is serving. That is stronger than asking
supervisord whether the process exists, because it fails for a process that is
alive but no longer listening.

  startup   - generous, so a slow first start (which mints an administrator
              keychain) is not mistaken for a failure
  readiness - tight, so the pod leaves the Service and shows as not ready
              quickly, which is the visibility that was missing
  liveness  - deliberately slow: supervisord already restarts the program, and
              a container restart here also takes down everything else in the
              pod, Kerberos included. It is the backstop for a program
              supervisord believes is running but which no longer serves.

Takes {"ctx": ., } and reads .Values.pvacmsProbes.
*/}}
{{- define "pvxs-lab.pvacmsProbes" -}}
{{- $p := .ctx.Values.pvacmsProbes -}}
{{- if $p.enabled }}
startupProbe:
  tcpSocket:
    port: {{ .ctx.Values.ports.pvaTcp }}
  periodSeconds: {{ $p.startup.periodSeconds }}
  failureThreshold: {{ $p.startup.failureThreshold }}
readinessProbe:
  tcpSocket:
    port: {{ .ctx.Values.ports.pvaTcp }}
  periodSeconds: {{ $p.readiness.periodSeconds }}
  failureThreshold: {{ $p.readiness.failureThreshold }}
livenessProbe:
  tcpSocket:
    port: {{ .ctx.Values.ports.pvaTcp }}
  periodSeconds: {{ $p.liveness.periodSeconds }}
  failureThreshold: {{ $p.liveness.failureThreshold }}
{{- end }}
{{- end -}}
