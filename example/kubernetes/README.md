# Kubernetes Cluster with PVAccess Gateway Ingress

## Overview
A single-node Kubernetes cluster simulating **one laboratory** with two departments plus an
outside Internet zone, on one host. The lab's IT department mints a single facility Root
Certificate Authority and runs a separate departmental intermediate CA for each department; each
department runs its own standalone PVACMS (there is no PVACMS cluster). See **Federated CMS** below.

- **Zone 1: Lab Network (control-systems department)**
	- **idm**: Identity Management
		- ***kdc***: Kerberos Service (user: *idm*)
		- ***pvacms***: the Lab (control-systems) PVACMS — signs with the Controls intermediate CA;
		  external access (user: *idm*)
	- **testioc**: IOC — ***softIocPVX*** (user: *testioc*)
	- **tstioc**: IOC — ***softIocPVX*** (user: *tstioc*)
	- **lab**: General Lab Personnel — Control Room (*operator*), Office (*guest*)
	- **cs-studio-lab**: CS-Studio (Phoebus) via noVNC — same users as lab (*operator*, *guest*)
	- **gateway**: PVAccess Gateway — two servers: ml (:5075) + internet (:5275) (user: *gateway*).
	  Forwards the Lab department's `CERT:CREATE`/`CERT:STATUS` PVs to the Lab PVACMS.

- **Zone 2: ML Centre Network (machine-learning department)**
	- **ml**: General ML Personnel and IT Systems — Office (*mloperator*), ML Systems (*mlsystem*),
	  ***pvacms*** — the ML PVACMS, signs with the ML intermediate CA (user: *idm*)
	- **ml-ioc**: IOC — ***softIocPVX*** (user: *mlioc*)
	- **cs-studio-ml**: CS-Studio (Phoebus) via noVNC — same users as ml (*mloperator*, *mlsystem*)
	- **ml-gateway**: PVAccess Gateway — one server: internet (:5075) (user: *gateway*). Forwards the
	  ML department's `CERT:CREATE`/`CERT:STATUS` PVs to the ML PVACMS.

- **Zone 3: Internet**
	- **internet**: Home users — *operator*, *guest*
	- **cs-studio-internet**: CS-Studio (Phoebus) via noVNC — same users as internet (*operator*, *guest*)

There is no `it` node and no PVACMS cluster in this lab. Network policies enforce zone isolation;
gateways are the only path between zones.

## Network Policies

NetworkPolicy enforcement requires a CNI that supports it (Calico, Cilium, Antrea). The cluster
uses Calico. Policies are defined in `templates/networkpolicy.yaml`.

The strategy is **ingress-centric**: each service pod pins down who can reach it, and egress is left unrestricted except for the internet zone (which must be confined so internet clients can hit the gateways and the KDC — nothing else).

### Ingress policies

| Policy                 | Target pod(s)   | Allowed sources                                                              |   | Caveats                                                    |
|------------------------|-----------------|------------------------------------------------------------------------------|:--|------------------------------------------------------------|
| lab-pvacms-kdc-ingress | idm             | lab, cs-studio-lab, gateway, testioc, tstioc, internet, cs-studio-internet   |   | Egress on other side restricts internet and ml to only KDC |
| ml-pvacms-ingress      | ml              | ml, cs-studio-ml, ml-gateway, ml-ioc                                         |   |                                                            |
| lab-ioc-ingress        | testioc, tstioc | lab, cs-studio-lab, gateway                                                  |   |                                                            |
| ml-ioc-ingress         | ml-ioc          | ml, cs-studio-ml, ml-gateway                                                 |   |                                                            |
| lab-gateway-ingress    | gateway         | any pod NOT IN {lab, cs-studio-lab, idm, gateway, testioc, tstioc, ml-gateway} |   |                                                          |
| ml-gateway-ingress     | ml-gateway      | any pod NOT IN {ml, cs-studio-ml, ml-gateway, ml-ioc, gateway}               |   |                                                            |

Notes:
- `NotIn` excludes pods that have the `app` label with one of the listed values. Pods with no `app` label are also excluded (this is standard `NotIn` semantics); in this chart every pod carries an `app` label, so the rule behaves as written.
- Internet pods can reach `idm` on any port at the ingress layer, but `internet-egress` below clips them to KDC ports only — layered enforcement.
- The lab gateway reaches the Lab (idm) PVACMS (via `lab-pvacms-kdc-ingress`) and the ml-gateway reaches the ML PVACMS (via `ml-pvacms-ingress`) to forward each department's `CERT:*` PVs.

Pods without an ingress policy (accept all ingress): lab, cs-studio-lab, cs-studio-ml, internet, cs-studio-internet.

### Egress policies

| Policy          | Source pod(s)                | Allowed destinations                                                                          | Notes                     |
|-----------------|------------------------------|-----------------------------------------------------------------------------------------------|---------------------------|
| internet-egress | internet, cs-studio-internet | gateway, ml-gateway (any port); idm (UDP 88 / TCP 749 — Kerberos only); kube-dns (UDP/TCP 53) | Kerberos-only path to idm |

Pods without an egress policy (unrestricted egress): idm, gateway, ml-gateway, testioc, tstioc, ml, ml-ioc, lab, cs-studio-lab, cs-studio-ml.

## Topology

Lab gateway runs **two PVA servers** and ml gateway runs **one**, with separate pvlists, preventing duplicate PVs:

```text
Lab pods (lab, cs-studio-lab)
  ├── direct: pvacms(idm), testioc, tstioc    (ADDR_LIST)
  └── via ml-gateway:5075                      (NAME_SERVERS) → ml:*

ML pods (ml, cs-studio-ml)
  ├── direct: pvacms(ml), ml-ioc              (ADDR_LIST)
  └── via gateway:5075                        (NAME_SERVERS) → test:*, tst:*

Cross-department cert status (no cluster; each PVACMS answers only its own issuer):
  Lab client → ml IOC : CERT:STATUS:<ml>  via ml-gateway → ML pvacms
  ML  client → lab IOC: CERT:STATUS:<lab> via gateway    → Lab pvacms

Internet pods (internet, cs-studio-internet)
  ├── via gateway:5275: lab iocs, cert mgmt   (NAME_SERVERS) → test:*, tst:*, CERT:CREATE, CERT:STATUS
  └── via ml-gateway:5075: ml iocs            (NAME_SERVERS) → ml:*
```

### Gateway detail

| Gateway | Server     | Search Port | TLS Port | Pvlist                                                          | Consumers           |
|---------|------------|-------------|----------|-----------------------------------------------------------------|---------------------|
| Lab     | ml         | :5075       | :5076    | `test:.*`, `tst:.*`                                             | ML pods             |
| Lab     | internet   | :5275       | :5276    | `test:.*`, `tst:.*`, `CERT:CREATE:<lab>`, `CERT:STATUS:<lab>`   | Internet pods       |
| ML      | internet   | :5075       | :5076    | `ml:.*`, `CERT:CREATE:<ml>`, `CERT:STATUS:<ml>`                 | Lab & Internet pods |

`<lab>` / `<ml>` are the two departments' issuer ids (see **Federated CMS**). Both gateways fetch
**only** from their own zone's IOCs/services (no cross-connect clients).

### Federated CMS
The lab has one facility Root Certificate Authority, minted by "IT", that signs two departmental
**intermediate** CAs:

| Intermediate CA (CN)                | Used by (PVACMS) | Issues certs for | Issuer id     |
|-------------------------------------|------------------|------------------|---------------|
| `EPICS Controls Intermediate CA`    | `idm` (Lab)      | control-systems  | `<lab>` (hex) |
| `EPICS ML Intermediate CA`          | `ml` (ML)        | machine-learning | `<ml>` (hex)  |

Both intermediates chain to the one facility Root (`EPICS Root Certificate Authority`), which every
pod trusts, so a certificate issued by either department is trusted across the whole lab. There is
**no PVACMS cluster** — each department's PVACMS runs standalone and answers only for its own
issuer's certificates.

**Bootstrapping.** The certificates are minted before any pod starts by the `ca-keygen` pre-install
Job (which runs `gen_lab_certs`): it produces the Root (no status extension), the two intermediate
keychains (each cert + key + Root chain, with a `CERT`-prefixed status extension), and an
`issuer-ids` ConfigMap holding the two issuer ids. Each PVACMS points `EPICS_CERT_AUTH_TLS_KEYCHAIN`
at its own intermediate keychain (the Lab PVACMS at the Controls intermediate, the ML PVACMS at the
ML intermediate) and signs leaf certs with it. A PVACMS cannot mint its own intermediate, so they
are pre-minted and pushed in.

**Cross-department certificate status.** Because each PVACMS answers only its own issuer's
`CERT:STATUS` PVs, a secure cross-zone connection resolves the *foreign* certificate's status through
the peer gateway to the issuing PVACMS. Each gateway forwards `CERT:STATUS`/`CERT:CREATE` **keyed by
its department's issuer id** (the issuer id is substituted into the gateway pvlist at pod start from
the `issuer-ids` ConfigMap). Naming the issuer means each gateway claims only the requests it can
actually serve, so a client reaching both gateways from the Internet routes to the right one without
a wasted round-trip. Server-side certificate-status **stapling** is enabled by default (PVXS default;
nothing sets `no_stapling`), which lets a served IOC present its own signed status too.

**Targeting a department's CMS.** Each department's client/IOC pods set `EPICS_PVA_AUTH_ISSUER` (from
the `issuer-ids` ConfigMap) to their own department's issuer id, so `authnstd`/`authnkrb` request
`CERT:CREATE:<issuer>` and reach only that department's PVACMS without passing `--issuer`.

**Trust vs authorisation.** Trust is shared (whole-lab); authorisation is per department and applies
only to WRITE. IOC ACFs allow READ to anyone (including anonymous, any zone). For WRITE: guests may
write only their own zone's IOCs; operators may write both zones' IOCs. The lab-only `test:spec`
special PV is writable by operators only (guests may read it). Department confinement lives in ACF
WRITE authorisation and NetworkPolicy, not in the trust anchors — do not split the trust stores.

## Users

### Lab (Zone 1)
| Pod           | Users           |
|---------------|-----------------|
| idm           | idm, admin      |
| lab           | guest, operator |
| cs-studio-lab | guest, operator |
| it            | idm, admin      |
| gateway       | gateway         |
| testioc       | testioc         |
| tstioc        | tstioc          |

### ML Centre (Zone 2)
| Pod          | Users                |
|--------------|----------------------|
| ml           | mloperator, mlsystem |
| cs-studio-ml | mloperator, mlsystem |
| ml-gateway   | gateway              |
| ml-ioc       | mlioc                |

### Internet (Zone 3)
| Pod                | Users           |
|--------------------|-----------------|
| internet           | guest, operator |
| cs-studio-internet | guest, operator |

A valid administrator certificate keychain file is provided and configured for the admin user. The admin user can additionally use `kinit` to obtain a Kerberos ticket and then use `authnkrb` to get an X.509 certificate.

## Services
| Pod                | Services           |
|--------------------|--------------------|
| idm                | kdc, pvacms        |
| it                 | pvacms             |
| lab                | lab                |
| cs-studio-lab      | cs-studio-lab      |
| testioc            | testioc            |
| tstioc             | tstioc             |
| gateway            | gateway            |
| ml                 | pvacms             |
| ml-ioc             | mlioc              |
| ml-gateway         | ml-gateway         |
| cs-studio-ml       | cs-studio-ml       |
| internet           | internet           |
| cs-studio-internet | cs-studio-internet |

## Kerberos Authentication

The lab cluster includes a single Kerberos KDC (Key Distribution Center) running on the `idm` pod.
All pods — including those in the ML centre and internet zones — use this same KDC via the
`pvxs-lab-krb` ClusterIP service. The krb5.conf is injected at deploy time via a Helm ConfigMap
(overriding the image-baked default), so all pods resolve the KDC correctly.

> **Note on ML Kerberos access**: In a real deployment, the ML centre would have its own identity provider or a federated trust relationship. In this simulation, the direct Kerberos path from the `ml` pod to the `idm` KDC (allowed by network policy on UDP 88 / TCP 749) represents a secure tunnel between the ML facility and the lab's identity infrastructure. This is a pragmatic simplification for development and testing.

### Kerberos Realm
- **Realm**: EPICS.ORG
- **KDC Service**: pvxs-lab-krb (UDP 88, TCP 749)
- **NodePort**: 30049, 30088 (for external kinit)

### Users (Kerberos Principals)
| Principal                | Password | Zone           |
|--------------------------|----------|----------------|
| admin@EPICS.ORG          | secret   | Lab            |
| guest@EPICS.ORG          | secret   | Lab / Internet |
| operator@EPICS.ORG       | secret   | Lab / Internet |
| pvacms/cluster@EPICS.ORG | random   | Lab (service)  |
| remote@EPICS.ORG         | secret   | Lab            |
| testioc@EPICS.ORG        | secret   | Lab            |
| tstioc@EPICS.ORG         | secret   | Lab            |
| mloperator@EPICS.ORG     | secret   | ML Centre      |
| mlsystem@EPICS.ORG       | secret   | ML Centre      |

All users and services can use `authnkrb` to get an X.509 certificate:

```sh
kinit operator@EPICS.ORG
authnkrb
```

or for server/IOC usage:

```sh
kinit testioc@EPICS.ORG
authnkrb -u server
```

A keytab is provided and configured for the pvacms service.

## PVs available

All three pvacms instances share the same issuer_id (derived from the shared CA keychain).
The `????????` placeholders represent 8-character hex IDs generated at runtime.

### IDM, ML, and IT pvacms
- CERT:CREATE
- CERT:CREATE:????????
- CERT:ISSUER
- CERT:ISSUER:????????
- CERT:ROOT
- CERT:ROOT:????????
- CERT:STATUS:????????:*
- CERT:CLUSTER:CTRL:????????
- CERT:CLUSTER:CTRL:????????:????????
- CERT:CLUSTER:SYNC:????????:????????

### testioc
- test:aiExample
- test:arrayExample
- test:calcExample
- test:compressExample
- test:enumExample
- test:groupExampleAS
- test:groupExampleSave
- test:longExample
- test:spec &mdash; Only settable by operator and gateway
- test:stringExample
- test:structExample
- test:structExampleSave
- test:tableExample
- test:vectorExampleD1
- test:vectorExampleD2

### tstioc
- tst:Array
- tst:Array2
- tst:ArrayData
- tst:ArrayData_
- tst:ArraySize0_RBV
- tst:ArraySize1_RBV
- tst:ColorMode
- tst:ColorMode_
- tst:extra
- tst:extra:alias

### ml-ioc
- ml:aiExample
- ml:stringExample
- ml:longExample

# Helpers

```sh
source ./helpers.sh
```

## Build & deploy

- **gw_build_images** — Build Docker images for the cluster
```sh
gw_build_images [<target>] [<options>]

# target (omit to build all):
#   lab_tools, lab_base, lab, internet, testioc, tstioc, idm,
#   ml, ml-ioc, gateway, cs-studio

# options:
#   --no-cache  Do not use Docker cache
gw_build_images cs-studio --no-cache
```

- **gw_deploy** — Deploy (or redeploy) the cluster via Helm
```sh
gw_deploy [-r] [options]

# -r            Redeploy (delete, quiesce, recreate)
# --dry-run     Print rendered YAML without applying
# --set k=v     Override Helm values
gw_deploy -r
gw_deploy --set gateway.debug.enabled=true --dry-run
```

Notes:
- Changes under `example/kubernetes/helm/pvxs-lab/` only need `gw_deploy`.
- Changes under `example/kubernetes/docker/gateway/` require rebuilding the `gateway` image first, then `gw_deploy`.

- **gw_undeploy** — Tear down the cluster
```sh
gw_undeploy
```

## Login helpers

> **Administrators must wait for their keychain on a fresh install.**
> Approving, denying or revoking a certificate requires the administrator to
> present a certificate issued by that department's own certificate authority,
> over a secure transport. The administrator's keychain is copied from the
> certificate manager once it has bootstrapped, which takes up to two minutes on a
> fresh install. An administrator shell opened before the copy finishes now fails
> the decision outright rather than quietly succeeding over plain transport.
>
> To tell that it has happened, check the file exists in the administrator's home:
> ```sh
> kubectl -n pvxs-lab exec deploy/pvxs-lab-idm -c idm -- \
>     ls -l /home/admin/.config/pva/1.5/client.p12
> ```
> The copy step logs `admin.p12 copied to admin client cert` when it succeeds and
> warns if the certificate manager had not produced one within two minutes.
>
> **Upgrading a laboratory installed before the certificate database was
> persisted.** The database used to be written outside the persistent volume, so
> it was destroyed whenever the certificate manager restarted, and every
> certificate issued beforehand lost its status record. An administrator keychain
> kept from such an installation reports `UNKNOWN` and is refused. Clear it once
> and let the certificate manager mint a replacement:
> ```sh
> kubectl -n pvxs-lab exec deploy/pvxs-lab-idm -c idm -- \
>     rm -f /home/idm/.config/pva/1.5/admin.p12 \
>           /home/admin/.config/pva/1.5/client.p12
> kubectl -n pvxs-lab delete pod -l app=pvxs-lab-idm
> ```
> Check the replacement with `pvxcert -f ~/.config/pva/1.5/client.p12`, which
> should report `VALID`. A new installation does not need this.

- **login_to_lab** — Login as a lab user (selects the correct pod automatically)
```sh
login_to_lab <user>
# user: admin | guest | operator | gateway | testioc | tstioc | idm | it
login_to_lab operator
```

- **login_from_internet** — Login as an internet user
```sh
login_from_internet <user>
# user: guest | operator
login_from_internet guest
```

- **login_to_ml** — Login to ML centre pods
```sh
login_to_ml <user>
# user: mloperator | mlsystem | ml-gateway | ml-ioc
login_to_ml mloperator
```

- **login_to_cs_studio_in_lab** — Login to cs-studio-lab pod
```sh
login_to_cs_studio_in_lab <user>
# user: operator | guest
```

- **login_to_cs_studio_in_ml** — Login to cs-studio-ml pod
```sh
login_to_cs_studio_in_ml <user>
# user: mloperator | mlsystem
```

- **login_to_cs_studio_from_internet** — Login to cs-studio-internet pod
```sh
login_to_cs_studio_from_internet <user>
# user: operator | guest
```

- **go_in_to** — Root shell into any pod
```sh
go_in_to <container>
# container: idm | gateway | testioc | tstioc | lab | internet | it |
#            ml | ml-ioc | ml-gateway | cs-studio-lab | cs-studio-ml |
#            cs-studio-internet
go_in_to gateway
```

## CS-Studio (Phoebus) via browser

Each CS-Studio pod runs Phoebus inside Xvfb, exposed through noVNC. Port-forward to access via browser:

- **cs_studio_lab** — Forward cs-studio-lab noVNC to http://localhost:8080
- **cs_studio_ml** — Forward cs-studio-ml noVNC to http://localhost:8081
- **cs_studio_internet** — Forward cs-studio-internet noVNC to http://localhost:8082

```sh
cs_studio_lab       # then open http://localhost:8080
cs_studio_ml        # then open http://localhost:8081
cs_studio_internet  # then open http://localhost:8082
```

## File copy helpers

- **gw_cp** — Copy files from a container to the host
```sh
gw_cp <container> <user> <container_src> [host_dest]
# container: lab | idm | gateway | testioc | tstioc | internet | it |
#            ml | ml-ioc | ml-gateway
gw_cp lab operator '/home/operator/.config/pva/1.5/client.p12' ./client.p12
```

- **gw_cp_in** — Copy files from the host into a container
```sh
gw_cp_in <container> <user> <host_src> <container_dest>
gw_cp_in lab guest ~/Downloads/gateway.p12 '/home/guest/.config/pva/1.4/gateway.p12'
```

## Logging

- **gw_log** — Tail logs from any pod
```sh
gw_log <container>
# container: idm | gateway | testioc | tstioc | lab | internet | it |
#            ml | ml-ioc | ml-gateway | cs-studio-lab | cs-studio-ml |
#            cs-studio-internet
gw_log gateway
```

# How to

## Build and deploy the cluster

```sh
gw_build_images
gw_deploy
```

To redeploy from scratch:
```sh
gw_deploy -r
```

## Create a certificate for the IOC

IOC certificates must be created and activated **before** the gateway certificate,
so that when the gateway restarts it can connect to the upstream IOCs over TLS.

```sh
login_to_lab testioc
```
```sh
authnstd -u server
# Output: Keychain file created, Certificate identifier: <issuer_id>:<cert_id>
exit
```

Approve and restart:
```sh
login_to_lab admin
pvxcert --approve <issuer_id>:<cert_id>
exit

go_in_to testioc
supervisorctl restart testioc:
exit
```

Repeat for tstioc (and ml-ioc if desired).

## Create a certificate for the gateway

```sh
login_to_lab gateway
```
```console
gateway@pvxs-lab-gateway-...:~$
```
```sh
authnstd -u ioc
# Output: Keychain file created, Certificate identifier: <issuer_id>:<cert_id>
exit
```

Approve the certificate as admin:
```sh
login_to_lab admin
```
```sh
pvxcert --approve <issuer_id>:<cert_id>
# Output: Approve ==> CERT:STATUS:<id> ==> Completed Successfully
exit
```

Restart the gateway to pick up the cert:
```sh
go_in_to gateway
supervisorctl restart gateway
exit
```

## Create a certificate for the ML gateway

The `gateway` user shell inside `ml-gateway` is configured to talk directly to the ML-side PVACMS using the local upstream addrlist from `gateway.conf` (`pvxs-lab-ml pvxs-lab-ml-ioc`). It does not use the gateway's public PV list for `CERT:*` access.

```sh
login_to_ml ml-gateway
```
```console
gateway@pvxs-lab-ml-gateway-...:~$
```
```sh
authnstd -u ioc -n ml-gateway
# Output: Keychain file created, Certificate identifier: <issuer_id>:<cert_id>
exit
```

Approve the certificate as admin:
```sh
login_to_lab admin
```
```sh
pvxcert --approve <issuer_id>:<cert_id>
# Output: Approve ==> CERT:STATUS:<id> ==> Completed Successfully
exit
```

Restart the ML gateway to pick up the cert:
```sh
go_in_to ml-gateway
supervisorctl restart gateway
exit
```

## Access PVs from the lab — without a certificate (TCP)

Lab pods can reach local IOCs directly and ML PVs via the ml-gateway's cross-zone server.

```sh
login_to_lab operator
```
```sh
# Local lab PV — direct via ADDR_LIST
pvxget test:aiExample
# Expected: returns the current value over plain TCP (no TLS)

# ML PV — via ml-gateway:5175 cross-zone server
pvxget ml:aiExample
# Expected: returns the ML IOC value, routed through ml-gateway
exit
```

## Access PVs from the lab — with a certificate (TLS)

```sh
login_to_lab operator
```
```sh
kinit operator@EPICS.ORG
# Enter password: secret
authnkrb
# Output: Keychain file created: .../client.p12
```
```sh
pvxinfo test:spec
# Expected: shows TLS connection to testioc (x509 certificate in output)

pvxget test:aiExample
# Expected: value returned over TLS

pvxget ml:stringExample
# Expected: ML PV value via ml-gateway:5175, over TLS if gateway has cert
exit
```

## Access PVs from the ML centre

ML pods reach their own IOCs directly and lab PVs via the lab gateway's cross-zone server.

```sh
login_to_ml mloperator
```
```sh
# Local ML PV — direct via ADDR_LIST
pvxget ml:aiExample

# Lab PV — via gateway:5175 cross-zone server
pvxget test:aiExample
pvxget tst:extra
exit
```

## Access PVs from the internet — with a certificate

Internet pods have no direct IOC access. All PVs come through gateway servers on port :5275.

```sh
login_from_internet operator
```
```sh
kinit operator@EPICS.ORG
authnkrb
```
```sh
# Lab PV — via gateway:5075
pvxget test:aiExample

# ML PV — via ml-gateway:5075
pvxget ml:aiExample

# Both work because internet NAME_SERVERS includes both gateways on :5075
pvxinfo test:spec
# Expected: shows TLS via gateway certificate

exit
```

## Access PVs from CS-Studio

CS-Studio pods have the same PVA configuration as their zone's terminal pod. Each runs Phoebus inside Xvfb, exposed through noVNC.

### Lab CS-Studio

Terminal 1 — launch Phoebus:
```sh
login_to_cs_studio_in_lab operator
cs-studio
```

Terminal 2 — start the port-forward:
```sh
cs_studio_lab
```

Then open http://127.0.0.1:8080/vnc_auto.html in your browser and click **Connect**.

Phoebus sees the same PVs as the lab pod: `test:*` and `tst:*` directly, `ml:*` via ml-gateway:5175.

### ML CS-Studio

Terminal 1:
```sh
login_to_cs_studio_in_ml mloperator
cs-studio
```

Terminal 2:
```sh
cs_studio_ml
```

Then open http://127.0.0.1:8081/vnc_auto.html and click **Connect**.

Phoebus sees `ml:*` directly, `test:*` and `tst:*` via gateway:5175.

### Internet CS-Studio

Terminal 1:
```sh
login_to_cs_studio_from_internet operator
kinit operator@EPICS.ORG
authnkrb
cs-studio
```

Terminal 2:
```sh
cs_studio_internet
```

Then open http://127.0.0.1:8082/vnc_auto.html and click **Connect**.

Phoebus sees `test:*` and `tst:*` via gateway:5275, `ml:*` via ml-gateway:5275.

## Verify no duplicate PVs

A key design goal is that no PV appears from multiple sources. Verify with:

```sh
login_to_lab operator
pvxinfo -S test:aiExample
# Expected: exactly ONE result from testioc (direct), not duplicated via gateway

pvxinfo -S ml:aiExample
# Expected: exactly ONE result from ml-gateway:5175
exit
```

```sh
login_from_internet operator
kinit operator@EPICS.ORG
authnkrb
pvxinfo -S test:aiExample
# Expected: exactly ONE result from gateway:5075

pvxinfo -S ml:aiExample
# Expected: exactly ONE result from ml-gateway:5075
exit
```

## Certificate management PVs

- `CERT:CREATE` and `CERT:STATUS` are only accessible through the lab gateway's internet server (:5275/:5276) for internet clients. 
- `CERT:CLUSTER` PVs are only accessible through the cross-zone servers (:5175/:5176) on both gateways.
- Inside the lab and ML zones, PVACMS `CERT:*` PVs are accessed directly from the local PVACMS via `EPICS_PVA_ADDR_LIST`.

From the internet:
```sh
login_from_internet operator
kinit operator@EPICS.ORG
authnkrb
pvxget CERT:CREATE
# Expected: accessible via gateway:5075

pvxget CERT:CLUSTER:CTRL:????????
# Expected: NOT accessible (CERT:CLUSTER not in internet pvlist)
exit
```

Inside the lab, PVACMS PVs are accessed directly (not through the gateway):
```sh
login_to_lab operator
pvxget CERT:CREATE
# Expected: direct from pvacms via ADDR_LIST
exit
```

Inside the ML zone, PVACMS PVs are also accessed directly (not through ml-gateway):
```sh
login_to_ml mloperator
pvxget CERT:CREATE
# Expected: direct from ml pvacms via ADDR_LIST
exit
```
