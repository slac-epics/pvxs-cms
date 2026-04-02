# Kubernetes Cluster with PVAccess Gateway ingress

## Overview
In this setup, we create a single-node Kubernetes cluster that simulates three isolated zones on the same host:
- Zone 1: **Lab Network**
	- **idm**: Identity Management
		- ***kdc***: Kerberos Service
			- user: *idm*
		- ***pvacms***: PVACMS Service with external access
			- user: *pvacms*
	- **it**: IT
		- ***pvacms***: PVACMS HA and failover Service for lab only
			- user: *pvacms*
	- **testioc**: IOC
		- ***softIocPVX***
			- user: *testioc*
	- **tstioc**: IOC
		- ***softIocPVX***
			- user: *tstioc*
	- **lab**: General Lab Personnel
		- Control Room
			- user: *operator*
		- Office
			- user: *guest*
	- **gateway**: PVAccess Gateway - external client access to lab services
		- ***PVAGateway***
			- user: *gateway*
- Zone 2: **ML Center network**
	- **ml**: General ML Personnel and IT Systems
		- Office
			- user: *mloperator*
		- ML Systems
			- user: *mlsystem*
		- ***pvacms***: PVACMS Service for ML only
			- user: *pvacms*
	- **ml-ioc**: IOC
		- ***softIocPVX***
			- user: *mlioc*
	- **ml-gateway**: PVAccess Gateway - external client access to ML services
		- ***PVAGateway***		
			- user: *gateway*
- Zone 3: **Internet** 
	- **internet**:
		- Home:
			- user: *guest*
			- user: *operator*

The internet and ML centre reach the lab through gateways, enforcing network segmentation while still allowing PVA access and CMS clustering.

### Topology
```text
Internet pod --(lab gateway only)--> Lab Gateway --> Lab Network
                                      <->
                                 ML Gateway
                                      <->
                                 ML Network
```

### PVACMS cluster mode
The CMS runs in three-node cluster mode (`--cluster-mode`) on `idm`, `it`, and `ml`:
- `idm` <-> `it` communicate directly on the lab network.
- `ml` reaches lab services through the gateway chain (`ml-gateway` <-> `gateway`).
- `it` and `ml` do not connect directly; `idm` relays cluster updates transitively.
- `--cluster-discovery-timeout 30` and `--cluster-bidi-timeout 30` are set on all nodes to accommodate the extra latency of the two-gateway chain for the `ml` node.

# Users
## INSIDE LAB
| Pod | Users |
|-----|-------|
| idm | admin, pvacms |
| lab | guest, operator |
| it | idm, admin |
| gateway | gateway |
| testioc | testioc |
| tstioc | tstioc |

## ML CENTRE
| Pod | Users |
|-----|-------|
| ml | mloperator, mlsystem |
| ml-gateway | gateway |
| ml-ioc | mlioc |

A valid administrator certificate keychain file is provided and configured for the admin user.  The admin user can additionally use the kinit command to obtain a Kerberos ticket and then use `authnkrb` to get an X.509 certificate.

## OUTSIDE LAB
| Pod | Users |
|-----|-------|
| internet | guest, operator |
| extern | remote |

# services
| Pod        | Services    |
| ---------- | ----------- |
| internet   | internet    |
| idm        | kdc, pvacms |
| it         | pvacms      |
| lab        | lab         |
| testioc    | testioc     |
| tstioc     | tstioc      |
| gateway    | gateway     |
| ml         | pvacms      |
| ml-ioc     | mlioc       |
| ml-gateway | gateway     |

# Kerberos Authentication

The lab cluster includes a single Kerberos KDC (Key Distribution Center) running on the `idm` pod.
All pods — including those in the ML centre and internet zones — use this same KDC via the
`pvxs-lab-krb` ClusterIP service. The krb5.conf is injected at deploy time via a Helm ConfigMap
(overriding the image-baked default), so all pods resolve the KDC correctly.

> **Note on ML Kerberos access**: In a real deployment, the ML centre would have its own identity provider or a federated trust relationship. In this simulation, the direct Kerberos path from the `ml` pod to the `idm` KDC (allowed by network policy on UDP 88 / TCP 749) represents a secure tunnel between the ML facility and the lab's identity infrastructure. This is a pragmatic simplification for development and testing.

## Kerberos Realm
- **Realm**: EPICS.ORG
- **KDC Service**: pvxs-lab-krb (UDP 88, TCP 749)
- **NodePort**: 30049, 30088 (for external kinit)

## Users (Kerberos Principals)
| Principal                | Password | Zone |
|--------------------------|----------|------|
| admin@EPICS.ORG          | secret   | Lab |
| guest@EPICS.ORG          | secret   | Lab / Internet |
| operator@EPICS.ORG       | secret   | Lab / Internet |
| pvacms/cluster@EPICS.ORG | random   | Lab (service) |
| remote@EPICS.ORG         | secret   | Lab |
| testioc@EPICS.ORG        | secret   | Lab |
| tstioc@EPICS.ORG         | secret   | Lab |
| mloperator@EPICS.ORG     | secret   | ML Centre |
| mlsystem@EPICS.ORG       | secret   | ML Centre |

All these users and services can use authnkrb to get an X.509 certificate. e.g.

```sh
kinit operator@EPICS.ORG
authnkrb
```

or 

```shell
kinit testioc@EPICS.ORG
authnkrb -u server
```

A keytab is provided and configured for the pvacms service.

# PVs available:

All three pvacms instances share the same issuer_id (derived from the shared CA keychain).
The `????????` placeholders represent 8-character hex IDs generated at runtime.

## IDM, ML, and IT pvacms
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

## testioc
- test:aiExample
- test:arrayExample
- test:calcExample
- test:compressExample
- test:enumExample
- test:groupExampleAS
- test:groupExampleSave
- test:longExample
- test:spec   ....<<<....<<<....<<<...  Only setable by operator and gateway
- test:stringExample
- test:structExample
- test:structExampleSave
- test:tableExample
- test:vectorExampleD1
- test:vectorExampleD2

## tstioc
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

## ml-ioc
- ml:aiExample
- ml:stringExample
- ml:longExample



# Helpers

```shell
source ./helpers.sh
```

Set up the following helper functions by sourcing the helpers.sh script:
- **gw_build_images** - Build the docker images for the cluster

```shell
# usage: 
gw_build_images [<target>] [<options>]

# target: if omitted then build all images
#  lab_base - Build lab base image
#  lab - Build lab image (simulates login terminal inside lab)
#  internet - Build internet users image
#  testioc - Build testioc image
#  tstioc - Build tstioc image
#  idm - Build idm (identity management) image
#  ml - Build ml pvacms image
#  ml-ioc - Build ml-ioc image
#  gateway - Build gateway image

# options:
# --no-cache - Do not use Docker cache when building images,
# e.g.
gw_build_images --no-cache
``` 
- **gw_cp** - Copy files from any container to the host
```shell
# usage: 
gw_cp <container> <user> <container_source_path> <host_dest_path> 

# container: lab | idm | gateway | testioc | tstioc | internet | it | ml | ml-ioc | ml-gateway
# user: admin | guest | operator | pvacms | gateway | testioc | tstioc | mloperator | mlsystem | mlioc

# e.g. 
gw_cp lab operator '/home/operator/.config/pva/1.5/client.p12' ~/.config/pva/1.5/client.p12
``` 
- **gw_cp_in** - Copy files from the host into any container
```shell
# usage: 
gw_cp_in <container> <user> <host_dest_path> <container_source_path> 

# container: lab | idm | gateway | testioc | tstioc | internet | it | ml | ml-ioc | ml-gateway
# user: admin | guest | operator | pvacms | gateway | testioc | tstioc | mloperator | mlsystem | mlioc

gw_cp_in lab guest ~/Downloads/gateway.p12 '/home/guest/.config/pva/1.4/gateway.p12'
``` 
- **gw_deploy** - Deploy the gateway and testioc services
```shell
# usage: 
gw_deploy [-r] [options] 

# -r - Redeploy the cluster (delete, quiesce, and recreate)
# options:
# --dry-run - Do not deploy, just print kubectl yaml,
# --set gateway.debug.enabled=true - enable debug logging,
# --set gateway.separate_server_keychain=true - use separate server and client-side keychain files for gateway,
# --set additional helm options can be passed after --set to override helm default values,
# e.g. 
gw_deploy --set gateway.separate_server_keychain=true --dry-run
``` 
- **gw_internet_config** - Configure the SPVA to access lab PVs via the gateway and configure remote kerberos authentication
```shell
# usage: 
gw_internet_config 
``` 
- **gw_log** - View the logs of the gateway and testioc services
```shell
# usage: 
gw_log <service_container> 

# service_container: idm | gateway | testioc | tstioc | internet | it | ml | ml-ioc | ml-gateway

# e.g. 
gw_log gateway
``` 
- **gw_undeploy** - Undeploy the cluster
```shell
# usage: 
gw_undeploy
``` 
- **go_in_to** - Login as root to specified container.
```shell
# usage: 
go_in_to <container> 

# container: idm | gateway | testioc | tstioc | lab | internet | it | ml | ml-ioc | ml-gateway

go_in_to gateway
``` 
- **login_to_lab** - Simulate user login to the lab.  Automatically selects the correct container to log in to based on the user.
```shell
# usage: 
login_to_lab <user> 

# user: admin | guest | operator | pvacms | gateway | testioc | tstioc | it

login_to_lab guest
``` 
- **login_from_internet** - Simulate user login from internet users pod.
```shell
# usage:
login_from_internet <user>

# user: guest | operator

login_from_internet operator
```
- **login_to_ml** - Simulate user login to ML centre pods.
```shell
# usage:
login_to_ml <user>

# user: mloperator | mlsystem | ml-gateway | ml-ioc

login_to_ml mloperator
login_to_ml ml-gateway
```

# How to
## Building and deploying the cluster

```shell
gw_build_images
gw_deploy
```

## Create a certificate for the gateway
```shell
login_to_lab gateway
```
```console
    Defaulted container "gateway" out of: gateway, gateway-conf-init (init)
    gateway@pvxs-lab-gateway-b8ddf69cc-w4sff:~$ 
```
```shell
authnstd -u ioc
```
```console
    Keychain file created   : /home/gateway/.config/pva/1.5/gateway.p12
    Certificate identifier  : 5ccdbe56:14618850982176448153
    gateway@pvxs-lab-gateway-b8ddf69cc-w4sff:~$ 
```
```shell
exit
```
```console
  logout
```
```shell
login_to_lab admin
```
```shell
    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.
    
    admin@pvxs-lab-idm-664c48bf84-67vpx:~$ 
```
```shell
pvxcert --approve 5ccdbe56:14618850982176448153
```
```shell
    Approve ==> CERT:STATUS:5ccdbe56:14618850982176448153 ==> Completed Successfully
    admin@pvxs-lab-idm-664c48bf84-67vpx:~$ 
```
```shell
exit
```
```shell
    logout
```
```shell
go_in_to gateway
```
```console
    Defaulted container "gateway" out of: gateway, gateway-conf-init (init)
    root@pvxs-lab-gateway-b8ddf69cc-w4sff:/home/gateway# 
```
```shell
supervisorctl restart gateway
```
```console
    gateway: stopped
    gateway: started
    root@pvxs-lab-gateway-b8ddf69cc-w4sff:/home/gateway# 
```
```shell
exit
```

## Create a certificate for the ioc
```shell
login_to_lab testioc
```
```console
    testioc@pvxs-lab-testioc-75b5d99bfc-pkkp9:~$ 
```
```shell
authnstd -u server
```
```console
    Keychain file created   : /home/testioc/.config/pva/1.5/server.p12
    Certificate identifier  : 5ccdbe56:9231356005662723745
    testioc@pvxs-lab-testioc-75b5d99bfc-pkkp9:~$ 
```
```shell
exit
```
```console
  logout
```
```shell
login_to_lab admin
```
```console
    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.
    
    admin@pvxs-lab-idm-664c48bf84-67vpx:~$ 
```
```shell
pvxcert --approve 5ccdbe56:9231356005662723745
```
```console
    Approve ==> CERT:STATUS:5ccdbe56:9231356005662723745 ==> Completed Successfully
    admin@pvxs-lab-idm-664c48bf84-67vpx:~$ 
```
```shell
exit
```
```console
  logout
```
```shell
go_in_to testioc
```
```console
    root@pvxs-lab-testioc-75b5d99bfc-pkkp9:/opt/epics/pvxs-cms# 
```
```shell
supervisorctl restart testioc:
```
```console
    testioc:: stopped
    testioc:: started
    root@pvxs-lab-testioc-75b5d99bfc-pkkp9:/opt/epics/pvxs-cms# 
```
```shell
exit
```

## Login as operator using kerberos

```shell
login_to_lab operator
```
```console
    Password:
    operator@pvxs-lab-lab-78c5c7dfb7-8g9wm:~$ 
```
```shell
kinit
```
```console
    Password for operator@EPICS.ORG:
    operator@pvxs-lab-lab-78c5c7dfb7-8g9wm:~$ 
```
```shell
klist
```
```console
    Ticket cache: FILE:/tmp/krb5cc_1001
    Default principal: operator@EPICS.ORG
    
    Valid starting     Expires            Service principal
    02/25/26 11:51:14  02/26/26 11:51:14  krbtgt/EPICS.ORG@EPICS.ORG
        renew until 02/25/26 11:51:14
    operator@pvxs-lab-lab-78c5c7dfb7-8g9wm:~$ 
```
```shell
authnkrb
```
```console
    Keychain file created   : /home/operator/.config/pva/1.5/client.p12
    Certificate identifier  : 5ccdbe56:3177094924438270462
    operator@pvxs-lab-lab-78c5c7dfb7-8g9wm:~$ 
```
```shell
exit
```
```console
  logout
```

## Secure access to IOC from within the lab

```shell
login_to_lab operator
```
```console
    Password:
    operator@pvxs-lab-lab-78c5c7dfb7-8g9wm:~$ 
```
```shell
pvxinfo -v test:spec
```
```console
    Effective config
    EPICS_PVA_ADDR_LIST=10.96.154.196:5076 10.97.197.159:5076 10.100.237.122:5076
    EPICS_PVA_AUTO_ADDR_LIST=NO
    EPICS_PVA_BROADCAST_PORT=5076
    EPICS_PVA_CERT_PV_PREFIX=CERT
    EPICS_PVA_CONN_TMO=30.000000
    EPICS_PVA_SERVER_PORT=5075
    EPICS_PVA_TLS_KEYCHAIN=/home/operator/.config/pva/1.5/client.p12
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/home/operator/.config
    XDG_DATA_HOME=/home/operator/.local/share
    # TLS x509:5ccdbe56:9231356005662723745:EPICS Root Certificate Authority/testioc@10.97.197.159:5076
    test:spec from 10.97.197.159:5076
    struct "epics:nt/NTScalar:1.0" {
        double value
        struct "alarm_t" {
            int32_t severity
            int32_t status
            string message
        } alarm
        struct "time_t" {
            int64_t secondsPastEpoch
            int32_t nanoseconds
            int32_t userTag
        } timeStamp
        struct {
            double limitLow
            double limitHigh
            string description
            string units
            int32_t precision
            struct "enum_t" {
                int32_t index
                string[] choices
            } form
        } display
        struct {
            double limitLow
            double limitHigh
            double minStep
        } control
        struct {
            bool active
            double lowAlarmLimit
            double lowWarningLimit
            double highWarningLimit
            double highAlarmLimit
            int32_t lowAlarmSeverity
            int32_t lowWarningSeverity
            int32_t highWarningSeverity
            int32_t highAlarmSeverity
            double hysteresis
        } valueAlarm
    }
```

## Secure access to IOC from outside the lab

```shell
 gw_internet_config                                                                                                                           4 ↵
```
```console
INTERNET mode: PVA client->127.0.0.1:31075 ; ~/.config/pva/1.5/client.p12 ; KRB5 PORTS: 30049, 30088
```
```shell
klist
```
```console
Credentials cache: API:0E72A801-7899-4C3E-9C34-14F52C474BC9
        Principal: operator@EPICS.ORG

  Issued                Expires               Principal
Feb 25 16:39:52 2026  Feb 26 16:39:52 2026  krbtgt/EPICS.ORG@EPICS.ORG
```
```shell
authnkrb
    Keychain file created   : /home/operator/.config/pva/1.5/client.p12
    Certificate identifier  : 5ccdbe56:3177094924438270462
```
```shell
pvxinfo -v test:spec
```
```console
    Effective config
    EPICS_PVA_ADDR_LIST=10.96.154.196:5076 10.97.197.159:5076 10.100.237.122:5076
    EPICS_PVA_AUTO_ADDR_LIST=NO
    EPICS_PVA_BROADCAST_PORT=5076
    EPICS_PVA_CERT_PV_PREFIX=CERT
    EPICS_PVA_CONN_TMO=30.000000
    EPICS_PVA_SERVER_PORT=5075
    EPICS_PVA_TLS_KEYCHAIN=/home/operator/.config/pva/1.5/client.p12
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/home/operator/.config
    XDG_DATA_HOME=/home/operator/.local/share
    # TLS x509:5ccdbe56:14618850982176448153:EPICS Root Certificate Authority/gateway@10.97.197.159:5076
    test:spec from 10.97.197.159:5076
    struct "epics:nt/NTScalar:1.0" {
        double value
        struct "alarm_t" {
            int32_t severity
            int32_t status
            string message
        } alarm
        struct "time_t" {
            int64_t secondsPastEpoch
            int32_t nanoseconds
            int32_t userTag
        } timeStamp
        struct {
            double limitLow
            double limitHigh
            string description
            string units
            int32_t precision
            struct "enum_t" {
                int32_t index
                string[] choices
            } form
        } display
        struct {
            double limitLow
            double limitHigh
            double minStep
        } control
        struct {
            bool active
            double lowAlarmLimit
            double lowWarningLimit
            double highWarningLimit
            double highAlarmLimit
            int32_t lowAlarmSeverity
            int32_t lowWarningSeverity
            int32_t highWarningSeverity
            int32_t highAlarmSeverity
            double hysteresis
        } valueAlarm
    }
```
