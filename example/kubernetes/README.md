# Kubernetes Cluster with PVAccess Gateway ingress

## Overview
In this setup, we create a single-node Kubernetes cluster that simulates two isolated networks (subnets) on the same host:
- a “lab” subnet for internal services, and 
- a “non-lab” (external) subnet for clients

The goal is that external clients can only reach the SoftIOC’s PVs via the gateway, enforcing network isolation. This mirrors a typical EPICS deployment where a gateway machine with two NICs connects an isolated control network with an office network. The gateway will accept client connections on the external subnet and forward requests to the SoftIOC on the lab subnet, and vice versa, acting as a PVA protocol proxy.

# Users

## INSIDE LAB
- lab:
  - operator
  - guest
- idm
  - kdc
  - pvacms
  - admin
- testioc:
  - testioc
- tstioc:
  - tstioc
- gateway:
  - gateway

## OUTSIDE LAB
- lab:
  - operator
- extern:
  - remote


# Kerberos Authentication

The lab cluster includes a Kerberos KDC (Key Distribution Center) for authentication.

## Kerberos Realm
- **Realm**: EPICS.ORG
- **KDC Service**: pvxs-lab-idm (port 88, 479)
- **NodePort**: 30049, 30088 (for external kinit)

## Users (Kerberos Principals)
| Principal  | Password |
|------------|----------|
| operator@EPICS.ORG | secret |
| guest@EPICS.ORG | secret |
| client@EPICS.ORG | secret |

## External Access (kinit from outside cluster)

1. Copy the sample client configuration:
   ```sh
   cp krb5-client.conf /etc/krb5.conf
   ```

2. Replace `<NODE-IP>` with your Kubernetes node's IP address:
   ```sh
   sed -i 's/<NODE-IP>/<your-node-ip>/g' /etc/krb5.conf
   ```

3. Initialize your Kerberos ticket:
   ```sh
   kinit operator@EPICS.ORG
   # Password: secret
   ```

4. Verify your ticket:
   ```sh
   klist
   ```

5. Use authnkrb to get an X.509 certificate:
   ```sh
   authnkrb
   ```

## Inside the Lab Pod

Users inside the lab pod already have Kerberos configured via the ConfigMap:

```sh
kubectl exec -it deploy/pvxs-lab-lab -- su - guest
kinit guest@EPICS.ORG
# Password: secret
```

## Building the IDM Image

The IDM (Identity Management) image includes the KDC and pvacms:

```sh
cd docker/idm
./build_docker.sh
```

## Helm Deployment

Deploy with Helm:

```sh
helm upgrade --install pvxs-lab ./helm/pvxs-lab \
  --namespace pvxs-lab --create-namespace
```

The IDM service is exposed via NodePort on UDP port 30088.


# PVs available:
## pvacms
- CERT:CREATE
- CERT:CREATE:65aeafe4
- CERT:ISSUER
- CERT:ISSUER:65aeafe4
- CERT:ROOT
- CERT:ROOT:65aeafe4
- CERT:STATUS:65aeafe4:*

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


