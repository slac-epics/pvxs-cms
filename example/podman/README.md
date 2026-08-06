# Secure PVAccess demonstration laboratory, on podman

A two-department Secure PVAccess laboratory that runs on rootless podman with
`podman-compose`.

Everything here is exercised from the command line, where every property worth
demonstrating can be shown and checked directly.

## Contents

- [What it demonstrates](#what-it-demonstrates)
- [Installation](#installation)
- [Bringing it up](#bringing-it-up)
- [1. Two certificate managers, one per department](#1-two-certificate-managers-one-per-department)
- [2. Crossing a boundary is only possible through a gateway](#2-crossing-a-boundary-is-only-possible-through-a-gateway)
- [3. One facility root, so each department trusts the other's certificates](#3-one-facility-root-so-each-department-trusts-the-others-certificates)
- [4. The request identifier an administrator checks](#4-the-request-identifier-an-administrator-checks)
- [5. Listing certificates](#5-listing-certificates)
- [6. Filtering the listing](#6-filtering-the-listing)
- [7. Approving, in batches or one at a time](#7-approving-in-batches-or-one-at-a-time)
- [8. Denying and revoking](#8-denying-and-revoking)
- [9. Only an administrator may decide](#9-only-an-administrator-may-decide)
- [Troubleshooting](#troubleshooting)

## What it demonstrates

| | |
|---|---|
| **Two departments** | Each runs its own certificate manager, signing with its own intermediate certificate authority, holding only the certificates it issued |
| **One facility root** | Both intermediates are signed by it, so a certificate from either department is trusted laboratory-wide, while authorisation stays per department |
| **Real network separation** | Three podman networks; a container reaches only those it is attached to, so a department's certificate manager is addressable only from inside it |
| **Gateways on the boundary** | The only route between departments. Each forwards its own department's controller process variables, and its certificate traffic keyed by issuer id |
| **Administration** | Listing, filtering, request identifiers, approval in batches or one at a time, denial and revocation, all restricted to administrators |

## Installation

**1. Install podman.** The image build scripts call `docker`, so the shim is needed too.

```sh
sudo apt install -y podman podman-compose podman-docker      # Debian, Ubuntu
sudo dnf install -y podman podman-compose podman-docker      # Fedora, RHEL
```

**2. Allow containers to outlive your login session.** Without this, rootless containers
are killed the moment you log out or your connection drops.

```sh
loginctl enable-linger "$USER"
```

**3. Get the source.** The four trees must be siblings, and the directory names matter -
the image builds reference them by name.

```sh
mkdir -p ~/slac && cd ~/slac
B=scratch/fy26-integration-testing
git clone -b $B --recurse-submodules https://github.com/slac-epics/pvxs-cms.git       pvxs-cms
git clone -b $B --recurse-submodules https://github.com/slac-epics/pvxs-tls.git       pvxs
git clone -b $B --recurse-submodules https://github.com/slac-epics/epics-base-tls.git epics-base
git clone -b $B --recurse-submodules https://github.com/slac-epics/p4p-tls.git        p4p
```

## Bringing it up

```sh
cd ~/slac/pvxs-cms/example/podman
./bootstrap.sh              # builds the images, mints the authorities
podman-compose up -d
podman-compose ps
```

The build compiles EPICS Base, pvxs, pvxs-cms and p4p from source and takes a while. On a
machine with little memory, lower the compiler parallelism and make sure there is swap:

```sh
JOBS=2 ./bootstrap.sh
```

`bootstrap.sh` writes `.env` and `issuer_ids.env`, holding the two departments' issuer ids.
Keep them to hand:

```sh
cat .env
#   LAB_ISSUER=ba71d9e3
#   ML_ISSUER=2328300d
export LAB=$(grep LAB_ISSUER .env | cut -d= -f2)
export ML=$(grep ML_ISSUER  .env | cut -d= -f2)
```

### Issue the certificates

Nothing holds a certificate yet. Each service asks its **own** department, and that
department's administrator approves.

```sh
# controllers ask
podman exec podman_pvxs-lab-testioc_1 su - testioc -c 'source ~/.testioc_bashrc; authnstd -u server'
podman exec podman_pvxs-lab-tstioc_1  su - tstioc  -c 'source ~/.tstioc_bashrc;  authnstd -u server'
podman exec podman_pvxs-lab-ml-ioc_1  su - mlioc   -c 'source ~/.mlioc_bashrc;   authnstd -u server'

# each department approves its own
podman exec podman_pvxs-lab-pvacms_1 bash -lc \
  'export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
   export EPICS_PVA_NAME_SERVERS=pvas://localhost:5076
   pvxcert --review-pending --all approve --yes'
podman exec podman_pvxs-lab-ml_1 bash -lc \
  'export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
   export EPICS_PVA_NAME_SERVERS=pvas://localhost:5076
   pvxcert --review-pending --all approve --yes'

# gateways last, then approve them the same way
podman exec podman_pvxs-lab-gateway_1    su - gateway -c 'source ~/.gateway_bashrc; authnstd -u ioc'
podman exec podman_pvxs-lab-ml-gateway_1 su - gateway -c 'source ~/.gateway_bashrc; authnstd -u ioc -n ml-gateway'
```

Because that administrator command is long, the rest of this document abbreviates it:

```sh
admin() {   # admin <lab|ml> <pvxcert arguments...>
    local c=podman_pvxs-lab-pvacms_1; [ "$1" = ml ] && c=podman_pvxs-lab-ml_1; shift
    podman exec "$c" bash -lc \
      "export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
       export EPICS_PVA_NAME_SERVERS=pvas://localhost:5076
       PVXS_LOG=none pvxcert $*"
}
```

**Then restart the two gateways.** A gateway that started before the controllers were
serving does not retry, and nothing crosses a boundary until it is restarted.

```sh
podman-compose restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

---

## 1. Two certificate managers, one per department

They are independent. Each holds only what it issued, and neither knows about the other's
certificates.

```sh
admin lab -l
admin ml  -l
```

The certificate identifiers make it plain: everything the first lists begins with
`$LAB`, everything the second lists begins with `$ML`. The issuer half of an
`<issuer>:<serial>` identifier says which department to ask about a certificate.

Which department a service asks is decided by where it runs, not by which manager answers
first. Each container carries its own department's issuer id:

```sh
podman exec podman_pvxs-lab-testioc_1 su - testioc -c 'echo $EPICS_PVA_AUTH_ISSUER'   # lab
podman exec podman_pvxs-lab-ml-ioc_1  su - mlioc   -c 'echo $EPICS_PVA_AUTH_ISSUER'   # machine learning
```

## 2. Crossing a boundary is only possible through a gateway

Inside a department, a client talks to its controllers directly:

```sh
podman exec podman_lab-client_1 bash -lc 'source ~/.guest_bashrc; pvxget test:aiExample'
```

From outside both departments, the same read has to cross a gateway, and does:

```sh
podman exec podman_perimeter-client_1 bash -lc 'source ~/.guest_bashrc; pvxget test:aiExample'
podman exec podman_perimeter-client_1 bash -lc 'source ~/.guest_bashrc; pvxget ml:aiExample'
```

And a lab client reaching the other department goes through that department's gateway:

```sh
podman exec podman_lab-client_1 bash -lc 'source ~/.guest_bashrc; pvxget ml:aiExample'
```

A gateway is the only route. Every direct approach is refused:

```sh
podman exec podman_lab-client_1       getent hosts pvxs-lab-ml        # other department's manager
podman exec podman_lab-client_1       getent hosts pvxs-lab-ml-ioc    # other department's controller
podman exec podman_perimeter-client_1 getent hosts pvxs-lab-pvacms    # a certificate manager
podman exec podman_perimeter-client_1 getent hosts pvxs-lab-ml
```

podman enforces the separation itself: a container reaches only the networks it is
attached to. Only the two gateways sit on a department network **and** the perimeter.

What a gateway carries is exactly what its list names - its department's controllers, and
its department's certificate traffic keyed by issuer id:

```sh
podman exec podman_pvxs-lab-gateway_1    cat /home/gateway/gateway.pvlist
#   test:.* ALLOW                                 its controllers, readable
#   tst:.* ALLOW
#   test:spec ALLOW SPECIAL                       writable, to a certificate from either department
#   CERT:CREATE:<lab>(?::.*)? ALLOW CERT_CREATE   ask this department for a certificate
#   CERT:STATUS:<lab>(?::.*)? ALLOW CERT_STATUS   check one it issued
#   CERT:LIST:<lab>:ALL ALLOW CERT_STATUS         the two open views
#   CERT:LIST:<lab>:EXPIRING ALLOW CERT_STATUS
podman exec podman_pvxs-lab-ml-gateway_1 cat /home/gateway/gateway.pvlist
```

Each names its **own** issuer only, so a request for the other department's certificates is
not claimed by the wrong gateway. The view of certificates awaiting a decision appears in
neither list, for the reason in section 9.

## 3. One facility root, so each department trusts the other's certificates

This is the point of the whole arrangement, and it is worth walking through.

A client outside both departments asks the **machine learning** department for a
certificate. It cannot reach that certificate manager, so the request travels through the
machine learning gateway:

```sh
podman exec --user operator podman_perimeter-client_1 bash -lc \
  "source ~/.operator_bashrc; authnstd -u client --issuer ${ML}"
admin ml --review-pending --all approve --yes
```

That client now holds a **machine-learning-issued** certificate. It uses it to write to a
**lab** controller, through the **lab** gateway:

```sh
podman exec --user operator podman_perimeter-client_1 bash -lc \
  'source ~/.operator_bashrc
   export EPICS_PVA_TLS_KEYCHAIN=/home/operator/.config/pva/1.5/client.p12
   pvxput test:spec 7
   pvxget test:spec'
```

The write succeeds. For that to happen, every one of these had to hold:

- The lab gateway verified a certificate issued by the **machine learning** intermediate,
  by following the chain back to the facility root it holds locally
- Its access rule authorised the write on `AUTHORITY(EPICS_CA)`, the **shared root**, so a
  certificate from either department qualifies
- The certificate's status was checked against the **machine learning** certificate
  manager, which the lab side reaches only through a gateway

Trust is shared; authorisation is not. The gateway's access file grants writes only for
process variables marked `ALLOW SPECIAL` in its list, and only to
`UAG(SPECIAL_USERS)` over TLS with a certificate:

```sh
podman exec podman_pvxs-lab-gateway_1 cat /home/gateway/gateway.acf
podman exec podman_pvxs-lab-gateway_1 cat /home/gateway/gateway.pvlist
```

A certificate from the wrong department, or none at all, is refused:

```sh
podman exec podman_perimeter-client_1 bash -lc 'source ~/.guest_bashrc; pvxput test:spec 9'
#   Put permission denied by gateway
```

## 4. The request identifier an administrator checks

The certificate creation request travels in clear text, so an administrator has to be able
to compare what is on screen against what the requester sent. `authnstd` prints an
identifier for the requester to quote:

```sh
podman exec podman_lab-client_1 bash -lc 'source ~/.guest_bashrc; authnstd -u client'
#   email this Certificate Request ID: 4KFD-Z215-WGFD-977M, to your SPVA administrator
```

The administrator sees the same identifier, in the same grouping, against the request:

```sh
admin lab --review-pending < /dev/null
#     Subject        : CN=guest,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : 4KFD-Z215-WGFD-977M
```

It is also a column in the listing:

```sh
admin lab -l
```

## 5. Listing certificates

```sh
admin lab -l
```

Every certificate the department has issued, with its type, subject, status, dates and
request identifier. Dates are rendered year first in one fixed-width layout everywhere, so
they sort and compare as plain text.

The same listing is served as standing views a client can subscribe to, named by issuer so
that two certificate managers on one network are never ambiguous:

```sh
podman exec podman_lab-client_1 bash -lc "source ~/.guest_bashrc; pvxmonitor CERT:LIST:${LAB}:ALL"
podman exec podman_lab-client_1 bash -lc "source ~/.guest_bashrc; pvxmonitor CERT:LIST:${LAB}:EXPIRING"
```

Those two are open to everyone. The third is not - see section 9.

## 6. Filtering the listing

```sh
admin lab -l --where "name:gateway"
admin lab -l --where "state:VALID"
admin lab -l --where "state:PENDING_APPROVAL"
admin lab -l --where "type:SERVER"
admin lab -l --where "name:testioc and state:VALID"
admin lab -l --where "name:testioc or name:tstioc"
admin lab -l --where "expires_before:30d and state:VALID"
admin lab --expiring 30d
```

The expression is meant to be sayable aloud. Because dates are fixed width and year
first, a partial bound selects by prefix and nothing needs parsing.

## 7. Approving, in batches or one at a time

**One at a time**, with the full subject and the request identifier in front of you.
Answer `approve`, `deny`, `skip`, `stop` or `cancel`:

```sh
admin lab --review-pending
```

`s` is refused, because it could mean `skip` or `stop`. `a`, `d`, `r` and `c` are accepted.
Nothing is written until a single confirmation at the end, which defaults to no. Just
before it, every decided certificate is re-read, and any that changed since the listing is
dropped and reported rather than written over.

**The whole batch**, without being asked:

```sh
admin lab --review-pending --all approve --yes
admin lab --review-pending --all deny --yes
```

`--all` decides every listed certificate; `--yes` answers the final confirmation. Together
they approve without showing you a single request identifier, which is why the tool warns
about it.

**One known certificate**, when you already have its identifier:

```sh
admin lab -A "${LAB}:0123456789"      # approve
admin lab -D "${LAB}:0123456789"      # deny
```

With no terminal to read answers from and no `--all`, the listing is printed, nothing is
written, and the exit code is 3:

```sh
admin lab --review-pending < /dev/null ; echo "exit $?"
```

## 8. Denying and revoking

A denial is not a separate state: the certificate manager writes `REVOKED`, and the review
shows that before you confirm.

```sh
admin lab --review-pending --all deny --yes
```

Revocation works over the issued certificates, narrowed by the same filter:

```sh
admin lab --review-issued --where "state:VALID"                 # one at a time
admin lab --review-issued --where "name:testioc" --all --yes    # the whole batch
admin lab -R "${LAB}:0123456789"                                # one known certificate
```

Only certificates that can actually be revoked are offered. The rest are listed with the
reason and never asked about - a status outside `PENDING_APPROVAL`, `PENDING` and `VALID`,
and your own certificate, which you may not revoke:

```sh
admin lab --review-issued --where "state:VALID" < /dev/null
#     Not offered    : status REVOKED cannot be revoked
#     Not offered    : this is your own certificate, which you cannot revoke
```

A failed write does not stop the ones after it, the certificate manager's own message is
shown against the certificate it belongs to, and a partly successful batch exits 5.

## 9. Only an administrator may decide

The administrator write rule names four things, and all of them are load bearing:

```sh
podman exec podman_pvxs-lab-pvacms_1 cat /etc/pvacms/pvacms.acf
#   RULE(1,WRITE) {
#       UAG(CMS_ADMIN)        who
#       AUTHORITY(CMS_AUTH)   issued by this department, not the other one
#       PROTOCOL(TLS)         over a secure transport, not plain
#       METHOD("x509")        having actually presented a certificate
#   }
```

An ordinary user is refused a decision:

```sh
podman exec podman_lab-client_1 bash -lc \
  "source ~/.guest_bashrc; pvxput CERT:STATUS:${LAB}:0123456789 state=REVOKED"
#   ERROR ... REVOKED operation not authorized ... by ca/guest@...
```

`ca/guest` is the whole explanation: the connection presented no certificate, so the rule
could not match however the user is named.

The view of certificates **awaiting a decision** is gated the same way, at channel
creation:

```sh
podman exec podman_lab-client_1 bash -lc "source ~/.guest_bashrc; pvxmonitor CERT:LIST:${LAB}:PENDING_APPROVAL"
#   Server ... refuses channel to 'CERT:LIST:ba71d9e3:PENDING_APPROVAL' : Refused to create Channel
```

while the open views are served to the same user without complaint:

```sh
podman exec podman_lab-client_1 bash -lc "source ~/.guest_bashrc; pvxmonitor CERT:LIST:${LAB}:ALL"
```

Neither gateway forwards the awaiting-decision view or a certificate status write, because
a gateway makes its upstream connection as itself and the certificate manager would see
the gateway rather than the administrator behind it. Decisions are made from inside the
department.

## The layout

| Service | Network(s) | What it is |
|---|---|---|
| `pvxs-lab-pvacms` | lab | the lab department's certificate manager |
| `pvxs-lab-testioc`, `pvxs-lab-tstioc` | lab | lab controllers, serving `test:` and `tst:` |
| `pvxs-lab-gateway` | lab + perimeter | the lab boundary |
| `pvxs-lab-ml` | ml | the machine learning certificate manager |
| `pvxs-lab-ml-ioc` | ml | its controller, serving `ml:` |
| `pvxs-lab-ml-gateway` | ml + perimeter | its boundary |
| `lab-client` | lab + perimeter | a shell in the lab department, able to reach the other department's gateway |
| `perimeter-client` | perimeter | a shell outside both |

Service names are the DNS names, and they match the names used in the shell profiles and
gateway configuration inside the images, so nothing needs rewriting per environment.

Configuration worth reading:

- `config/pvacms-lab.acf`, `config/pvacms-ml.acf` - each certificate manager's access rules
- `config/gateway-lab.pvlist`, `config/gateway-ml.pvlist` - what each gateway forwards
- `config/gateway-lab.conf`, `config/gateway-ml.conf` - each gateway's own configuration

## Troubleshooting

**Nothing crosses a boundary.** Restart the two gateways. One that started before the
controllers were serving does not retry.

```sh
podman-compose restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

**Containers vanish when you log out.** `loginctl enable-linger "$USER"`, then bring them
up again. Rootless containers are killed with your last session otherwise.

**`authnstd` says there is no trusted issuer.** The department's issuer id has not reached
the shell. A login shell resets the environment; the start scripts write it to
`/etc/epics/issuer` for the profile in the image to read back. Check it:

```sh
podman exec podman_pvxs-lab-testioc_1 cat /etc/epics/issuer
```

**A decision is refused as `ca/<user>`.** The connection presented no certificate. Export
`EPICS_PVA_TLS_KEYCHAIN` and address the manager over the secure port, as the `admin`
function above does.

**A certificate is issued but cannot be saved.** The keychain directory is not writable by
the user. The start scripts take ownership of it; if you added a service, do the same.

**The build is killed.** Too many compiler processes for the memory available. Use
`JOBS=2` and add swap.

## Starting over

```sh
podman-compose down -v      # removes volumes, including every issued certificate
./bootstrap.sh              # fresh authorities
./bootstrap.sh --keep-certs # rebuild images, keep the certificates
```
