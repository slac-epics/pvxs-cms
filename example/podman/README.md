# Secure PVAccess demonstration laboratory, on podman

A two-department Secure PVAccess laboratory that runs on rootless podman with
`podman-compose`.

Everything here is exercised from the command line, where every property worth
demonstrating can be shown and checked directly.

## Contents

- [What it demonstrates](#what-it-demonstrates)
- [Topology](#topology)
- [Installation](#installation)
- [Bringing it up](#bringing-it-up)
- [Say it once: where, and who](#say-it-once-where-and-who)
- [What works with no certificates at all](#first-what-works-with-no-certificates-at-all)
- [1. Two certificate managers, one per department](#1-two-certificate-managers-one-per-department)
  - [Naming an authority](#naming-an-authority)
- [2. Crossing a boundary is only possible through a gateway](#2-crossing-a-boundary-is-only-possible-through-a-gateway)
- [3. What a certificate is worth, one step at a time](#3-what-a-certificate-is-worth-one-step-at-a-time)
- [4. One facility root, so each department trusts the other's certificates](#4-one-facility-root-so-each-department-trusts-the-others-certificates)
  - [Narrowing a write to a unit, not a department](#narrowing-a-write-to-a-unit-not-a-department)
- [5. The request identifier an administrator checks](#5-the-request-identifier-an-administrator-checks)
- [6. Listing certificates](#6-listing-certificates)
- [7. Filtering the listing](#7-filtering-the-listing)
- [8. Approving, in batches or one at a time](#8-approving-in-batches-or-one-at-a-time)
- [9. Denying and revoking](#9-denying-and-revoking)
- [10. Revoking the authority itself](#10-revoking-the-authority-itself)
  - [When the responder cannot be reached](#when-the-responder-cannot-be-reached)
- [11. Only an administrator may decide](#11-only-an-administrator-may-decide)
- [Resetting between demonstrations](#resetting-between-demonstrations)
- [Troubleshooting](#troubleshooting)

## What it demonstrates

| | |
|---|---|
| **Two departments** | Each runs its own certificate manager, signing with its own intermediate certificate authority, holding only the certificates it issued |
| **One facility root** | Both intermediates are signed by it, so a certificate from either department is trusted laboratory-wide, while authorisation stays per department |
| **Real network separation** | Three podman networks; a container reaches only those it is attached to, so a department's certificate manager is addressable only from inside it |
| **Gateways on the boundary** | The only route between departments. Each forwards its own department's controller process variables, and its certificate traffic keyed by issuer id |
| **Administration** | Listing, filtering, request identifiers, approval in batches or one at a time, denial and revocation, all restricted to administrators |
| **Revoking the authority** | The root names a responder that publishes its own revocation, and every certificate beneath a revoked root reports a state that says so rather than claiming its own revocation |

## Topology

Every component of the laboratory, on one map: the three networks, the two gateways, the
controllers, the certificate managers, the certificate authorities with their issuer
identifiers, the responder for the facility root, and the full text of every access
security file and gateway process variable list.

![The demonstration laboratory: the lab and machine learning zones side by side, the
perimeter and the certificate authorities between them, and every access file attached to
the component that loads it](topology-infographic.svg)

The picture is wide. Open it in its own tab and zoom: every access rule and process
variable list is readable at full size.

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

**If you built before pulling**, rebuild the images. The process variables and the access
rules live inside them, so a pull on its own leaves a controller serving the old set and the
examples below timing out:

```sh
git pull && JOBS=2 ./bootstrap.sh --keep-certs && ./reset.sh
```

That keeps the certificate authorities, so the issuer ids you already noted still apply.

`bootstrap.sh` writes `.env` and `issuer_ids.env`, holding the two departments' issuer ids.

### Say it once: where, and who

Every command below runs inside a container, as a particular account, and both facts are
the point of the demonstration. Rather than repeat a long `podman exec` line each time,
source the shorthands once:

```sh
source ./helpers.sh
```

That defines `run_in`, and reads the two issuer ids into `$LAB` and `$ML`:

```
run_in <place> as <person> [without a certificate] [--show] <command...>
```

| Place | Is |
|---|---|
| `lab`, `ml` | a workstation inside a department |
| `perimeter` | a workstation outside both, reaching only the two gateways |
| `lab-manager`, `ml-manager` | a department's certificate manager |
| `testioc`, `tstioc`, `ml-ioc` | a controller |
| `gateway`, `ml-gateway` | a department's boundary |

The people are real accounts on those machines: `guest` and `operator` on a workstation,
`admin` on a certificate manager, and a service's own account such as `testioc` or
`gateway`. So `run_in lab as guest pvxget test:aiExample` reads as what it does.

Nothing is hidden. Any command can print the `podman exec` line it stands for instead of
running it, which is also how to lift one of these examples into a real deployment:

```sh
run_in lab as guest --show pvxget test:aiExample
#   podman exec --user guest podman_lab-client_1 bash -lc '...'
```

**With no command, it opens a shell there.** You land as that person, with everything set up
that a command would have had, and a prompt saying who and where you are:

```sh
run_in lab-manager as admin
#   [admin@lab-manager] > pvxcert -l
#   [admin@lab-manager] > exit
```

That is how to answer anything that asks a question, since those read their answers from a
terminal, and how to try a few things without writing `run_in` in front of each. Pass the
command as arguments instead when scripting: piping into a shell will not do, because a
terminal never reaches the end of its input.

`run_in` on its own lists the places and people; `lab_status` shows what is running.
`authority_says` reports what the facility root's responder says about the root, and
`authority_revoke`, `authority_restore`, `authority_unreachable` and `authority_reachable`
change it; section 10 is what they are for.

### First, what works with no certificates at all

Before any certificate exists, the laboratory is already running and readable. This is the
baseline to come back to when something later looks broken.

**Reading works everywhere, over plain TCP, with no certificate.** Inside a department:

```sh
run_in lab as guest without a certificate pvxget test:aiExample
```

In the peer department, through its gateway:

```sh
run_in lab as guest without a certificate pvxget ml:aiExample
run_in ml  as guest without a certificate pvxget test:aiExample
```

And from outside both departments, through a gateway either way:

```sh
run_in perimeter as guest without a certificate pvxget test:aiExample
run_in perimeter as guest without a certificate pvxget ml:aiExample
```

Read is deliberately open, to anyone, in any zone. Certificates are not about hiding
readings.

**Writing is refused, whatever you write to.** Every write rule in the laboratory names
`PROTOCOL(TLS)` and `METHOD(X509)`, so with no certificate nothing is writable anywhere:

```sh
# from inside the department: the request reaches the controller, which refuses it
run_in lab as guest without a certificate pvxput test:stringExample "hello"
#   ERROR ... Put not permitted

# from the peer department: stopped at the lab's boundary, before reaching the controller
run_in ml as guest without a certificate pvxput test:stringExample "hello"
#   ERROR ... Put permission denied by gateway

# from outside both departments: stopped at that same boundary
run_in perimeter as guest without a certificate pvxput test:stringExample "hello"
#   ERROR ... Put permission denied by gateway
```

The two messages come from two different places, and which one you get says how far the
request travelled. The first reached the controller, which applied its own access file. The
other two never left the boundary: the gateway refused them there, whether the request came
from the peer department or from outside both.

So: reading needs nothing, writing needs an identity. Section 3 returns to `test:spec` and
writes it successfully with a certificate issued by the *other* department.

### Issue the certificates

Nothing holds a certificate yet. Each service asks its **own** department, and that
department's administrator approves.

```sh
# controllers ask
run_in testioc as testioc authnstd -u ioc
run_in tstioc  as tstioc  authnstd -u ioc
run_in ml-ioc  as mlioc   authnstd -u ioc

# each department approves its own
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
run_in ml-manager  as admin pvxcert --review-pending --all approve --yes

# gateways last, and they need approving too
run_in gateway    as gateway authnstd -u ioc
run_in ml-gateway as gateway authnstd -u ioc -n ml-gateway
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
run_in ml-manager  as admin pvxcert --review-pending --all approve --yes
```

Most of the people need them too. Everything from section 3 onwards is about what a
certificate is worth to the person holding it, and none of it means anything until they
hold one. Each asks the department it belongs to, and two of them carry the unit their
department knows them by, which section 4 turns on:

```sh
run_in lab       as operator    authnstd -u client --ou lab --issuer ${LAB_SKID}
run_in ml        as guest       authnstd -u client
run_in perimeter as operator    authnstd -u client --issuer ${ML_SKID}
run_in lab       as ml/operator authnstd -u client --ou ml  --issuer ${ML_SKID}

run_in lab-manager as admin pvxcert --review-pending --all approve --yes
run_in ml-manager  as admin pvxcert --review-pending --all approve --yes
```

Two are deliberately left without one, and each is used later for something only someone
without one can show. The lab guest asks in the next section, where a keychain that already
held a certificate would answer before the point about naming an authority could be made.
The perimeter guest waits until section 5, where its request is the one still undecided.

Check they all arrived before going on. Each department lists only what it issued, and each
listing also holds three the department made for itself: its own authority, its certificate
manager's, and its administrator's. A gateway without a certificate refuses every write on
the boundary, which looks like a broken rule rather than a missing certificate:

```sh
run_in lab-manager as admin pvxcert -l --where "state:VALID"
run_in ml-manager  as admin pvxcert -l --where "state:VALID"
```

Note that the administrator is `run_in lab-manager`, not `run_in lab`. That identity lives
beside the certificate manager and is presented to it over the secure port on the same
machine; a workstation in the lab department is a different place, with different accounts.
Run the same listing as `admin` and as `guest` to see what the identity is worth.

**Then restart the controllers, and after them the gateways.** Order matters, and both
steps are needed:

```sh
podman-compose restart pvxs-lab-testioc pvxs-lab-tstioc pvxs-lab-ml-ioc
podman-compose restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

A controller reads its keychain at start, and it was already running when the certificate
arrived, so until it restarts it serves plain traffic only - it listens on 5075 and not on
the secure port:

```sh
run_in testioc as testioc ss -lnt | grep 507
#   before: *:5075          after: *:5075 and *:5076
```

The gateways go second because a gateway that starts before its department is serving does
not retry, and restarting the controllers is exactly such a moment. Restart them in the
other order and nothing crosses a boundary.

---

## 1. Two certificate managers, one per department

They are independent. Each holds only what it issued, and neither knows about the other's
certificates.

```sh
run_in lab-manager as admin pvxcert -l
run_in ml-manager  as admin pvxcert -l
```

The certificate identifiers make it plain: everything the first lists begins with
`$LAB`, everything the second lists begins with `$ML`. The issuer half of an
`<issuer>:<serial>` identifier says which department to ask about a certificate.

Which department a service asks is decided by where it runs, not by which manager answers
first. Each container is given the whole identifier of the authority its department trusts,
which is forty digits, because on a first request there is nothing yet to check a delivered
authority against and only the whole identifier decides it:

```sh
run_in testioc as testioc printenv EPICS_PVA_AUTH_ISSUER   # lab
run_in ml-ioc  as mlioc   printenv EPICS_PVA_AUTH_ISSUER   # machine learning
```

### Naming an authority

The `$LAB` and `$ML` above are the first eight digits of those, which is what a process
variable name can carry. The whole forty is what the certificate holds, and that is what you
see if you read it:

```sh
run_in lab-manager as idm bash -c \
  "openssl pkcs12 -in /certs/lab_intermediate.p12 -passin pass: -nokeys \
   | openssl x509 -noout -ext subjectKeyIdentifier"
#   53:E8:04:2C:F6:8B:D9:A0:BA:C0:A0:89:85:AB:47:BF:0F:BB:EB:D0
```

> **Every identifier printed in this document came from one run.** Each laboratory mints its
> own authorities, and mints them again on `./reset.sh --authorities`, so yours are different.
> Where a command has to carry one, it is written `${LAB}` or `${LAB_SKID}`, which `lab_ids`
> fills in from the laboratory in front of you. Where a certificate has to be named, take the
> identifier from the listing rather than from here.

All of these are the same authority written four ways, and all four are understood
wherever an authority is named. Separators are dropped and capitals folded:

```sh
run_in lab-manager as admin pvxcert -l --where "issuer:${LAB}"
run_in lab-manager as admin pvxcert -l --where "issuer:$(echo ${LAB} | tr a-z A-Z)"
run_in lab-manager as admin pvxcert -l --where "issuer:${LAB_SKID}"
run_in lab-manager as admin pvxcert -l --where "issuer:'53:E8:04:2C:F6:8B:D9:A0:BA:C0:A0:89:85:AB:47:BF:0F:BB:EB:D0'"
```

The last is the colon form, and is the one place here you would substitute your own: it is
`${LAB_SKID}` with a colon between each pair of digits.

The colon form needs quoting in a filter, because a bare colon is what separates the field
from the value. Everywhere else it can be written as it comes.

Something that is not an identifier at all, or is too short to name an authority, is refused
rather than turned into a name nothing answers:

```sh
run_in lab as guest authnstd -u client --issuer 53e80
#   '53e80' is too short to name a certificate authority: at least 8 hexadecimal digits are needed
```

How much of it is needed depends on what it is for. Naming takes as little as the eight
digits; deciding what to trust takes all of it.

**The whole identifier is required when nothing is trusted yet, and refused otherwise.**
Eight digits is thirty-two bits, and a key whose identifier begins with any wanted
thirty-two bits takes hours to generate on one processor core, so the short form names an
authority conveniently but cannot establish that it is the right one:

```sh
run_in lab as guest authnstd -u client --issuer ${LAB}
#   The issuer '<yours>' is only 8 of the 40 digits of a subject key identifier, which is
#   not enough to decide which certificate authority to trust ...
run_in lab as guest authnstd -u client --issuer ${LAB_SKID}      # accepted
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

That last one is a request like any other, and it waits for a decision, so it is approved
here: from section 3 on, the lab guest is someone who holds a certificate.

Once a keychain holds an authority, that pinned authority is what a delivered one is
compared against, and the short form is accepted again for naming. Certificate identifiers
keep the eight-digit form throughout, because that is what a process variable name carries.

`helpers.sh` gives you both: `$LAB` and `$ML` are the naming form, `$LAB_SKID` and `$ML_SKID`
the whole one. The certificate manager prints both when it starts:

```
| Issuer ID                             : 53e8042c
| Issuer SKID                           : 53e8042cf68bd9a0bac0a08985ab47bf0fbbebd0
```

## 2. Crossing a boundary is only possible through a gateway

Inside a department, a client talks to its controllers directly:

```sh
run_in lab as guest pvxget test:aiExample
```

From outside both departments, the same read has to cross a gateway, and does:

```sh
run_in perimeter as guest pvxget test:aiExample
run_in perimeter as guest pvxget ml:aiExample
```

And a lab client reaching the other department goes through that department's gateway:

```sh
run_in lab as guest pvxget ml:aiExample
```

A gateway is the only route. Every direct approach is refused:

```sh
run_in lab       as guest getent hosts pvxs-lab-ml        # other department's manager
run_in lab       as guest getent hosts pvxs-lab-ml-ioc    # other department's controller
run_in perimeter as guest getent hosts pvxs-lab-pvacms    # a certificate manager
run_in perimeter as guest getent hosts pvxs-lab-ml
```

podman enforces the separation itself: a container reaches only the networks it is
attached to. Only the two gateways sit on a department network **and** the perimeter.

What a gateway carries is exactly what its list names - its department's controllers, and
its department's certificate traffic keyed by issuer id:

```sh
run_in gateway as gateway cat /home/gateway/gateway.pvlist
#   test:.* ALLOW                                 its controllers, readable
#   tst:.* ALLOW
#   test:spec ALLOW SPECIAL                       writable, to a certificate from either department
#   test:open ALLOW OPEN_WRITE                    writable, to any certificate at all
#   CERT:CREATE:<lab>(?::.*)? ALLOW CERT_CREATE   ask this department for a certificate
#   CERT:STATUS:<lab>(?::.*)? ALLOW CERT_STATUS   check one it issued
#   CERT:LIST:<lab>:ALL ALLOW CERT_STATUS         the two open views
#   CERT:LIST:<lab>:EXPIRING ALLOW CERT_STATUS
run_in ml-gateway as gateway cat /home/gateway/gateway.pvlist
```

Each names its **own** issuer only, so a request for the other department's certificates is
not claimed by the wrong gateway. The view of certificates awaiting a decision appears in
neither list, for the reason in section 11.

## 3. What a certificate is worth, one step at a time

Access widens in steps, and each step is a separate condition in the access file. Walking
them in order shows what each one buys. All of these run from a lab workstation except where
they say otherwise.

**No certificate: nothing is writable.** That is the baseline above, and it holds for every
process variable, ordinary or special.

**A certificate, in its own department: ordinary variables open up.** The rule for them
names lab guests and operators, so either may write:

```sh
run_in lab as guest    pvxput test:stringExample "from the guest"
run_in lab as operator pvxput test:stringExample "from the operator"
```

**A special variable narrows that to operators.** `test:spec` carries its own access group,
which names operators and not guests, so a guest holding a perfectly good certificate is
still refused:

```sh
run_in lab as guest    pvxput test:spec 11
#   ERROR ... Put not permitted
run_in lab as operator pvxput test:spec 22
```

**From another zone, only what a gateway carries a write for crosses at all.** A gateway's
list marks those individually; everything else it forwards is readable and not writable,
however good the certificate is:

```sh
run_in perimeter as operator pvxput test:stringExample "from outside"
#   ERROR ... Put permission denied by gateway
```

Each department marks one variable that any certificate holder may write, and the two make
the point in both directions. Neither of these people is an operator:

```sh
run_in lab as guest pvxput ml:open   11      # a lab guest, into the machine learning department
run_in ml  as guest pvxput test:open 22      # a machine learning guest, into the lab
```

Who may write them is decided at the **gateway**, not at the controller. A gateway makes its
upstream connection as itself, so what the controller sees is the gateway rather than the
person behind it; the controller's rule therefore names the gateways, and the gateway's rule
is the one that names nobody and asks only for a certificate. Opening the variable up at the
controller does not open it to anyone the gateway would have turned away.

**A variable that crosses may still name who may write it.** `test:spec` is carried across
too, and names operators, so the same guest is refused where an operator is not:

```sh
run_in ml as guest    pvxput test:spec 33
#   ERROR ... Put permission denied by gateway
run_in perimeter as operator pvxput test:spec 33
```

That last write is the one section 4 is about: it came from outside both departments,
holding a certificate the *other* department issued, and it succeeded.

**And a variable may narrow further still, to what the certificate says about its holder.**
That is "Narrowing a write to a unit, not a department", below.

Read is untouched throughout. Every one of these variables can be read by anyone, from
anywhere, with nothing at all.

## 4. One facility root, so each department trusts the other's certificates

This is the point of the whole arrangement, and it is worth walking through.

A client outside both departments holds a certificate from the **machine learning**
department. It asked for that certificate when the others were issued, and it could not
reach that certificate manager to ask: the request travelled through the machine learning
gateway, which is the only way in.

It uses that certificate to write to a **lab** controller, through the **lab** gateway:

```sh
run_in perimeter as operator <<'EOF'
    pvxput test:spec 7
    pvxget test:spec
EOF
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
run_in gateway as gateway cat /home/gateway/gateway.acf
run_in gateway as gateway cat /home/gateway/gateway.pvlist
```

A certificate from the wrong department, or none at all, is refused:

```sh
run_in perimeter as guest pvxput test:spec 9
#   Put permission denied by gateway
```

### Narrowing a write to a unit, not a department

`test:spec` above shows what the shared root buys: either department's operator may write it.
`test:labspec` shows the other half. Its rule authorises on the same shared root, so a
certificate from either department is equally trusted, and then asks what the certificate
says about its holder - only one carrying the lab's own unit may write:

```
UAG(LAB_UNIT) { "OU=lab" }

ASG(LABSPEC) {
    RULE(1,READ)
    RULE(1,WRITE,TRAPWRITE) { UAG(LAB_UNIT) AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }
}
```

Give the lab's operator a certificate that says so, and give the same workstation a
machine-learning operator's certificate to compare against. A person written
`<department>/<user>` is that user holding a certificate from that department rather than from
the one they are sitting in, kept in a keychain of its own:

Both were issued when the certificates were, each carrying its own department's unit:

```sh
run_in lab as operator    authnstd -u client --ou lab --issuer ${LAB_SKID}
run_in lab as ml/operator authnstd -u client --ou ml  --issuer ${ML_SKID}
```

The unit also keeps the two subjects distinct, which is what lets one person hold both: a
certificate manager refuses a second certificate for a subject it has already issued.

Both are trusted by the lab controller, and only one may write:

```sh
run_in lab as operator    pvxput test:labspec 101      # allowed: carries OU=lab
run_in lab as ml/operator pvxput test:labspec 202      # refused: no such unit
#   ERROR ... Put not permitted
run_in lab as ml/operator pvxget test:labspec          # reading is open to both
```

The refusal is on the unit and not on the authority. The machine learning certificate was
verified, its status checked, and its holder found to be someone the rule does not name -
which is what the same operator writing `test:spec` demonstrates by succeeding:

```sh
run_in lab as ml/operator pvxput test:spec 202         # allowed: authorised on the shared root
```

Note what naming a unit does and does not guarantee. The unit is a claim the issuing
department vouched for, so a machine learning certificate asking for `--ou lab` would be
admitted here. A rule that must not be crossed under any circumstances should name the
authority as well; naming only the unit trusts every department sharing the root to issue
that unit honestly.

## 5. The request identifier an administrator checks

The certificate creation request travels in clear text, so an administrator has to be able
to compare what is on screen against what the requester sent. `authnstd` prints an
identifier for the requester to quote:

Someone outside both departments asks the lab for one. They ask as `visitor`, because a
certificate manager will not issue a second certificate for a subject it has already
issued and both departments have a `guest` already:

```sh
run_in perimeter as guest authnstd -u client -n visitor --issuer ${LAB_SKID}
#   email this Certificate Request ID: MM0C-WTSN-YGY2-FGRV, to your SPVA administrator for approval
```

The administrator sees the same identifier, in the same grouping, against the request:

```sh
run_in lab-manager as admin pvxcert --review-pending < /dev/null
#     Subject        : CN=visitor,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : MM0C-WTSN-YGY2-FGRV
```

It is also a column in the listing:

```sh
run_in lab-manager as admin pvxcert -l
```

## 6. Listing certificates

```sh
run_in lab-manager as admin pvxcert -l
```

Every certificate the department has issued, with its type, subject, status, dates and
request identifier. Dates are rendered year first in one fixed-width layout everywhere, so
they sort and compare as plain text.

**An ordinary user can list too, with no certificate at all:**

```sh
run_in lab as guest without a certificate pvxcert -l
```

Both see the same rows - what a department has issued is not a secret, and an operator
wanting to know whether their certificate arrived should not need an administrator. The
difference is the **request identifier**, which is blank for everyone but an administrator:

```sh
run_in lab-manager as admin pvxcert -l                  # a Request column, with identifiers in it
run_in lab as guest without a certificate pvxcert -l    # the same column, empty
```

That identifier is what the requester quotes to prove a request is theirs, so it is shown
only to whoever is deciding.

One row in that listing was issued by nobody: the facility root. Its Type says `ROOT_AUTH`,
and the column that would carry a request identifier says where its standing comes from
instead - `EXTERN`, or `EXTERN OCSP` where the certificate names a responder, which is what
section 10 is about.

```sh
run_in lab-manager as admin pvxcert -l --where "type:ROOT_AUTH"
```

It is listed because of when it expires. Every certificate beneath it stops working the day
it does, so it answers to `--expiring` like anything else, and planning its replacement does
not depend on anyone remembering it is there:

```sh
run_in lab-manager as admin pvxcert -l --expiring 30d
```

It appears in every view it fits and nowhere else. The one it can never appear in is the
view of requests awaiting a decision: nothing that was never requested can be waiting for
anyone to decide about it.

The same listing is served as standing views a client can subscribe to, named by issuer so
that two certificate managers on one network are never ambiguous:

```sh
run_in lab as guest pvxmonitor CERT:LIST:${LAB}:ALL
run_in lab as guest pvxmonitor CERT:LIST:${LAB}:EXPIRING
```

Those two are open to everyone. The third is not - see section 11.

## 7. Filtering the listing

The expression is meant to be sayable aloud.

```sh
run_in lab-manager as admin pvxcert -l --where "name:gateway"
run_in lab-manager as admin pvxcert -l --where "state:VALID"
run_in lab-manager as admin pvxcert -l --where "type:IOC"
run_in lab-manager as admin pvxcert -l --where "name:testioc and state:VALID"
run_in lab-manager as admin pvxcert -l --where "name:testioc or name:tstioc"
run_in lab-manager as admin pvxcert -l --where "expires_before:30d and state:VALID"
run_in lab-manager as admin pvxcert -l --expiring 30d
```

### The syntax, in full

```
expression := term { "or" term }
term       := factor { "and" factor }
factor     := [ "not" ] ( "(" expression ")" | test )
test       := field ":" value { "|" value }
value      := word | "quoted words" | /regular expression/     ( * matches any run )
```

Three rules follow from that, and they are the ones people get wrong:

- **`not` binds tightest, then `and`, then `or`** - the order you would read them aloud.
  `a or b and c` means `a or (b and c)`.
- **Brackets override it.** `(a or b) and c` is a different question, and both are accepted.
- **`|` is not `or`.** It offers alternatives *for one field*: `state:VALID|REVOKED` is one
  test with two acceptable values. A comma is not a separator - `state:VALID,REVOKED` is read
  as a single status of that name and refused.

The fields:

| Field | Matches |
|---|---|
| `id` | the printed `<issuer>:<serial>` identifier |
| `serial` | the serial alone |
| `issuer` | the issuing authority; naming another empties the result without a query |
| `name` | the common name |
| `org`, `unit`, `country` | the rest of the subject; a certificate with several units matches on any one |
| `state` | `VALID`, `PENDING_APPROVAL`, `PENDING`, `EXPIRED`, `REVOKED`, `PENDING_RENEWAL` |
| `type` | `CLIENT`, `SERVER`, `IOC`, `CERT_AUTH`, `UNKNOWN` - the word in the Type column |
| `issued`, `expires`, `renew_by`, `changed` | a date, matching that whole day |
| `..._before`, `..._after` | the same four, taking a date or a period |

Dates are written `2026-07-31`, or `'2026-07-31 10:31:21'` in quotes. A bare date matches
the whole day. Periods are a number and a unit letter - `y` years, `M` months, `w` weeks,
`d` days, `h` hours, `m` minutes, `s` seconds. **`M` is months and `m` is minutes**, and a
period without a unit is refused rather than guessed at.

A `_before` field looks forward from now and an `_after` field looks back, so
`expires_before:30d` is "expires within thirty days" and needs no arithmetic.

Matching ignores case, and `*` is a wildcard. A value in `/slashes/` is a regular
expression. Text that merely looks like a pattern is taken literally, so a common name with
a dot in it does not quietly become a wildcard.

### What it will not do

- **No comparison operators.** There is no `>`, `<` or `!=`. Ranges are expressed with the
  `_before` and `_after` fields, and inequality with `not`.
- **No arithmetic, and no joining one field to another.** Every test compares one field with
  a value you supply.
- **No sorting or field selection.** The listing decides its own columns and order.
- **Limits, refused plainly rather than silently truncated**: 4096 characters, 32 levels of
  brackets, 8 regular expressions in one expression, and 100000 rows examined.

Because dates are fixed width and year first, a partial bound selects by prefix and nothing
needs parsing.

## 8. Approving, in batches or one at a time

There are two separate questions - *what is the decision* and *are you sure* - and `--all`
and `--yes` answer one each. That gives four ways of working, from reading every request to
approving a hundred without being asked anything, and you choose how far to go.

**Neither.** Each certificate in turn, with its subject and its request identifier in front
of you, and a decision for each. The prompts are read from a terminal, so open a shell and
answer them yourself:

```sh
run_in lab-manager as admin
#   [admin@lab-manager] > pvxcert --review-pending
```

```
Compare the request identifier shown below against the one the requester sent you before approving.

[1/2] ba71d9e3:02665075835003669104
  Subject        : CN=guest,O=epics.org,C=US
  Status         : PENDING_APPROVAL
  Request ID     : VY14-FM0S-3HTV-V77Q
  Status changed : 2026-08-06 21:27:38 UTC
  approve / deny / skip / stop / cancel ? approve

[2/2] ba71d9e3:01457147623119291338
  Subject        : CN=operator,O=epics.org,C=US
  Status         : PENDING_APPROVAL
  Request ID     : Y6W7-HZMY-FX8R-R65E
  Status changed : 2026-08-06 21:27:37 UTC
  approve / deny / skip / stop / cancel ? skip

About to change 1 certificate:
  ba71d9e3:02665075835003669104  CN=guest,O=epics.org,C=US
      PENDING_APPROVAL -> VALID  (APPROVE)
  The certificate manager decides the final value for an approval, from the certificate's own dates.

Apply these 1 changes? [y/N]
```

The five answers differ in what they leave behind. `skip` moves on and decides this one
another day; `stop` keeps the decisions made so far and stops asking about the rest;
`cancel` abandons everything, written or not. `a`, `d` and `c` are accepted as shorthand,
but **`s` is refused** - it begins both `skip` and `stop`, and getting those two the wrong
way round is not something to guess at.

**`--all` alone.** One decision for every certificate, without being asked each time - but
still shown what that means, and still asked once:

```sh
run_in lab-manager as admin pvxcert --review-pending --all approve
```

```
About to change 2 certificates:
  ba71d9e3:02665075835003669104  CN=guest,O=epics.org,C=US
      PENDING_APPROVAL -> VALID  (APPROVE)
  ba71d9e3:01457147623119291338  CN=operator,O=epics.org,C=US
      PENDING_APPROVAL -> VALID  (APPROVE)
  The certificate manager decides the final value for an approval, from the certificate's own dates.

Apply these 2 changes? [y/N] n
Cancelled. Nothing was written.
```

Every certificate is named, with the status it holds now and the status it would hold, so
the confirmation is a last chance to read the list rather than a formality. It defaults to
no: pressing return changes nothing.

`--all` here means every certificate awaiting a decision, and a pending review cannot be
narrowed: `--where` applies to `--list` and to `--review-issued`, and asking for it with
`--review-pending` is refused rather than quietly ignored. To approve part of a batch, go
through them one at a time and `skip` the rest.

```sh
run_in lab-manager as admin pvxcert --review-pending --where "name:guest" --all approve
#   Error: --where, --pending and --expiring only apply to --list and --review-issued.
```

**Both.** No questions at all, for a script or a hundred controllers coming up at once:

```sh
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
run_in lab-manager as admin pvxcert --review-pending --all deny --yes
```

This approves without putting a single request identifier in front of anyone, which is the
one thing that identifier exists for. The tool says so rather than assuming you meant it.

Whichever way is used, nothing is written until that final point, and every decided
certificate is re-read just before the write. Any that changed since the listing is dropped
and reported rather than written over.

**One known certificate**, when you already have its identifier:

```sh
run_in lab-manager as admin pvxcert -A "${LAB}:0123456789"      # approve
run_in lab-manager as admin pvxcert -D "${LAB}:0123456789"      # deny
```

With no terminal to read answers from and no `--all`, the listing is printed, nothing is
written, and the exit code is 3 - asking for an interactive run with nothing able to answer
is a command line mistake rather than something to guess at:

```sh
run_in lab-manager as admin pvxcert --review-pending < /dev/null ; echo "exit $?"
#   exit 3
```

With nothing waiting for a decision there is nothing to be mistaken about, so the same
command reports that and exits 0.

## 9. Denying and revoking

A denial is not a separate state: the certificate manager writes `REVOKED`, and the review
shows that before you confirm.

```sh
run_in lab-manager as admin pvxcert --review-pending --all deny --yes
```

Revocation works over the issued certificates, and unlike a pending review it *can* be
narrowed by the filter from section 7. The same three levels of control apply:

```sh
run_in lab-manager as admin pvxcert --review-issued --where "state:VALID"                 # one at a time
run_in lab-manager as admin pvxcert --review-issued --where "name:guest" --all            # decided, still confirmed
run_in lab-manager as admin pvxcert --review-issued --where "name:testioc" --all --yes    # the whole batch
run_in lab-manager as admin pvxcert -R "${LAB}:0123456789"                                # one known certificate
```

That third one stops the controller. A service whose certificate is revoked cannot present
it, so put it back before going on, which is what a site would do having revoked one in
error:

```sh
run_in testioc as testioc authnstd -u ioc --force
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
podman-compose restart pvxs-lab-testioc
```

`--force` is needed because the keychain still holds the revoked certificate, and what is
on disk looks valid: a certificate carries its own dates, not its standing.

The middle one is the useful shape for a revocation: the filter chooses, and the
confirmation shows exactly what was chosen before anything is written.

```
About to change 2 certificates:
  ba71d9e3:02665075835003669104  CN=guest,O=epics.org,C=US
      PENDING_APPROVAL -> REVOKED  (REVOKE)
  ba71d9e3:15096909679183656442  CN=guest,O=lab-client,C=US
      VALID -> REVOKED  (REVOKE)

Revoke these 2 certificates? [y/N] n
Cancelled. Nothing was written.
```

Note the wording and the answers change with the job: revoking offers
`revoke / skip / stop / cancel`, with no `approve` or `deny` to pick the wrong one of.
A certificate awaiting a decision can be revoked outright, without being approved first.

Only certificates that can actually be revoked are offered. The rest are listed with the
reason and never asked about - a status outside `PENDING_APPROVAL`, `PENDING` and `VALID`:

```sh
run_in lab-manager as admin pvxcert --review-issued < /dev/null
#     Not offered    : status REVOKED cannot be revoked
```

Without a filter, because one that selects only what can be revoked has nothing to leave out.

**An ordinary user may revoke their own certificate, and that is the point of it for them.**
A key has leaked and they want it stopped now, without finding an administrator first:

```sh
run_in lab-manager as admin pvxcert -l --where "name:guest and state:VALID"   # its identifier
run_in lab as guest pvxcert -R "${LAB}:<the serial that listing shows>"
#   Revoke ==> CERT:STATUS:<that identifier> ==> Completed Successfully
```

That leaves them without one, so they ask again, which is what anyone would do having
stopped a key they no longer trust:

```sh
run_in lab as guest authnstd -u client --issuer ${LAB_SKID} --force
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

They may revoke that one and no other. Someone else's is refused, and the message names the
identity the certificate manager saw rather than the certificate:

```sh
run_in lab as guest pvxcert -R "${LAB}:<a controller's serial>"
#   ERR ... REVOKED operation not authorized on <that identifier> by
#   TLS x509:<issuer>:<serial>:EPICS Root Certificate Authority -> EPICS Controls
#   Intermediate CA/guest@...
```

The one identity this runs the other way for is the administrator's own certificate. A
certificate manager refuses that, because it is the identity it needs in order to keep
answering at all. The tool cannot tell an administrator's keychain from anyone else's - the
listing looks the same for both - so it offers the certificate like any other and reports
what the manager says:

```sh
run_in lab-manager as admin pvxcert -R "${LAB}:<the admin's own serial>"
#   ERR ... REVOKED Admin Self-Revoke not permitted on <that identifier> by ...
```

A failed write does not stop the ones after it, the certificate manager's own message is
shown against the certificate it belongs to, and a partly successful batch exits 5.

## 10. Revoking the authority itself

Everything so far revokes a certificate the laboratory issued, and the holder learns of it on
the status channel that certificate names. The facility root has no such channel. It is the
thing every node is configured to trust, so an answer about it carried over a connection it
underwrites would be worth nothing, and nothing subscribes to it in any case.

So the root says where its own revocation can be learned. It carries the address of a
responder, and each department's certificate manager asks that responder whether the root
still stands:

```sh
openssl x509 -in certs/ocsp_ca.pem -noout -text | grep -A 1 "Authority Information"
#   Authority Information Access:
#       OCSP - URI:http://pvxs-lab-authority-status:8888
```

That responder is the eleventh service in the laboratory. It sits on both departmental
networks, because both managers chain to the same root, and it signs with a certificate the
root authorised for the purpose, so the root's own key is not on it.

Start from a working laboratory, with certificates issued and a write that succeeds:

```sh
authority_says
#   the facility root stands
```

Now revoke the root, as its own authority would:

```sh
authority_revoke
#   the facility root is REVOKED
```

The certificate managers ask again when the answer they hold lapses. The responder states how
long that is, and the laboratory's says one minute, so allow one before asking. From then on
every certificate beneath the root is answered differently. Ask for one certificate's status,
by the identifier the listing shows:

```sh
run_in lab as guest pvxcert "${LAB}:02665075835003669104"
#   Status        : AUTHORITY_REVOKED
```

That state is not `REVOKED`, and the difference is the point of it. The holder's own
certificate is untouched: it has not been revoked, it has not expired, and asking for a
replacement would achieve nothing, because a replacement would be issued by the same
authority. The certificate cannot be used, and the reason lies above it.

A certificate that cannot be used is not presented, and the write does not go through:

```sh
run_in lab as guest pvxput test:aiExample 42
#   Timeout
```

What it says depends on how far the client gets. If it can still be told about its own
certificate it is refused for want of an identity, and if it cannot be told anything at all
- which is the usual case here, since the certificate manager's own certificate is under the
same root - nothing answers and it times out. Either way nothing is written, and reading the
variable back shows the value it had.

Administration stops with it, and that is worth seeing rather than working around. An
administrator's certificate was issued under the same root, so it is no more usable than
anyone else's, and the listing does not answer at all:

```sh
run_in lab-manager as admin pvxcert -l
#   ERR ... Timed out listing certificates from CERT:LIST
```

Revoking a facility root is not a way to withdraw one department or one holder. It stops
everyone who chains to it, including the people who would undo it, which is why it is the last
thing a facility does and why what it takes to undo it is a file and a restart rather than a
certificate operation.

Putting the root back is enough to put the laboratory back:

```sh
authority_restore
#   the facility root stands

run_in lab as guest pvxcert "${LAB}:02665075835003669104"
#   Status        : VALID
```

Nothing was repaired to achieve that. The listing shows what it showed before, because no
certificate was ever changed: what changed was above them, and it is read afresh each time a
status is answered rather than recorded against anything.

```sh
run_in lab-manager as admin pvxcert -l --where "name:guest"
#   7fdcbdea:15880246427277860638  CLIENT  CN=guest,O=epics.org,C=US  VALID  ...
```

### When the responder cannot be reached

A responder is a web service, and a web service can be down. That is a different fact from a
revoked authority: the root may be perfectly good and simply not answering for itself.

```sh
authority_unreachable
#   the responder is stopped; nothing can be learned about the root
```

A certificate manager that cannot check its own authority does not assume the answer. It
notices when the answer it holds lapses, which here is up to the minute the responder asked
for, and from then on it retries every fifteen seconds. Until one succeeds it reports what
it actually knows, which is nothing:

```sh
run_in lab as guest pvxcert "${LAB}:02665075835003669104"
#   Status        : UNKNOWN
```

Connections refuse, exactly as they do for any status a client cannot establish. This is the
laboratory failing closed, and it is a choice rather than a consequence: a facility that
cannot check its authority stops, rather than continuing on an assumption.

A site that would rather stay up sets `EPICS_PVACMS_AUTHORITY_HOLD_LAST_KNOWN=YES` on its
certificate managers, and an unreachable responder then leaves them serving the last answer
they verified. The trade is stated plainly: an outage of one web service no longer takes the
facility with it, and a revocation issued during that outage is not seen until it ends.

Put the responder back and the managers pick it up on one of those retries, within fifteen
seconds:

```sh
authority_reachable
#   the responder is running again
#   the facility root stands
```

## 11. Only an administrator may decide

The administrator write rule names four things, and all of them are load bearing:

```sh
run_in lab-manager as idm cat /etc/pvacms/pvacms.acf
#   RULE(1,WRITE) {
#       UAG(CMS_ADMIN)        who
#       AUTHORITY(CMS_AUTH)   issued by this department, not the other one
#       PROTOCOL(TLS)         over a secure transport, not plain
#       METHOD("x509")        having actually presented a certificate
#   }
```

An ordinary user may look at everything and decide nothing. The same review command run
both ways shows exactly where the line falls. Section 9 decided the last request there was,
so ask for one again first:

It asks under a name nobody has been issued yet, because whether the visitor from section 5
still holds a certificate depends on which of section 8's two endings you ran, and a subject
that already has one cannot ask again:

```sh
run_in perimeter as guest authnstd -u client -n reviewer --issuer ${LAB_SKID} --force

run_in lab-manager as admin pvxcert --review-pending < /dev/null
#     Subject        : CN=reviewer,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : 2JSQ-NJFE-JPFF-732Z

run_in lab as guest without a certificate pvxcert --review-pending < /dev/null
#     Subject        : CN=reviewer,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : (none)
```

The certificate awaiting a decision is visible to both. The identifier that would let
someone confirm it is the request they were sent is not. And an attempt to act is refused
outright:

```sh
run_in lab as guest without a certificate pvxcert --review-issued --where "state:VALID" --all --yes
#   ... FAILED: REVOKED operation not authorized on <identifier> by ca/guest@...

run_in lab as guest without a certificate pvxput CERT:STATUS:${LAB}:0123456789 state=REVOKED
#   ERROR ... REVOKED operation not authorized ... by ca/guest@...
```

`ca/guest` is the whole explanation: the connection presented no certificate, so the rule
could not match however the user is named.

The view of certificates **awaiting a decision** is gated the same way, at channel
creation:

```sh
run_in lab as guest pvxmonitor CERT:LIST:${LAB}:PENDING_APPROVAL
#   Server ... refuses channel to 'CERT:LIST:ba71d9e3:PENDING_APPROVAL' : Refused to create Channel
```

while the open views are served to the same user without complaint:

```sh
run_in lab as guest pvxmonitor CERT:LIST:${LAB}:ALL
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

**`authnstd` says there is no trusted issuer.** The whole identifier of the department's
authority has not reached the shell. A login shell resets the environment; the start scripts
write it to `/etc/epics/issuer` for the profile in the image to read back, and it is the
forty-digit form, because that is what a first request needs. Check it:

```sh
run_in testioc as testioc cat /etc/epics/issuer
```

**A decision is refused as `ca/<user>`.** The connection presented no certificate. A
keychain has to be named and the manager addressed over its secure port, which is what
`run_in lab-manager as admin` sets up - run it with `--show` to see exactly what it sets.

**A certificate is issued but cannot be saved.** The keychain directory is not writable by
the user. The start scripts take ownership of it; if you added a service, do the same.

**The build is killed.** Too many compiler processes for the memory available. Use
`JOBS=2` and add swap.

## Resetting between demonstrations

To run the demonstration again from the top, put the laboratory back to the state it is in
immediately after a build:

```sh
./reset.sh
```

That discards every certificate the laboratory has issued and every keychain the services
hold, keeps the two departmental certificate authorities so the issuer ids stay the same,
brings everything back up, and restarts the gateways last so the boundaries work. It takes
about half a minute.

Afterwards each certificate manager holds only what it creates for itself - its own service
certificate, its administrator identity, and its intermediate authority - and no controller,
gateway or client holds anything:

```sh
run_in testioc as testioc ls /home/testioc/.config/pva/1.5/    # empty
```

Reading still works from everywhere, and writing is refused everywhere, which is exactly
where [the baseline section](#first-what-works-with-no-certificates-at-all) starts.

To mint new certificate authorities as well, which changes the issuer ids:

```sh
./reset.sh --authorities
```

That takes about a minute and a half. It builds nothing: the images do not depend on which
authorities exist, so there is nothing about them to rebuild.

To rebuild the images without discarding anything:

```sh
./bootstrap.sh --keep-certs
```

To mint the authorities without rebuilding anything, which is what the reset above uses:

```sh
./bootstrap.sh --certs-only
```
