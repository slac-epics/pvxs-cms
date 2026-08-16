# Secure PVAccess demonstration laboratory

## Contents

- [What it demonstrates](#what-it-demonstrates)
- [The four laboratories](#the-four-laboratories)
- [Installation](#installation)
- [Bringing one up](#bringing-one-up)

**[Part 1 - simple](#part-1---simple)**
- [1. What a certificate is worth, one step at a time](#1-what-a-certificate-is-worth-one-step-at-a-time)
- [2. The request identifier an administrator checks](#2-the-request-identifier-an-administrator-checks)
- [3. Listing certificates](#3-listing-certificates)
- [4. Only an administrator may decide](#4-only-an-administrator-may-decide)

**[Part 2 - simple, with a gateway](#part-2---simple-with-a-gateway)**
- [5. Reaching the laboratory from outside it](#5-reaching-the-laboratory-from-outside-it)
- [6. Who the controller thinks you are](#6-who-the-controller-thinks-you-are)

**[Part 3 - federated, one facility root](#part-3---federated-one-facility-root)**
- [One address for the facility, and the port says which department](#one-address-for-the-facility-and-the-port-says-which-department)
- [First, what works with no certificates at all](#first-what-works-with-no-certificates-at-all)
- [7. Two certificate managers, one per department](#7-two-certificate-managers-one-per-department)
- [Issue the certificates](#issue-the-certificates)
- [8. One facility root, so each department trusts the other's certificates](#8-one-facility-root-so-each-department-trusts-the-others-certificates)
- [9. A certificate is revoked where it was issued](#9-a-certificate-is-revoked-where-it-was-issued)
- [10. Revoking the authority itself](#10-revoking-the-authority-itself)

**[Part 4 - federated, two independent roots](#part-4---federated-two-independent-roots)**
- [11. Filtering the listing](#11-filtering-the-listing)

**[Reference](#reference)**
- [The layout](#the-layout)
- [Troubleshooting](#troubleshooting)
- [Resetting between demonstrations](#resetting-between-demonstrations)

## What it demonstrates

| | |
|---|---|
| **Two departments** | Each runs its own certificate manager, signing with its own intermediate certificate authority, holding only the certificates it issued |
| **One facility root** | Both intermediates are signed by it, so a certificate from either department is trusted laboratory-wide, while authorisation stays per department |
| **Real network separation** | Up to five podman networks, each isolated from the others, so a department's certificate manager cannot be reached from outside it even by address - and discovery and name resolution stop at a segment too |
| **Gateways on the boundary** | The only route between departments, enforced rather than configured. Each forwards its own department's controller process variables, and its certificate traffic keyed by issuer id |
| **Administration** | Listing, filtering, request identifiers, approval in batches or one at a time, denial and revocation, all restricted to administrators |
| **Revoking the authority** | The root names a responder that publishes its own revocation, and every certificate beneath a revoked root reports a state that says so rather than claiming its own revocation |

## The four laboratories

This example builds four laboratories from the same images. Each one is drawn, each has a part
of the walkthrough to itself, and no test appears twice: a walkthrough lives with the smallest
laboratory that can show it.

| laboratory | walkthrough | what it is |
|---|---|---|
| [`simple`](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-simple.svg) | Part 1 | One segment, one self-signed authority, no boundary to cross |
| [`simple-with-gateway`](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-simple-with-gateway.svg) | Part 2 | One laboratory, published at a facility address and reached through a gateway |
| [`federated-shared-root`](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-federated-shared-root.svg) | Part 3 | Two departments under one facility root, with a responder answering for it |
| [`federated-non-shared-root`](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-federated-non-shared-root.svg) | Part 4 | Two departments under two independent roots, every keychain trusting both |

Each picture is one map of its laboratory: every segment, every appliance, the certificate
authorities with their issuer identifiers, and the full text of every access security file and
gateway process variable list. They are wide. Click one to open the raw file, which the browser
renders full size and zoomable, and every rule is readable there.

<!-- These are absolute raw.githubusercontent.com addresses: GitHub's in-page navigation fails
on a relative link with ?raw=true, showing an error page instead of following the redirect.
Absolute means the branch is hardcoded - update it here when this work moves off
scratch/fy26-four-topologies. -->

**Three of the four are built today**, all but `federated-non-shared-root`. That one is drawn,
and `./reset.sh` says so and stops when you name it. What building it needs is written at the
top of `topologies/federated-non-shared-root/compose.yaml`.

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
B=scratch/fy26-four-topologies
git clone -b $B --recurse-submodules https://github.com/slac-epics/pvxs-cms.git       pvxs-cms
git clone -b $B --recurse-submodules https://github.com/slac-epics/pvxs-tls.git       pvxs
git clone -b $B --recurse-submodules https://github.com/slac-epics/epics-base-tls.git epics-base
git clone -b $B --recurse-submodules https://github.com/slac-epics/p4p-tls.git        p4p
```

## Bringing one up

Two steps, and they do different things. `bootstrap.sh` builds the images, which is slow and
done once. `reset.sh` builds a laboratory out of them, which takes a minute or two and is done
whenever you want a different one or a clean one:

```sh
cd ~/slac/pvxs-cms/example/podman
./bootstrap.sh                        # builds the images; mints nothing
./reset.sh                            # lists the four and says what each is
./reset.sh federated-shared-root      # brings that one up, and checks it before handing it back
```

The image build compiles EPICS Base, pvxs, pvxs-cms and p4p from source and takes a while. On a
machine with little memory, lower the compiler parallelism and make sure there is swap:

```sh
JOBS=2 ./bootstrap.sh
```

**If you built before pulling**, rebuild the images. The process variables and the access rules
live inside them, so a pull on its own leaves a controller serving the old set and the examples
below timing out:

```sh
git pull && JOBS=2 ./bootstrap.sh && ./reset.sh federated-shared-root
```

Certificate authorities belong to a laboratory rather than to the images, so `reset.sh` mints
them into `topologies/<name>/`, and keeps the ones already there unless you ask for new ones
with `--authorities`. It writes the issuer ids where compose and `helpers.sh` each read them.

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

---

# Part 1 - simple

One segment, one self-signed authority held by the certificate manager, two controllers and a
workstation. Nothing crosses a boundary because there is no boundary, which is what makes it
the place to see what a certificate is worth on its own, before a gateway or a second
department is in the way.

```sh
./reset.sh simple
```

[![The simple laboratory: one segment carrying a certificate manager, two controllers and a workstation, and one self-signed authority beside it](topology/topology-simple.svg)](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-simple.svg)

The picture is wide. Click it to open the raw file, which the browser renders full size and
zoomable: every access rule and process variable list is readable there.

Nothing is minted for this laboratory before it starts. The certificate manager finds no
authority where it is told to look, mints a self-signed one there, and issues every
certificate under it. That is the whole hierarchy: one authority, and the certificates it
signs.

## Telling this laboratory's holders what to trust

An authority the certificate manager made itself has an identifier nobody chose, and nothing
may trust an authority it was told about over the very channel it is trying to secure. So
before anyone can ask for a certificate, the identifier has to reach them another way. This is
what `./reset.sh` does for you, and it is worth being able to do by hand, because it is what
an operator does when distributing trust to a machine the laboratory does not manage.

The authority is a keychain the certificate manager wrote, and its identifier is that
certificate's subject key identifier:

```sh
run_in lab-manager as admin \
    openssl pkcs12 -in /home/idm/.local/share/pva/1.5/cert_auth.p12 -nokeys -passin pass: \
  | openssl x509 -noout -ext subjectKeyIdentifier
#   X509v3 Subject Key Identifier:
#       E3:7F:CF:9D:DF:0B:AC:65:D3:30:2B:4D:B5:88:71:F9:6E:E1:01:24
```

Written the way the tools want it, which is the same digits without separators and in lower
case:

```sh
run_in lab-manager as admin bash -c \
  'openssl pkcs12 -in /home/idm/.local/share/pva/1.5/cert_auth.p12 -nokeys -passin pass: \
   | openssl x509 -noout -ext subjectKeyIdentifier | tail -1 | tr -d " :" | tr "A-F" "a-f"'
#   e37fcf9ddf0bac65d3302b4db58871f96ee10124
```

Both forms of it are wanted, in different places, and `lab_ids` puts them in a shell:

```sh
lab_ids
echo "${ROOT}"        # 39ed6dd4          names the authority where a name needs one
echo "${ROOT_SKID}"   # 39ed6dd4...  40   establishes trust in it, the first time
```

Both are variables in the shell you type in. A command sent into a container is expanded by
this shell before it gets there, so `"${ROOT_SKID}"` reaches the container as its value - but
typing the same thing *inside* a container's own shell finds nothing, because `lab_ids` set it
out here.

The whole forty digits is what a holder needs the first time it asks, because eight is not
enough to decide which authority is meant. In this laboratory every container is given it at
start, in `/etc/epics/issuer`, which a login shell reads back, so **the walkthrough below needs
nothing further** and you can go straight to section 1.

### Reference: giving a holder the identifier

> **Nothing in this subsection is part of the walkthrough. Do not run it here.** Each one
> replaces a keychain or takes away what a later section depends on. It is written down
> because it is what an operator does for a machine the laboratory does not manage, and it is
> in this list rather than in a block so it cannot be copied out by accident.

The identifier goes to the holder, so it is given where the holder runs, which here means
inside a container and therefore through `run_in`. Three ways, in increasing order of how long
they last:

- `authnstd -u client --issuer "${ROOT_SKID}"` gives it for that one request and keeps nothing.
- `EPICS_PVA_AUTH_ISSUER="${ROOT_SKID}"` gives it to every request that environment covers.
  This is how the containers here are told, from `/etc/epics/issuer` at start.
- `authnstd --trust-anchor --issuer "${ROOT_SKID}"` fetches the authority and writes it into
  the keychain, answering `Trust Anchor retrieved`. Only this one leaves the holder needing no
  identifier again, and it replaces whatever the keychain held, renaming the old file aside.

Running more than one in turn demonstrates nothing: once a request has succeeded the keychain
holds a valid certificate and the next attempt stops with `Valid certificate found: Use
--force flag to overwrite`.

### Reference: handing over the authority itself, rather than its name

> **Nothing in this subsection is part of the walkthrough either. Do not run it here.** It
> overwrites the workstation's keychain and removes the identifier every later section relies
> on.

All three above tell a holder which authority to *expect*, and it then fetches and stores it.
For a machine the laboratory does not manage there is a simpler route: put the authority into
its keychain yourself. A holder whose keychain already contains the authority needs no
identifier at all, because there is nothing left to decide.

The file to hand over is the authority with its private key removed, which is what
`authnstd --trust-anchor` produces. openssl makes one in two steps, run on the certificate
manager, which holds `/home/idm/.local/share/pva/1.5/cert_auth.p12`:

- `openssl pkcs12 -in cert_auth.p12 -nokeys -passin pass: -out root.pem` takes the certificate
  out and leaves the key behind.
- `openssl pkcs12 -export -nokeys -in root.pem -out trust_anchor.p12 -passout pass:` puts that
  certificate, and only it, into a keychain.
- `openssl pkcs12 -in trust_anchor.p12 -passin pass: -info -noout` should answer with one
  `Certificate bag` and no shrouded key bag. Worth checking: a keychain that kept the key would
  hand out the power to issue certificates rather than the ability to trust them.

Then put that file where the holder's `EPICS_PVA_TLS_KEYCHAIN` names, which for the laboratory
workstation is `/home/guest/.config/pva/1.5/client.p12`, and make it readable by that user:
`podman cp` it in and `chown guest`. From that moment `authnstd -u client` succeeds there with
no `--issuer` and no `EPICS_PVA_AUTH_ISSUER` set, and the certificate comes back issued under
the authority you copied in. Asking keeps the authority and adds the holder's own identity
beside it, so one file ends up carrying both.

What makes either route safe is the same in both cases: the authority, or its name, reached
the holder by a path the laboratory does not depend on. Copying a file across is such a path.
Being handed an authority by whatever answered the request is not, which is why a holder with
neither refuses to ask at all.

## 1. What a certificate is worth, one step at a time

Nothing holds a certificate yet, and the laboratory is already running. That is the baseline
to come back to whenever something later looks broken.

**Reading needs nothing.** Both controllers answer anyone on the segment:

```sh
run_in lab as guest without a certificate pvxget test:aiExample
#   value double = 10
run_in lab as guest without a certificate pvxget tst:ColorMode
#   value.index int32_t = 0
```

**Writing is refused, whatever you write to.** Every write rule in `testioc.acf` names
`PROTOCOL(TLS)` and `METHOD(X509)`, so with no certificate nothing is writable:

```sh
run_in lab as guest without a certificate pvxput test:stringExample hello
#   ERROR ... Put not permitted
```

The refusal comes from the controller itself. There is nowhere else it could come from: one
segment, and the holder is on it.

**So issue certificates.** Two people, and both controllers, then approve the four together:

```sh
run_in lab as guest    authnstd -u client
run_in lab as operator authnstd -u client
run_in testioc as testioc authnstd -u ioc
run_in tstioc  as tstioc  authnstd -u ioc

run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

A controller reads its keychain when it starts, and both were already running when their
certificates arrived, so they go on serving plain traffic until restarted. Restart them, or
every write below is refused for a reason that has nothing to do with the rule being tested:

```sh
podman-compose -p podman -f topologies/simple/compose.yaml \
    restart pvxs-lab-testioc pvxs-lab-tstioc
```

**Now the same write goes through**, and the rule that separates the two people shows itself.
`testioc.acf` puts operators and guests in the default group, and operators alone on
`test:spec`:

```sh
run_in lab as guest    pvxput test:stringExample hello   # written
run_in lab as operator pvxput test:spec 22               # written

run_in lab as guest    pvxput test:spec 11
#   ERROR ... Put not permitted
```

The guest holds a perfectly good certificate from this laboratory's own authority. What it
lacks is membership of the group the rule names:

```sh
run_in testioc as testioc cat /home/testioc/testioc.acf
#   UAG(OPERATORS) {
#       "operator"
#   }
#
#   UAG(GUESTS) {
#       "guest"
#   }
#
#   ASG(SPECIAL) {                          test:spec
#       RULE(1,READ)
#       RULE(1,WRITE,TRAPWRITE) {
#           UAG(OPERATORS)
#           AUTHORITY(EPICS_CA)
#           PROTOCOL(TLS)
#           METHOD(X509)
#       }
#   }
```

**Who answered.** `pvxinfo -v` ends with the identity of the peer it reached. Here that is the
controller itself, because nothing stands between them - worth noting now, because Part 2 asks
the same question through a gateway and gets a different answer:

```sh
run_in lab as operator pvxinfo -v test:open | grep '^#'
#   # TLS x509:0b5ee2fc:7327241123256509997:EPICS Root Certificate Authority/testioc@10.89.0.95:5076
```

`pvxinfo -v` prints the whole effective configuration first; the identity of the peer it
reached is the one line beginning `#`, which is what the pipe keeps. The name after the
authority is the certificate the controller presented, and the address is
where it is. On one segment, with nothing in between, they name the same machine.

**What the certificate manager holds**, as a standing view anyone may subscribe to. The guest
still holds the certificate approved a moment ago, so it can ask as itself:

```sh
# a monitor runs until you stop it: Ctrl-C to come back
run_in lab as guest pvxmonitor CERT:LIST:ALL
```

The name has no authority in it. Where two certificate managers share a network each view is
named by issuer, `CERT:LIST:<issuer>:ALL`, so a request is never ambiguous. Here there is one
manager and nothing to be ambiguous about, so the plain name is the one to use - and it is a
name, not a shell variable, so it means the same typed anywhere.

**Take one away and watch it stop working.** Revoke the operator's certificate, the one it
just wrote `test:spec` with:

```sh
run_in lab-manager as admin pvxcert -l --where "name:operator"
#   6e93ed57:15059513235269544035  CLIENT  CN=operator,O=epics.org,C=US  VALID ...

run_in lab-manager as admin pvxcert --review-issued --where "name:operator" --all --yes
#         VALID -> REVOKED  (REVOKE)
#   6e93ed57:15059513235269544035  done
```

The write it made a moment ago is refused now, and nothing was restarted or reconfigured to
make that happen. The controller asked about the certificate and was told:

```sh
run_in lab as operator pvxput test:spec 44
#   ERROR ... Put not permitted
```

Reading is untouched by any of it, because it never needed a certificate. The value the
operator wrote before it lost the right to write is still there:

```sh
run_in lab as guest without a certificate pvxget test:spec
#   value double = 22
```

That is the whole of what a certificate is worth here: it is the difference between reading
and writing, the group it puts you in decides which writes, and it stops meaning anything the
moment the certificate manager says so.

## 2. The request identifier an administrator checks

A request arrives at the certificate manager with a subject on it, and a subject is what the
asker chose to call itself. What ties the request in front of the administrator to the person
who made it is a separate identifier, printed to the asker and to nobody else.

The operator needs a certificate anyway: section 1 revoked the one it had. Ask again.
`--force` is needed because a revoked certificate is still a certificate, and only one fits in
a keychain:

```sh
run_in lab as operator authnstd -u client --force
#   email this Certificate Request ID: EPHH-RJJV-A9CE-K996, to your SPVA administrator
#   Keychain file created   : /home/operator/.config/pva/1.5/client.p12
#   Certificate identifier  : bf95cd24:14240780177074030135
```

The administrator sees that same identifier against the request:

```sh
run_in lab-manager as admin pvxcert --review-pending < /dev/null
#   [1/1] bf95cd24:14240780177074030135
#     Subject        : CN=operator,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : EPHH-RJJV-A9CE-K996
#     Status changed : 2026-08-12 00:55:07 UTC
#
#   Nothing to read answers from, and no --all given. Nothing was written.
```

`< /dev/null` is what makes it show and stop. Given a terminal it would ask about each in turn,
which section 4 comes back to once there are enough requests for that to be worth doing.

The subject says `CN=operator` because that is what was asked for, and asking is free: anyone
may ask for any subject, including one that belongs to somebody else. Nothing in the request
proves who sent it. The request identifier is what the administrator checks against what the
person told them out of band, and it is the only thing in that listing the asker could not
have chosen for itself.

Approve it, which also puts the operator back:

```sh
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
#         PENDING_APPROVAL -> VALID  (APPROVE)
```

Everyone now holds a valid certificate under their own name, which is what the rest of this
part assumes. A certificate awaiting a decision establishes nothing, so leaving one pending
here would make later commands fail for that reason rather than the one being demonstrated.

## 3. Listing certificates

```sh
run_in lab-manager as admin pvxcert -l
```

Every certificate this laboratory has issued, with its type, subject, status, dates and
request identifier. Dates are rendered year first in one fixed-width layout everywhere, so
they sort and compare as plain text.

**An ordinary user can list too, with no certificate at all:**

```sh
run_in lab as guest without a certificate pvxcert -l
```

Both see the same rows - what the laboratory has issued is not a secret, and an operator
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

The same listing is served as standing views a client can subscribe to. These two are open to
everyone:

```sh
# a monitor runs until you stop it: Ctrl-C to come back
run_in lab as guest pvxmonitor CERT:LIST:ALL
```

```sh
run_in lab as guest pvxmonitor CERT:LIST:EXPIRING
```

The third view, of requests awaiting a decision, is open to nobody but an administrator, which
is section 4.

> If either of those answers `Certificate not valid: PENDING_APPROVAL` rather than a view, the
> guest is holding a request nobody has approved. Approve it and try again:
> `run_in lab-manager as admin pvxcert --review-pending --all approve --yes`

## 4. Only an administrator may decide

The administrator write rule names four things, and all of them are load bearing:

```sh
run_in lab-manager as idm cat /etc/pvacms/pvacms.acf
#   RULE(1,WRITE) {
#       UAG(CMS_ADMIN)        who
#       AUTHORITY(CMS_AUTH)   issued by this laboratory's own authority
#       PROTOCOL(TLS)         over a secure transport, not plain
#       METHOD("x509")        having actually presented a certificate
#   }
```

An ordinary user may look at everything and decide nothing. The same review command run two
ways shows exactly where the line falls, and it needs a request waiting to be looked at.
Section 2's was approved, so make another.

**The operator asks, and the guest does the looking.** That way one holder has a request
pending while another still holds a valid certificate, which is what the rest of this section
needs. A holder whose own certificate is awaiting a decision cannot establish a secure
connection at all, and would fail for that reason rather than the one being shown.

It asks under a name nothing has used yet. The operator's own name is taken: section 2 got it
a certificate, and a certificate manager refuses a second one for a subject it has already
issued, answering `Duplicate Certificate Subject`.

```sh
run_in lab as operator authnstd -u client -n reviewer --force

run_in lab-manager as admin pvxcert --review-pending < /dev/null
#     Subject        : CN=reviewer,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : FDGB-CYEV-R5D1-4QBQ

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

lab_ids   # ${ROOT} is a variable in this shell, not in the container
run_in lab as guest without a certificate pvxput CERT:STATUS:${ROOT}:0123456789 state=REVOKED
#   ERROR ... REVOKED operation not authorized ... by ca/guest@...
```

`ca/guest` is the whole explanation: the connection presented no certificate, so the rule
could not match however the user is named.

The view of certificates **awaiting a decision** is gated the same way, at channel creation.
The guest asks holding the certificate approved in section 2, so what comes back is about who
it is rather than about what it presented:

```sh
# a monitor runs until you stop it: Ctrl-C to come back
run_in lab as guest pvxmonitor CERT:LIST:PENDING_APPROVAL
#   WARN pvxs.cli.io Server 10.89.0.22:5076 refuses channel to
#        'CERT:LIST:PENDING_APPROVAL' : Refused to create Channel
```

while the open views are served to that same holder without complaint:

```sh
run_in lab as guest pvxmonitor CERT:LIST:ALL
```

That is the distinction worth having: a good certificate, from this laboratory's own
authority, and still refused - because the rule names an administrator and this holder is not
one. A `Certificate not valid` message instead would mean something different, that the asker
never got far enough for any rule to apply to it.

Approve the request to finish, which leaves the operator holding a certificate again, under
the name it asked for:

```sh
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

Decisions are made at the certificate manager, by somebody the certificate manager's own access
file names.

### What a decision can be, and how much of it you are asked

**A denial is not a separate state.** The certificate manager writes `REVOKED`, and the review
shows that before you confirm. Make a request to spend on it:

```sh
run_in lab as operator authnstd -u client -n spare --force

run_in lab-manager as admin pvxcert --review-pending --all deny --yes
#   About to change 1 certificate:
#     <identifier>  CN=spare,O=epics.org,C=US
#         PENDING_APPROVAL -> REVOKED  (DENY)
```

**Revocation works over the issued certificates**, and unlike a pending review it *can* be
narrowed by a filter. Three levels of control, and a fourth form that takes one identifier:

```sh
run_in lab-manager as admin pvxcert --review-issued --where "state:VALID"               # one at a time  - answer skip, then stop
run_in lab-manager as admin pvxcert --review-issued --where "name:guest" --all          # asks once      - answer n
run_in lab-manager as admin pvxcert --review-issued --where "name:tstioc" --all --yes   # no questions   - this one goes through
run_in lab-manager as admin pvxcert -R "${ROOT}:0123456789"                             # one certificate - that serial does not exist
```

**Only the third is meant to be carried through.** The first walks every valid certificate,
the administrator's own among them, so answer `skip` to move past each and `stop` when you have
seen enough. The second is answered `n`, and shows exactly what was chosen before anything is
written:

```
About to change 1 certificate:
  <identifier>  CN=guest,O=epics.org,C=US
      VALID -> REVOKED  (REVOKE)

Revoke these 1 certificates? [y/N] n
Cancelled. Nothing was written.
```

The wording and the answers change with the job: revoking offers `revoke / skip / stop /
cancel`, with no `approve` or `deny` to pick the wrong one of. The fourth names a serial that
does not exist and says so, writing nothing.

That third one stopped a controller, so put it back, which is what a site would do having
revoked one in error:

```sh
run_in tstioc as tstioc authnstd -u ioc --force
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
podman-compose -p podman -f topologies/simple/compose.yaml restart pvxs-lab-tstioc
```

**Only what can be revoked is offered.** The rest is listed with the reason and never asked
about - anything outside `PENDING_APPROVAL`, `PENDING` and `VALID`, which the denied request
above now is:

```sh
run_in lab-manager as admin pvxcert --review-issued < /dev/null
#     Subject        : CN=spare,O=epics.org,C=US
#     Status         : REVOKED
#     Not offered    : status REVOKED cannot be revoked
```

### An ordinary user may revoke their own, and no other

That is the point of it for them: a key has leaked and they want it stopped now, without
finding an administrator first.

```sh
run_in lab-manager as admin pvxcert -l --where "name:guest and state:VALID"   # its identifier
run_in lab as guest pvxcert -R "${ROOT}:<the serial that listing shows>"
#   Revoke ==> CERT:STATUS:<that identifier> ==> Completed Successfully
```

That leaves them without one, so they ask again, which is what anyone would do having stopped a
key they no longer trust:

```sh
run_in lab as guest authnstd -u client --force
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

Someone else's is refused, and the message names the identity the certificate manager saw
rather than the certificate it was asked about:

```sh
run_in lab as guest pvxcert -R "${ROOT}:<a controller's serial>"
#   ERR ... REVOKED operation not authorized on <that identifier> by
#   TLS x509:<issuer>:<serial>:EPICS Root Certificate Authority/guest@...
```

The one identity this runs the other way for is the administrator's own certificate. A
certificate manager refuses that, because it is the identity it needs in order to keep answering
at all. The tool cannot tell an administrator's keychain from anyone else's, so it offers the
certificate like any other and reports what the manager says:

```sh
run_in lab-manager as admin pvxcert -R "${ROOT}:<the admin's own serial>"
#   ERR ... REVOKED Admin Self-Revoke not permitted on <that identifier> by ...
```

A failed write does not stop the ones after it, the manager's own message is shown against the
certificate it belongs to, and a partly successful batch exits 5.

# Part 2 - simple, with a gateway

The same laboratory, published at a facility address. A gateway stands in the DMZ and proxies
inward; a load balancer owns the address and maps a port to the gateway. Nothing inside
originates traffic outward, so there is no router here: every crossing is inbound, and the
gateway is the only thing that crosses.

```sh
./reset.sh simple-with-gateway
```

[![The simple laboratory published at a facility address: a load balancer and a gateway in the DMZ, the laboratory segment behind them, and a workstation outside](topology/topology-simple-with-gateway.svg)](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-simple-with-gateway.svg)

The picture is wide. Click it to open the raw file, which the browser renders full size and
zoomable: every access rule and process variable list is readable there.

## 5. Reaching the laboratory from outside it

The workstation outside knows one address and one port. It has never heard of the gateway, and
it cannot reach the laboratory segment at all - `net-lab` carries `isolate: "true"`, so podman
drops anything it addresses there, whatever the access rules might have said:

```sh
run_in perimeter as guest sh -c 'echo ${EPICS_PVA_NAME_SERVERS}'
#   facility:5075
```

`facility` is the load balancer. It is HAProxy in `tcp` mode: it maps a port to a gateway and
forwards the stream without looking inside it, which is what layer 4 means. Its configuration
is `topologies/simple-with-gateway/config/haproxy.cfg`, and the part that matters is two pairs:

- `frontend pva_plain` binds `:5075` and its backend is `pvxs-lab-gateway:5075`
- `frontend pva_tls` binds `:5076` and its backend is `pvxs-lab-gateway:5076`

Both port numbers are the same on each line, deliberately. A server names its own port in a
search reply and the client then dials that port on the address the reply came from, so a
client answered "come back on 5075" would land on whatever 5075 maps to. Translate the port
and it lands somewhere else.

**Everything the laboratory has is issued as in Part 1, and the gateway needs one too.** It
asks for an `ioc` certificate rather than a `server` one, because it is a server to the
workstation outside and a client to the controllers, and only an `ioc` certificate is both:

```sh
run_in lab as guest    authnstd -u client
run_in lab as operator authnstd -u client
run_in testioc as testioc authnstd -u ioc
run_in tstioc  as tstioc  authnstd -u ioc
run_in gateway as gateway authnstd -u ioc

run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

The workstation outside asks too, and this is the first proof the path works: its request
crosses the load balancer and the gateway to reach a certificate manager it cannot address.
It asks under a name of its own, because the laboratory already has a `guest` and a
certificate manager refuses a second certificate for a subject it has issued:

```sh
run_in perimeter as guest authnstd -u client -n remote
#   email this Certificate Request ID: CSCS-DCQV-WJQ9-JPZT, to your SPVA administrator
#   Certificate identifier  : b1d050ed:17275979695046077977

run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

Restart the three that read a keychain at start. **The controllers first, and the gateway
only once they are serving**, because a gateway makes its upstream connections when it starts
and does not retry the ones it could not make. Restart them together and the gateway comes up
against controllers that are still starting, forwards nothing, and every read across the
boundary times out with bytes visibly flowing:

```sh
podman-compose -p podman -f topologies/simple-with-gateway/compose.yaml \
    restart pvxs-lab-testioc pvxs-lab-tstioc
```

Wait for the controller to be serving securely rather than for a number of seconds. Its
certificate reads `VALID` as soon as it is approved, which is before the controller has
restarted and has anything to do with it; what says it is ready is that it answers over TLS:

```sh
run_in lab as operator pvxinfo -v test:aiExample | grep '^#'
#   # TLS x509:...:EPICS Root Certificate Authority/testioc@10.89.0.95:5076
```

Until then the same line says `anonymous/@...:5075`. Then the gateway:

```sh
podman-compose -p podman -f topologies/simple-with-gateway/compose.yaml \
    restart pvxs-lab-gateway
```

Now read across the boundary:

```sh
run_in perimeter as guest pvxget test:aiExample
#   value double = 4
```

## 6. Who the controller thinks you are

This is the part that differs from Part 1, and it changes which rules apply. `pvxinfo -v` ends
with the identity of the peer it reached, so ask the same question from both sides.

From inside the laboratory, the peer is the controller itself:

```sh
run_in lab as operator pvxinfo -v test:open | grep '^#'
#   # TLS x509:0b5ee2fc:7327241123256509997:EPICS Root Certificate Authority/testioc@10.89.0.95:5076
```

From outside, the peer is the **gateway**, at the load balancer's address:

```sh
run_in perimeter as guest pvxinfo -v test:open | grep '^#'
#   # TLS x509:0b5ee2fc:9808356842445051647:EPICS Root Certificate Authority/gateway@10.89.4.14:5076
```

Two things in one line. The identity is `gateway`, because the secure connection is
established with the gateway and terminates there; the address is `10.89.4.10`, the load
balancer's, because that is the path the bytes took. Identity comes from the certificate
presented, and the address from the route, and they name different machines.

**So a request that crosses is judged twice, against two different files.**

The gateway judges you. It sees your certificate, and `gateway.acf` decides what may cross:

```sh
run_in gateway as gateway cat /home/gateway/gateway.acf
#   UAG(USERS)         { "guest", "operator", "remote" }
#   UAG(SPECIAL_USERS) { "operator" }
#
#   ASG(DEFAULT)    { RULE(1,READ)  { UAG(USERS) ... } }
#   ASG(SPECIAL)    { RULE(1,READ)  { UAG(USERS) ... }
#                     RULE(1,WRITE) { UAG(SPECIAL_USERS) ... } }
#   ASG(OPEN_WRITE) { RULE(1,READ)  { AUTHORITY(EPICS_CA) ... }
#                     RULE(1,WRITE) { AUTHORITY(EPICS_CA) ... } }
```

The controller then judges the **gateway**, because that is who is asking it. It never sees
you at all, which is why `testioc.acf` cannot express anything about who you are.

Which variable you write decides where you are stopped:

```sh
run_in perimeter as guest pvxput test:stringExample 9
#   ERROR ... Put permission denied by gateway

run_in perimeter as guest pvxput test:spec 9
#   ERROR ... Put permission denied by gateway

run_in perimeter as guest pvxput test:open 9
#   written
```

The first two never left the DMZ. `config/gateway.pvlist` maps `test:stringExample` to
`ASG(DEFAULT)`, which grants read and nothing else, and `test:spec` to `ASG(SPECIAL)`, which
grants write only to `UAG(SPECIAL_USERS)` - `operator`, and this holder is `remote`.

The third crossed, and then had to satisfy the controller as well. `test:open` is
`ASG(OPEN_WRITE)` at the gateway, which any certificate holder may write, and `ASG(OPEN)` at
the controller, whose rule names an authority and no user group at all:

```sh
run_in testioc as testioc cat /home/testioc/testioc.acf
#   ASG(OPEN) {
#       RULE(1,READ)
#       RULE(1,WRITE,TRAPWRITE) {
#           AUTHORITY(EPICS_CA)      <- any certificate this laboratory issued
#           PROTOCOL(TLS)
#           METHOD(X509)
#       }
#   }
```

`CN=gateway` satisfies that, so the write lands. Read it back from inside to be sure it did:

```sh
run_in lab as guest without a certificate pvxget test:open
#   value double = 9
```

The same three writes from inside all succeed, because the controller is looking at
`CN=operator` rather than `CN=gateway`, and `UAG(OPERATORS)` names it:

```sh
run_in lab as operator pvxput test:stringExample 3    # written
run_in lab as operator pvxput test:spec 3             # written
run_in lab as operator pvxput test:open 3             # written
```

> **If a read across the boundary stops working after a while**, restart the gateway. It makes
> its upstream connections when it starts and does not re-make one it has lost, so a
> laboratory left running answers its own status variable perfectly while forwarding nothing.
> `podman restart podman_pvxs-lab-gateway_1` puts it back, and it is the same fact as the
> restart order above.

That is the whole difference a gateway makes. Inside, a rule may name you. Outside, the
controller's rules can only name the gateway, so anything about *you* has to be said in the
gateway's own file, and the controller has to be willing to accept whatever the gateway
forwards. Granting a controller's variable to `AUTHORITY` with no user group, as `test:open`
does, is how you say "and I accept it through the gateway too".

# Part 3 - federated, one facility root

Two departments, each with its own certificate manager and gateway, both chaining to one
facility root whose standing a responder answers for. Certificates from either department are
trusted everywhere, because everything chains to that one root - and revoking that root stops
the whole facility, which is the last thing this part shows.

```sh
./reset.sh federated-shared-root
```

[![Two departments side by side, each with its own certificate manager and gateway, one facility root above them and a responder answering for it](topology/topology-federated-shared-root.svg)](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-federated-shared-root.svg)

The picture is wide. Click it to open the raw file, which the browser renders full size and
zoomable: every access rule and process variable list is readable there.

The two routers in it are the only things drawn that no container corresponds to. Rootless
podman cannot run one, so each says `SIMULATED` where every other card names its image. Their
work is done by adding a network interface to the containers that need one, and by setting
`isolate: "true"` on every network.

## One address for the facility, and the port says which department

Five segments:

| Segment | | Who is on it |
|---|---|---|
| `net-lab` | `10.89.0.0/24` | the lab department: its certificate manager, its two controllers, its gateway, its workstation - and the balancer and the responder, which stand here only to be named |
| `net-ml` | `10.89.1.0/24` | the machine learning department: the same again |
| `net-perimeter` | `10.89.2.0/24` | the DMZ: the two gateways and the balancer. Each gateway holds its own identity; no key that can issue a certificate is here |
| `net-it` | `10.89.3.0/24` | the facility's own, and the responder is the only thing on it |
| `net-internet` | `10.89.4.0/24` | outside the facility: one workstation, and the balancer answering as `facility` |

**A workstation has one network interface, as a real one does.** It is on its own department
and nowhere else, and everything it reaches beyond that it reaches at the facility address:

```sh
run_in lab       as guest sh -c 'echo ${EPICS_PVA_NAME_SERVERS}'
#   facility:5175
run_in ml        as guest sh -c 'echo ${EPICS_PVA_NAME_SERVERS}'
#   facility:5075
run_in perimeter as guest sh -c 'echo ${EPICS_PVA_NAME_SERVERS}'
#   facility:5075 facility:5175
```

One address, and the port chooses the department: `5075` and `5076` are the lab, `5175` and
`5176` the machine learning department, the second of each pair being the secure one. So the
lab workstation, naming `facility:5175`, is addressing the *other* department.

**Its own department it does not address at all.** Nothing here names a controller or a
certificate manager by address. Discovery is left on, as it is out of the box, and a search
is a broadcast that reaches everything on the segment the workstation is standing on:

```sh
run_in lab as guest sh -c 'echo "[${EPICS_PVA_ADDR_LIST-unset}] [${EPICS_PVA_AUTO_ADDR_LIST-unset}]"'
#   [unset] [YES]
```

So the rule for the whole laboratory is one line: **find your own department by broadcast,
and name the facility address for anything beyond it.** That is how a site is usually
configured, and it is why a segment mattering to discovery mattered so much earlier - a
broadcast search does not leave the segment it was sent to, so a department's own names
resolve inside it and nowhere else.

**`pvxlist` shows what a broadcast reaches**, which is the segment and nothing else:

```sh
run_in lab       as guest without a certificate pvxlist
#   10.89.0.192:5075      pvxs-lab-testioc
#   10.89.0.191:5075      pvxs-lab-tstioc
#   10.89.0.185:5075      pvxs-lab-pvacms

run_in ml        as guest without a certificate pvxlist
#   10.89.1.59:5075       pvxs-lab-ml-ioc
#   10.89.1.54:5075       pvxs-lab-ml

run_in perimeter as guest without a certificate pvxlist
#   (nothing answers)
```

Three answers in the lab department, two in the machine learning one, none outside. Read the
three lists together and they say the whole addressing arrangement.

**What is missing from the first list is the point.** The lab gateway stands on `net-lab` too,
at `10.89.0.199`, and it is not there. It serves on its perimeter address alone, so it never
answers a search on the department behind it - which is what lets discovery be left on without
a name ever being answered twice, once by the controller and once by the gateway in front of
it. The machine learning gateway is absent from the second list for the same reason.

**The third list is empty**, and that is why the workstation outside has name servers and
nothing else. There is no controller on `net-internet` to find; the only thing there is the
balancer, which forwards streams and answers no search. Everything that workstation does, it
does by naming the facility address.

The certificate managers *are* in their department's list, because they are servers. They do
not appear as askers anywhere: they search for nothing at all, which is why `compose.yaml`
gives them `EPICS_PVA_AUTO_ADDR_LIST: "NO"` and no address list.

`pvxinfo -v` then says which of the two routes a particular name took:

```sh
run_in lab as guest without a certificate pvxinfo -v test:aiExample | grep '^#'
#   # anonymous/@10.89.0.192:5075          the controller itself, found by broadcast
run_in lab as guest without a certificate pvxinfo -v ml:aiExample   | grep '^#'
#   # anonymous/@10.89.0.189:5175          the facility address, on the ML port
```

The perimeter workstation names both ports and no department directly, because it is outside
both. Everything it does crosses a gateway.

`facility` is HAProxy in `tcp` mode, as in Part 2, and the same rule holds about the ports:
each frontend and its backend carry the same number, because a server names its own port in a
search reply and the client dials that port on the address the reply came from. Translate one
and the client lands in the other department. Its configuration is
`topologies/federated-shared-root/config/haproxy.cfg`.

> **These segments are separated, not merely labelled.** Each carries `isolate: "true"`, so
> no podman network forwards to another: nothing reaches another segment by addressing it,
> and the gateway is the only way between departments in fact rather than by configuration.
> A broadcast search does not leave its segment either, and a name is answered only within
> one - which is why the balancer and the responder each have a leg in every network that
> names them. Those legs are not there to carry traffic; they are there so the name each is
> called by can be answered where it is asked. Everything else keeps one interface, including
> both certificate managers, so neither department's can be addressed from outside it.

## First, what works with no certificates at all

Parts 1 and 2 showed what a laboratory does before anything is issued: reading is open to
anyone, writing is refused, and a request from outside is stopped at the gateway rather than at
the controller. All of that still holds. What is new here is the department next door.

**Reading crosses with no certificate**, in both directions, each department reaching the other
at the facility address:

```sh
run_in lab as guest without a certificate pvxget ml:aiExample
#   value double = 1.23
run_in ml  as guest without a certificate pvxget test:aiExample
```

**Writing across is refused**, and refused at the far department's own boundary:

```sh
run_in lab as guest without a certificate pvxput ml:stringExample hello
#   ERROR ... Put permission denied by gateway
run_in ml  as guest without a certificate pvxput test:stringExample hello
#   ERROR ... Put permission denied by gateway
```

Neither request reached a controller. Each was stopped by the gateway of the department it was
addressed to, which is the same answer the outside workstation got in Part 2 and for the same
reason: a peer department is outside, as far as a gateway is concerned.

## 7. Two certificate managers, one per department

They are independent. Each holds only what it issued, and neither knows about the other's
certificates. Nothing has been issued to anyone yet, which is the clearest moment to look:

```sh
run_in lab-manager as admin pvxcert -l
#   89caabd6:03977854352940719173  IOC        CN=PVACMS Service ...
#   89caabd6:16553058513422122773  CLIENT     CN=admin,C=US
#   89caabd6:00000000009876543212  CERT_AUTH  CN=EPICS Controls Intermediate CA ...
#   58aec41b:00000000009876543210  ROOT_AUTH  CN=EPICS Root Certificate Authority ...

run_in ml-manager  as admin pvxcert -l
#   64ca66c8:16283814643480803887  IOC        CN=PVACMS Service ...
#   64ca66c8:08301308272239585373  CLIENT     CN=admin,C=US
#   64ca66c8:00000000009876543213  CERT_AUTH  CN=EPICS ML Intermediate CA ...
#   58aec41b:00000000009876543210  ROOT_AUTH  CN=EPICS Root Certificate Authority ...
```

Four rows each, and three of them differ. Each department made itself a service certificate and
an administrator, and holds the intermediate authority it signs with - `89caabd6` on one side,
`64ca66c8` on the other. **The fourth row is the same row in both**, down to its identifier
`58aec41b`: the facility root, which neither department issued and neither answers for. That is
the whole shape of the arrangement in eight lines.

The issuer half of an `<issuer>:<serial>` identifier says which department to ask about a
certificate, and a department has nothing to say about one it did not issue:

```sh
run_in lab-manager as admin pvxcert -l --where "issuer:${ML}"
#   (the column headings, and no rows)
```

Which department a service asks is decided by where it runs, not by which manager answers
first. Each container is given the whole identifier of the authority its department trusts,
which is forty digits, because on a first request there is nothing yet to check a delivered
authority against and only the whole identifier decides it:

```sh
run_in testioc as testioc printenv EPICS_PVA_AUTH_ISSUER   # lab
#   89caabd63805aa70a2ffea2832f05f5b1246b963
run_in ml-ioc  as mlioc   printenv EPICS_PVA_AUTH_ISSUER   # machine learning
#   64ca66c8b25b13e1f2afec7fc1858dd55a7103f3
```

Neither was told about the other, and neither needs to be. Both chain to the same root, so a
certificate from either is trusted everywhere - which is what section 8 is about.

### Naming an authority

The `$LAB` and `$ML` above are the first eight digits of those, which is what a process
variable name can carry. The whole forty is what the certificate holds, and that is what you
see if you read it:

```sh
run_in lab-manager as idm bash -c \
  "openssl pkcs12 -in /certs/lab_intermediate.p12 -passin pass: -nokeys \
   | openssl x509 -noout -ext subjectKeyIdentifier"
#   X509v3 Subject Key Identifier:
#       89:CA:AB:D6:38:05:AA:70:A2:FF:EA:28:32:F0:5F:5B:12:46:B9:63
```

> **Every identifier printed in this document came from one run.** Each laboratory mints its
> own authorities, and mints them again on `./reset.sh --authorities`, so yours are different.
> Where a command has to carry one, it is written `${LAB}` or `${LAB_SKID}`, which `lab_ids`
> fills in from the laboratory in front of you. Where a certificate has to be named, take the
> identifier from the listing rather than from here.

All of these are the same authority written four ways, and all four are understood wherever an
authority is named. Separators are dropped and capitals folded, so all four select the same
four rows:

```sh
run_in lab-manager as admin pvxcert -l --where "issuer:${LAB}"
run_in lab-manager as admin pvxcert -l --where "issuer:$(echo ${LAB} | tr a-z A-Z)"
run_in lab-manager as admin pvxcert -l --where "issuer:${LAB_SKID}"
run_in lab-manager as admin pvxcert -l --where "issuer:'89:CA:AB:D6:38:05:AA:70:A2:FF:EA:28:32:F0:5F:5B:12:46:B9:63'"
```

The last is the colon form, and is the one place here you would substitute your own: it is
`${LAB_SKID}` with a colon between each pair of digits.

The colon form needs quoting in a filter, because a bare colon is what separates the field
from the value. Everywhere else it can be written as it comes.

Something that is not an identifier at all, or is too short to name an authority, is refused
rather than turned into a name nothing answers:

```sh
run_in lab as guest authnstd -u client --issuer 89ca0
#   '89ca0' is too short to name a certificate authority: at least 8 hexadecimal digits are needed
```

How much of it is needed depends on what it is for. Naming takes as little as the eight
digits; deciding what to trust takes all of it.

**The whole identifier is required when nothing is trusted yet, and refused otherwise.** Eight
digits is thirty-two bits, and a key whose identifier begins with any wanted thirty-two bits
takes hours to generate on one processor core, so the short form names an authority
conveniently but cannot establish that it is the right one:

```sh
run_in lab as guest authnstd -u client --issuer ${LAB}
#   The issuer '89caabd6' is only 8 of the 40 digits of a subject key identifier, which is
#   not enough to decide which certificate authority to trust. Nothing is trusted yet, so
#   this identifier is the only thing deciding it. Give the whole subject key identifier, as
#   the certificate manager prints it at startup, or pre-provision a keychain holding the
#   authority to trust.

run_in lab as guest authnstd -u client --issuer ${LAB_SKID}      # accepted
run_in lab-manager as admin pvxcert --review-pending --all approve --yes
```

That last one is a request like any other, and it waits for a decision, so it is approved here:
from now on the lab guest is someone who holds a certificate, and it is the first thing this
laboratory has issued to anybody.

Once a keychain holds an authority, that pinned authority is what a delivered one is compared
against, and the short form is accepted again for naming. Certificate identifiers keep the
eight-digit form throughout, because that is what a process variable name carries.

`helpers.sh` gives you both: `$LAB` and `$ML` are the naming form, `$LAB_SKID` and `$ML_SKID`
the whole one. The certificate manager prints both when it starts:

```
| Issuer ID                             : 89caabd6
| Issuer SKID                           : 89caabd63805aa70a2ffea2832f05f5b1246b963
```

## Issue the certificates

Nothing new in how: it is Part 1's `authnstd` and `pvxcert --review-pending` throughout. What
is different is that every request goes to one department of two, and only that department's
administrator can approve it.

```sh
# the services, each asking its own department
run_in testioc as testioc authnstd -u ioc
run_in tstioc  as tstioc  authnstd -u ioc
run_in ml-ioc  as mlioc   authnstd -u ioc
run_in gateway    as gateway authnstd -u ioc
run_in ml-gateway as gateway authnstd -u ioc -n ml-gateway

# the people
run_in lab       as operator    authnstd -u client --ou lab --issuer ${LAB_SKID}
run_in ml        as guest       authnstd -u client
run_in perimeter as operator    authnstd -u client --issuer ${ML_SKID}
run_in lab       as ml/operator authnstd -u client --ou ml  --issuer ${ML_SKID}

# each department approves its own, and is offered nothing else
run_in lab-manager as admin pvxcert --review-pending --all approve --yes   # 4
run_in ml-manager  as admin pvxcert --review-pending --all approve --yes   # 5
```

Four and five, out of nine requests. Neither administrator was shown the other's, and neither
could have approved one.

Three of those lines carry something the single-department parts had no way to show:

- **`ml-gateway` asks under a name of its own.** Both gateways run the same image as the same
  account, and `testioc.acf` has `UAG(GATEWAYS) { gateway, ml-gateway }` - a rule can only name
  a gateway that is called something.
- **The machine learning guest names no authority.** Its container was given one, as every
  service here was. The other three name one because they are asking a department other than
  the one whose identifier they hold, or - for the workstation outside - because they were
  given none at all.
- **`--ou lab` and `--ou ml`** put each operator in its own department's unit, which section 8
  turns on.

Then restart the controllers, and the gateways after them, exactly as Part 2 did:

```sh
podman-compose -p podman -f topologies/federated-shared-root/compose.yaml \
    restart pvxs-lab-testioc pvxs-lab-tstioc pvxs-lab-ml-ioc
```

**Then wait for the controllers to be serving securely, and only then restart the gateways.**
Not for a number of seconds, and not for the certificate to read `VALID`: a controller's
certificate is valid from the moment it is approved, which is before the controller has
restarted and has anything to do with it. What says a controller is ready is that it answers
over TLS, and `pvxinfo -v` names the peer it reached:

```sh
run_in lab as operator pvxinfo -v test:aiExample | grep '^#'
#   # TLS x509:89caabd6:...:EPICS Root Certificate Authority -> EPICS Controls
#     Intermediate CA/testioc@10.89.0.177:5076
run_in ml  as guest    pvxinfo -v ml:aiExample   | grep '^#'
#   # TLS x509:64ca66c8:... /mlioc@10.89.1.47:5076
```

`TLS` and port `5076` is a controller that has read its keychain. Until it restarts the same
line says `anonymous/@...:5075` - serving plain traffic, and not yet worth relaying. Ask on
both sides, because a gateway restarted against a department that is not ready forwards
nothing until it is restarted again:

```sh
podman-compose -p podman -f topologies/federated-shared-root/compose.yaml \
    restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

## 8. One facility root, so each department trusts the other's certificates

This is the point of the whole arrangement, and it is worth walking through.

The workstation outside both departments holds a certificate from the **machine learning**
department. It asked for it when the others were issued, and it could not address that
certificate manager to ask: the request went to the facility address, on the port that means
machine learning, and crossed that department's gateway.

It uses that certificate to write to a **lab** controller, through the **lab** gateway - the
other port on the same address:

```sh
run_in perimeter as operator <<'EOF'
    pvxput test:spec 7
    pvxget test:spec
EOF
#   value double = 7
```

The write succeeds. For that to happen, every one of these had to hold:

- The lab gateway verified a certificate issued by the **machine learning** intermediate, by
  following the chain back to the facility root it holds locally
- Its access rule authorised the write on `AUTHORITY(EPICS_CA)`, the **shared root**, so a
  certificate from either department qualifies
- The certificate's status was checked against the **machine learning** certificate manager,
  which the lab side reaches only through a gateway

Trust is shared; authorisation is not. The gateway's access file grants writes only for
process variables its list marks `ALLOW SPECIAL`, and only to `UAG(SPECIAL_USERS)` over TLS
with a certificate:

```sh
run_in gateway as gateway cat /home/gateway/gateway.acf
run_in gateway as gateway cat /home/gateway/gateway.pvlist
```

The same write with no certificate is refused, and refused at the boundary rather than by the
controller:

```sh
run_in perimeter as guest pvxput test:spec 9
#   ERROR ... Put permission denied by gateway
```

Every rule in that file names `AUTHORITY(EPICS_CA)`, so being outside the facility is not what
stops this one. A holder of *any* certificate the facility issued gets past that condition; the
guest holds none, and so is refused on the first thing checked.

### Narrowing a write to a unit, not a department

`test:spec` above shows what the shared root buys: either department's operator may write it.
`test:labspec` shows the other half. Its rule authorises on the same shared root, so a
certificate from either department is equally trusted, and then asks what the certificate says
about its holder - only one carrying the lab's own unit may write:

```
UAG(LAB_UNIT) { "OU=lab" }

ASG(LABSPEC) {
    RULE(1,READ)
    RULE(1,WRITE,TRAPWRITE) { UAG(LAB_UNIT) AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }
}
```

Two certificates are needed to see the difference, and both were issued in the setup above,
each carrying its own department's unit:

```sh
run_in lab as operator    authnstd -u client --ou lab --issuer ${LAB_SKID}
run_in lab as ml/operator authnstd -u client --ou ml  --issuer ${ML_SKID}
```

`ml/operator` is the machine learning operator at a lab workstation: the same account, holding
a certificate from the other department, in a keychain of its own. Running either line again
answers `Valid certificate found: Use --force flag to overwrite`, which is the keychain saying
it already has one, not a fault.

The unit also keeps the two subjects distinct, which is what lets one person hold both: a
certificate manager refuses a second certificate for a subject it has already issued.

Both are trusted by the lab controller, and only one may write:

```sh
run_in lab as operator    pvxput test:labspec 101      # allowed: carries OU=lab
run_in lab as ml/operator pvxput test:labspec 202      # refused: no such unit
#   ERROR ... Put not permitted
run_in lab as ml/operator pvxget test:labspec          # reading is open to both
#   value double = 101
```

The refusal is on the unit and not on the authority. The machine learning certificate was
verified, its status checked, and its holder found to be someone the rule does not name - which
is what the same operator writing `test:spec` demonstrates by succeeding:

```sh
run_in lab as ml/operator pvxput test:spec 202         # allowed: authorised on the shared root
run_in lab as guest without a certificate pvxget test:spec
#   value double = 202
```

Note what naming a unit does and does not guarantee. The unit is a claim the issuing department
vouched for, so a machine learning certificate asking for `--ou lab` would be admitted here. A
rule that must not be crossed under any circumstances should name the authority as well; naming
only the unit trusts every department sharing the root to issue that unit honestly.

## 9. A certificate is revoked where it was issued

Revoking is Part 1's command and Part 1's rule about who may run it. What two departments add is
that there are now two places to run it, and only one of them will answer about any given
certificate.

Take one the machine learning department issued:

```sh
run_in ml-manager as admin pvxcert -l --where "name:guest and state:VALID"
#   64ca66c8:10879973745800329899  CLIENT  CN=guest,O=epics.org,C=US  VALID ...
```

The lab administrator cannot find it, and cannot act on it even when handed its identifier:

```sh
run_in lab-manager as admin pvxcert -l --where "issuer:${ML}"
#   (the column headings, and no rows)

run_in lab-manager as admin pvxcert -R "${ML}:<the serial that listing shows>"
#   Timeout
```

That timeout is not a refusal, and the difference matters. A certificate's status channel
carries its issuer in the name, so what was asked for is a channel the lab department does not
serve. There is nothing there to refuse it. The department that issued it answers in one
command:

```sh
run_in ml-manager as admin pvxcert -R "${ML}:<that serial>"
#   Revoke ==> CERT:STATUS:${ML}:<that serial> ==> Completed Successfully
```

So trust is shared and administration is not, which is the same division section 8 showed from
the other side: a certificate from either department is accepted everywhere, and yet only one
administrator in the facility can withdraw it.

Put it back, because section 10 wants the laboratory whole:

```sh
run_in ml as guest authnstd -u client --force
run_in ml-manager as admin pvxcert --review-pending --all approve --yes
```

## 10. Revoking the authority itself

Everything so far revokes a certificate the laboratory issued, and the holder learns of it on
the status channel that certificate names. The facility root has no such channel. It is the
thing every node is configured to trust, so an answer about it carried over a connection it
underwrites would be worth nothing, and nothing subscribes to it in any case.

So the root says where its own revocation can be learned. It carries the address of a
responder, and each department's certificate manager asks that responder whether the root still
stands:

```sh
openssl x509 -in topologies/federated-shared-root/certs/ocsp_ca.pem -noout -text \
  | grep -A 1 "Authority Information"
#   Authority Information Access:
#       OCSP - URI:http://pvxs-lab-authority-status:8888
```

The responder's own segment is `net-it`, the facility's: it belongs to neither department, as
the root does not. It also has a leg in each department, because the name the root gives it has
to be answerable where it is asked, and that leaves each certificate manager asking it without
leaving its own segment. It signs with a certificate the root authorised for the purpose, so
the root's own key is not on it - and the root's keychain has no key in it at all, only the
certificate, which is why nothing in the laboratory can sign as the root.

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

### Waiting for the answer to reach the departments

**Nothing changes in the laboratory at the moment the root is revoked, and this step is not
optional.** Each certificate manager holds the responder's last answer until it lapses, and the
laboratory's responder asks to be believed for one minute. The revocation reaches the
departments when that minute is up, not before - so ask, and keep asking, until it changes:

```sh
run_in lab as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12
#   Status        : AUTHORITY_REVOKED
```

A minute is the shortest it can be and not the longest: the manager re-asks after its held
answer lapses, so a revocation arriving just after one of those goes almost two minutes before
it is seen. Ask before then and you will see one of two answers, both correct for the moment
they are given:

- `VALID`, when the manager's held answer has not lapsed yet. Nothing above the certificate has
  reached that manager, so it says what it last established.
- `UNKNOWN`, when the answer lapsed while the responder was restarting. `authority_revoke`
  rewrites the responder's file and restarts it, because the responder reads its answer once at
  start; for the second or two that takes, a manager that asks gets nothing back. It does not
  assume an answer it could not get, which is the behaviour described under *When the responder
  cannot be reached* below, arriving a step earlier than you were expecting it.

Neither is the certificate manager being unclear about the revocation. It is the ordinary
sequence: last answer, then no answer, then the new one.

### What every certificate says once it has propagated

`-f` names a keychain instead of an identifier, and the status address is read from the
certificate inside it, so nothing has to be copied from the listing and the line stays right
however the serial numbers fall. The path is written out in full because it is a path inside
the container, where the guest's home is `/home/guest`. Writing `~` there would be expanded by
your own shell first, to your home directory on this machine, and the file it named would not
exist.

That state is not `REVOKED`, and the difference is the point of it. The holder's own
certificate is untouched: it has not been revoked, it has not expired, and asking for a
replacement would achieve nothing, because a replacement would be issued by the same authority.
The certificate cannot be used, and the reason lies above it.

A certificate that cannot be used is not presented, and the write does not go through:

```sh
run_in lab as guest pvxput test:aiExample 42
#   Timeout
```

What it says depends on how far the client gets. If it can still be told about its own
certificate it is refused for want of an identity, and if it cannot be told anything at all -
which is the usual case here, since the certificate manager's own certificate is under the same
root - nothing answers and it times out. Either way nothing is written, and reading the
variable back shows the value it had.

Administration stops with it, and that is worth seeing rather than working around. An
administrator's certificate was issued under the same root, so it is no more usable than anyone
else's, and the listing does not answer at all:

```sh
run_in lab-manager as admin pvxcert -l
#   ERR ... Timed out listing certificates from CERT:LIST
```

Revoking a facility root is not a way to withdraw one department or one holder. It stops
everyone who chains to it, including the people who would undo it, which is why it is the last
thing a facility does and why what it takes to undo it is a file and a restart rather than a
certificate operation.

Putting the root back takes the same wait to be believed, for the same reason, and the gateways
need one thing more:

```sh
authority_restore
#   the facility root stands

run_in lab as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12
#   Status        : VALID

podman-compose -p podman -f topologies/federated-shared-root/compose.yaml \
    restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

**Wait for `VALID` before restarting the gateways, rather than restarting them after a fixed
time.** They have to make their upstream connections to a department that is already answering,
and a department whose root has not yet come back is not. Restart them too early and everything
below still looks broken, for a reason that has nothing to do with the root any more. Ask too
early and the answer is `AUTHORITY_REVOKED` or `UNKNOWN` exactly as before: that is the wait,
not a restore that did not work.

**Both departments, not one.** The two certificate managers ask the responder on their own
schedule, so one is back before the other. Restarting on the strength of the lab side alone
leaves the machine learning gateway forwarding nothing, and the symptom is that `ml:aiExample`
cannot be read from anywhere while `test:aiExample` can. Ask on both sides before restarting:

```sh
run_in lab as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12
run_in ml  as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12
```

**Do not skip the gateway restart either.** Everything inside a department comes back on its
own: each certificate manager asks the responder again, and every holder is told over the
status channel it already subscribes to. A gateway does not. Its connections to the department
were torn down when the root was revoked, and it does not rebuild them once the root stands
again, so it goes on answering searches while no request through it ever completes. Everything
the perimeter workstation can see is reached through a gateway, so the symptom is a workstation
that cannot read a variable or ask for a certificate:

```
No certificate manager answered CERT:CREATE:<issuer> within 5 seconds. Nothing serves that
name, so either no certificate manager for this authority is running, or it cannot be
reached from here.
```

The certificate manager is running and perfectly healthy when that appears. The department can
read its own variables, the administrator can list every certificate, and the gateway's own
certificate is `VALID`: the only thing wrong is the gateway's side of a connection that was cut
a section ago. Restarting the two gateways is the whole repair, and these four are how you know
it worked:

```sh
run_in lab       as guest without a certificate pvxget ml:aiExample
run_in ml        as guest without a certificate pvxget test:aiExample
run_in perimeter as guest without a certificate pvxget test:aiExample
run_in perimeter as guest without a certificate pvxget ml:aiExample
```

Nothing was repaired to achieve that. The listing shows what it showed before, because no
certificate was ever changed: what changed was above them, and it is read afresh each time a
status is answered rather than recorded against anything.

```sh
run_in ml-manager as admin pvxcert -l --where "name:guest"
#   64ca66c8:<serial>  CLIENT  CN=guest,O=epics.org,C=US  VALID    ...
#   64ca66c8:<serial>  CLIENT  CN=guest,O=epics.org,C=US  REVOKED  ...
```

Two of them, because section 9 revoked one and it was asked for again. The revoked one is still
revoked, which is the point: the root coming back restores nothing that was decided beneath it.

A listing asked for too early answers `Certificate not valid: UNKNOWN` and then times out. That
is the administrator's own certificate, which is under the same root as everything else, and it
is the same wait again rather than a fault.

### When the responder cannot be reached

A responder is a web service, and a web service can be down. That is a different fact from a
revoked authority: the root may be perfectly good and simply not answering for itself.

```sh
authority_unreachable
#   the responder is stopped; nothing can be learned about the root
```

A certificate manager that cannot check its own authority does not assume the answer. It
notices when the answer it holds lapses, which here is up to the minute the responder asked
for, and from then on it retries every fifteen seconds. Until one succeeds it reports what it
actually knows, which is nothing:

> **One unanswered call is not an unreachable responder.** A poll asks up to five times before
> it concludes that, because this responder is `openssl ocsp`, which serves one caller at a
> time - and with two departments polling it, the second is dropped often enough to see. The
> attempts share the one deadline the poll already had, so a responder that takes the call and
> then says nothing is still asked once and given up on, and stopping the service waits no
> longer than it did. Without this, one dropped call reports the authority unknown and stops
> every connection the facility underwrites, for the fifteen seconds until the next poll.

```sh
run_in lab as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12
#   Status        : UNKNOWN
```

That is the same wait as before, so ask until it changes rather than reading anything into the
first answer.

Connections refuse, exactly as they do for any status a client cannot establish. This is the
laboratory failing closed, and it is a choice rather than a consequence: a facility that cannot
check its authority stops, rather than continuing on an assumption.

A site that would rather stay up sets `EPICS_PVACMS_AUTHORITY_HOLD_LAST_KNOWN=YES` on its
certificate managers, and an unreachable responder then leaves them serving the last answer
they verified. The trade is stated plainly: an outage of one web service no longer takes the
facility with it, and a revocation issued during that outage is not seen until it ends.

Put the responder back and the managers pick it up on one of those retries, within fifteen
seconds - quicker than the restore above, because nothing had to lapse first. The gateways need
the same restart, for the same reason: they were cut off while the standing was unknown, and
they do not reconnect by themselves:

```sh
authority_reachable
#   the responder is running again
#   the facility root stands

run_in lab as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12
#   Status        : VALID

podman-compose -p podman -f topologies/federated-shared-root/compose.yaml \
    restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

That restart leaves the laboratory as section 8 left it, which is where to come back to if a
later reading disagrees with what is written here.

# Part 4 - federated, two independent roots

Two departments under two roots that rotate separately. Trust cannot come from a shared chain
here, so each keychain stores both roots as trust anchors: one identity, many anchors. This is
the part that exercises the capability the other three do without.

```sh
./reset.sh federated-non-shared-root
```

[![Two departments side by side under two independent roots, with a keychain below them holding one identity and both roots as trust anchors](topology/topology-federated-non-shared-root.svg)](https://raw.githubusercontent.com/slac-epics/pvxs-cms/scratch/fy26-four-topologies/example/podman/topology/topology-federated-non-shared-root.svg)

The picture is wide. Click it to open the raw file, which the browser renders full size and
zoomable: every access rule and process variable list is readable there.

**This laboratory is drawn but not built yet**, and `./reset.sh federated-non-shared-root` says
so and stops. What building it needs is written at the top of
`topologies/federated-non-shared-root/compose.yaml`. Section 11 below is the walkthrough that
belongs here; it has not been run against this laboratory, because there is not one yet, and
`./reset.sh federated-shared-root` is what to bring up if you want to try the filters now.

## 11. Filtering the listing

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

# Reference

## The layout

The `federated-shared-root` laboratory, which is the largest of the four. Every other one is a
part of this: `simple` is the lab department alone, and `simple-with-gateway` adds the boundary
and the facility address to it.

| Service | Segment(s) | What it is |
|---|---|---|
| `pvxs-lab-pvacms` | lab | the lab department's certificate manager |
| `pvxs-lab-testioc`, `pvxs-lab-tstioc` | lab | lab controllers, serving `test:` and `tst:` |
| `pvxs-lab-gateway` | lab + perimeter | the lab boundary |
| `pvxs-lab-ml` | ml | the machine learning certificate manager |
| `pvxs-lab-ml-ioc` | ml | its controller, serving `ml:` |
| `pvxs-lab-ml-gateway` | ml + perimeter | its boundary |
| `pvxs-lab-authority-status` | it + lab + ml | the responder that answers for the facility root |
| `pvxs-facility-lb` | internet + perimeter + lab + ml | the facility address, layer 4 |
| `lab-client`, `ml-client` | lab, ml | a workstation in each department |
| `perimeter-client` | internet | a workstation outside the facility |

The balancer and the responder are the only things with a leg outside their own segment that
is not a boundary: each stands in every network that names it, because podman answers a name
only within a segment. Everything else has one interface.

Service names are the DNS names, and they match the names used in the shell profiles and
gateway configuration inside the images, so nothing needs rewriting per environment.

Configuration worth reading, under `topologies/federated-shared-root/`:

- `config/pvacms-lab.acf`, `config/pvacms-ml.acf` - each certificate manager's access rules
- `config/gateway-lab.pvlist`, `config/gateway-ml.pvlist` - what each gateway forwards
- `config/gateway-lab.conf`, `config/gateway-ml.conf` - each gateway's own configuration
- `config/haproxy.cfg` - the facility address, and which port reaches which department

## Troubleshooting

**Nothing crosses a boundary.** Restart the two gateways. A gateway does not retry a
connection it never made or has lost: one that started before the controllers were serving
never made it, and one whose department was cut off by a revoked authority (section 10) lost
it. Neither comes back on its own, and the gateway goes on answering searches meanwhile, so
the symptom is a request that times out rather than one that is refused.

Check the department is ready before restarting them, or you will be doing it twice. A
controller is ready when it answers over TLS, which is later than its certificate reading
`VALID`:

```sh
run_in lab as operator pvxinfo -v test:aiExample | grep '^#'
#   # TLS ... /testioc@...:5076        ready
#   # anonymous/@...:5075              not yet
```

```sh
podman-compose -p podman -f topologies/federated-shared-root/compose.yaml \
    restart pvxs-lab-gateway pvxs-lab-ml-gateway
```

Every `podman-compose` here names the project and the compose file, because each laboratory
lives in its own directory and they all make the same set of containers. Leave them off and
compose looks for a compose file in this directory, where there is none.

**A workstation cannot reach the other department.** Check that the facility address answers
where it is asked:

```sh
podman exec podman_lab-client_1 getent hosts facility
```

Nothing back means the balancer has no leg on that workstation's segment. Podman answers a name
only for containers that share one, so an appliance addressed by name has to stand on every
segment that names it - and with `isolate: "true"` on every segment, a leg is now the only way
to reach it as well as the only way to name it.

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
./reset.sh federated-shared-root
```

That discards every certificate the laboratory has issued and every keychain the services hold,
keeps the two departmental certificate authorities so the issuer ids stay the same, brings
everything back up, restarts the gateways last so the boundaries work, and then checks what a
demonstration depends on before handing it back. It takes a minute or two. Name a different
laboratory and you get that one instead; nothing of the last one is left behind.

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
./reset.sh --authorities federated-shared-root
```

It builds nothing: the images do not depend on which authorities exist, so there is nothing
about them to rebuild.

To rebuild the images without discarding anything:

```sh
./bootstrap.sh
```

Building mints nothing and minting builds nothing, so neither of those two ever waits on the
other.
