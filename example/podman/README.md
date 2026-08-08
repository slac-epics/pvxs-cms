# Secure PVAccess demonstration laboratory, on podman

A two-department Secure PVAccess laboratory that runs on rootless podman with
`podman-compose`.

Everything here is exercised from the command line, where every property worth
demonstrating can be shown and checked directly.

## Contents

- [What it demonstrates](#what-it-demonstrates)
- [Installation](#installation)
- [Bringing it up](#bringing-it-up)
- [Say it once: where, and who](#say-it-once-where-and-who)
- [What works with no certificates at all](#first-what-works-with-no-certificates-at-all)
- [1. Two certificate managers, one per department](#1-two-certificate-managers-one-per-department)
  - [Naming an authority](#naming-an-authority)
- [2. Crossing a boundary is only possible through a gateway](#2-crossing-a-boundary-is-only-possible-through-a-gateway)
- [3. One facility root, so each department trusts the other's certificates](#3-one-facility-root-so-each-department-trusts-the-others-certificates)
- [4. The request identifier an administrator checks](#4-the-request-identifier-an-administrator-checks)
- [5. Listing certificates](#5-listing-certificates)
- [6. Filtering the listing](#6-filtering-the-listing)
- [7. Approving, in batches or one at a time](#7-approving-in-batches-or-one-at-a-time)
- [8. Denying and revoking](#8-denying-and-revoking)
- [9. Only an administrator may decide](#9-only-an-administrator-may-decide)
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

`run_in` on its own lists the places and people; `lab_status` shows what is running.

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

**Writing is refused.** `test:spec` is the one process variable a gateway will carry a
write for, and it still requires a certificate presented over TLS by an operator:

```sh
# inside the department, refused by the controller itself
run_in lab as guest without a certificate pvxput test:spec 3
#   ERROR ... Put not permitted

# from the peer department, refused earlier, by the lab gateway
run_in ml as guest without a certificate pvxput test:spec 3
#   ERROR ... Put permission denied by gateway

# from outside both departments, refused the same way
run_in perimeter as guest without a certificate pvxput test:spec 3
#   ERROR ... Put permission denied by gateway
```

The messages come from two different places, and the difference is worth noticing. In the
first the request reached the controller, which applied its own access file. In the other
two it never got that far: the gateway refused it on the boundary, whether the request came
from the peer department or from outside both.

Any other process variable is refused the same way, because every write rule in the
laboratory names `PROTOCOL(TLS)` and `METHOD(X509)`:

```sh
run_in lab as guest without a certificate pvxput test:aiExample 3
#   ERROR ... Put not permitted
```

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

Check that all seven arrived before going on. A gateway without a certificate refuses every
write on the boundary, which looks like a broken rule rather than a missing certificate:

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
first. Each container carries its own department's issuer id:

```sh
run_in testioc as testioc printenv EPICS_PVA_AUTH_ISSUER   # lab
run_in ml-ioc  as mlioc   printenv EPICS_PVA_AUTH_ISSUER   # machine learning
```

### Naming an authority

That id is the first eight digits of the authority's subject key identifier, which is what a
process variable name can carry. The authority itself carries the whole forty, and that is
what you see if you read its certificate:

```sh
run_in lab-manager as idm bash -c \
  "openssl pkcs12 -in /certs/lab_intermediate.p12 -passin pass: -nokeys \
   | openssl x509 -noout -ext subjectKeyIdentifier"
#   53:E8:04:2C:F6:8B:D9:A0:BA:C0:A0:89:85:AB:47:BF:0F:BB:EB:D0
```

All of these are the same authority written four ways, and all four are understood
wherever an authority is named. Separators are dropped and capitals folded:

```sh
run_in lab-manager as admin pvxcert -l --where "issuer:53e8042c"
run_in lab-manager as admin pvxcert -l --where "issuer:53E8042C"
run_in lab-manager as admin pvxcert -l --where "issuer:53E8042CF68BD9A0BAC0A08985AB47BF0FBBEBD0"
run_in lab-manager as admin pvxcert -l --where "issuer:'53:E8:04:2C:F6:8B:D9:A0:BA:C0:A0:89:85:AB:47:BF:0F:BB:EB:D0'"
```

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
#   The issuer '53e8042c' is only 8 of the 40 digits of a subject key identifier, which is
#   not enough to decide which certificate authority to trust ...
run_in lab as guest authnstd -u client --issuer ${LAB_SKID}      # accepted
```

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
#   CERT:CREATE:<lab>(?::.*)? ALLOW CERT_CREATE   ask this department for a certificate
#   CERT:STATUS:<lab>(?::.*)? ALLOW CERT_STATUS   check one it issued
#   CERT:LIST:<lab>:ALL ALLOW CERT_STATUS         the two open views
#   CERT:LIST:<lab>:EXPIRING ALLOW CERT_STATUS
run_in ml-gateway as gateway cat /home/gateway/gateway.pvlist
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
run_in perimeter  as operator authnstd -u client --issuer ${ML_SKID}
run_in ml-manager as admin    pvxcert --review-pending --all approve --yes
```

That client now holds a **machine-learning-issued** certificate. It uses it to write to a
**lab** controller, through the **lab** gateway:

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

## 4. The request identifier an administrator checks

The certificate creation request travels in clear text, so an administrator has to be able
to compare what is on screen against what the requester sent. `authnstd` prints an
identifier for the requester to quote:

```sh
run_in lab as guest authnstd -u client
#   email this Certificate Request ID: 4KFD-Z215-WGFD-977M, to your SPVA administrator
```

The administrator sees the same identifier, in the same grouping, against the request:

```sh
run_in lab-manager as admin pvxcert --review-pending < /dev/null
#     Subject        : CN=guest,O=epics.org,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : 4KFD-Z215-WGFD-977M
```

It is also a column in the listing:

```sh
run_in lab-manager as admin pvxcert -l
```

## 5. Listing certificates

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
run_in lab-manager as admin pvxcert -l | awk '{print $NF}' | tail -n +2    # identifiers present
run_in lab as guest without a certificate pvxcert -l | awk '{print $NF}' | tail -n +2    # blank
```

That identifier is what the requester quotes to prove a request is theirs, so it is shown
only to whoever is deciding.

The same listing is served as standing views a client can subscribe to, named by issuer so
that two certificate managers on one network are never ambiguous:

```sh
run_in lab as guest pvxmonitor CERT:LIST:${LAB}:ALL
run_in lab as guest pvxmonitor CERT:LIST:${LAB}:EXPIRING
```

Those two are open to everyone. The third is not - see section 9.

## 6. Filtering the listing

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

## 7. Approving, in batches or one at a time

There are two separate questions - *what is the decision* and *are you sure* - and `--all`
and `--yes` answer one each. That gives four ways of working, from reading every request to
approving a hundred without being asked anything, and you choose how far to go.

**Neither.** Each certificate in turn, with its subject and its request identifier in front
of you, and a decision for each:

```sh
run_in lab-manager as admin pvxcert --review-pending
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

## 8. Denying and revoking

A denial is not a separate state: the certificate manager writes `REVOKED`, and the review
shows that before you confirm.

```sh
run_in lab-manager as admin pvxcert --review-pending --all deny --yes
```

Revocation works over the issued certificates, and unlike a pending review it *can* be
narrowed by the filter from section 6. The same three levels of control apply:

```sh
run_in lab-manager as admin pvxcert --review-issued --where "state:VALID"                 # one at a time
run_in lab-manager as admin pvxcert --review-issued --where "name:guest" --all            # decided, still confirmed
run_in lab-manager as admin pvxcert --review-issued --where "name:testioc" --all --yes    # the whole batch
run_in lab-manager as admin pvxcert -R "${LAB}:0123456789"                                # one known certificate
```

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
run_in lab-manager as admin pvxcert --review-issued --where "state:VALID" < /dev/null
#     Not offered    : status REVOKED cannot be revoked
```

**An ordinary user may revoke their own certificate, and that is the point of it for them.**
A key has leaked and they want it stopped now, without finding an administrator first:

```sh
run_in lab as guest pvxcert -R "${LAB}:02665075835003669104"
#   Revoke ==> CERT:STATUS:ba71d9e3:02665075835003669104 ==> Completed Successfully
```

They may revoke that one and no other. Someone else's is refused, and the message names the
identity the certificate manager saw rather than the certificate:

```sh
run_in lab as guest pvxcert -R "${LAB}:04214365283771761526"    # the controller's
#   ERROR ... REVOKED operation not authorized on ba71d9e3:... by ca/guest@...
```

The one identity this runs the other way for is the administrator's own certificate. A
certificate manager refuses that, because it is the identity it needs in order to keep
answering at all. The tool cannot tell an administrator's keychain from anyone else's - the
listing looks the same for both - so it offers the certificate like any other and reports
what the manager says:

```sh
run_in lab-manager as admin pvxcert -R "${LAB}:11277229790059579580"   # the administrator's own
#   ERROR ... REVOKED Admin Self-Revoke not permitted on ba71d9e3:...
```

A failed write does not stop the ones after it, the certificate manager's own message is
shown against the certificate it belongs to, and a partly successful batch exits 5.

## 9. Only an administrator may decide

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
both ways shows exactly where the line falls:

```sh
run_in lab-manager as admin pvxcert --review-pending < /dev/null
#     Subject        : CN=operator,O=lab-client,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : A0MP-TAKG-JG1P-YJED

run_in lab as guest without a certificate pvxcert --review-pending < /dev/null
#     Subject        : CN=operator,O=lab-client,C=US
#     Status         : PENDING_APPROVAL
#     Request ID     : (none)
```

The certificate awaiting a decision is visible to both. The identifier that would let
someone confirm it is the request they were sent is not. And an attempt to act is refused
outright:

```sh
run_in lab as guest without a certificate pvxcert --review-issued --where "state:VALID" --all --yes
#   ... FAILED: REVOKED operation not authorized on ba71d9e3:... by ca/guest@...

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

**`authnstd` says there is no trusted issuer.** The department's issuer id has not reached
the shell. A login shell resets the environment; the start scripts write it to
`/etc/epics/issuer` for the profile in the image to read back. Check it:

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
