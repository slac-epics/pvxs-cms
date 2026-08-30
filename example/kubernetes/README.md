# Kubernetes: Secure PVAccess demonstration laboratories

Four self-contained laboratories that demonstrate Secure PVAccess: certificates requested,
approved, presented, checked, and revoked, between real IOCs, certificate managers,
gateways, and workstations, all running as Kubernetes objects in one local cluster.

These are the same four laboratories as [`example/podman`](../podman/README.md), rendered
in Kubernetes. The walkthroughs run the same commands with a `k` in front.

## The four laboratories

| Part | Topology                    | What it demonstrates                                                                                       |
| ---- | --------------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1    | `simple`                    | One department. Certificates issued, approved, presented; access rules deciding who may write              |
| 2    | `simple-with-gateway`       | A gateway on a boundary that carries TLS alone, and a workstation on the internet that starts with nothing |
| 3    | `federated-shared-root`     | Two departments under one facility root; revocation of a department's authority, and of the root itself    |
| 4    | `federated-non-shared-root` | Two departments under two independent roots that share nothing; establishing trust with multiple roots     |

Each part has a diagram of its Kubernetes objects, in [`topology/`](topology/):
pods, Services, NetworkPolicies, PersistentVolumeClaims, Secrets and ConfigMaps, and the
minting Job where one exists.

- [Part 1: `topology/topology-simple.svg`](topology/topology-simple.svg)
- [Part 2: `topology/topology-simple-with-gateway.svg`](topology/topology-simple-with-gateway.svg)
- [Part 3: `topology/topology-federated-shared-root.svg`](topology/topology-federated-shared-root.svg)
- [Part 4: `topology/topology-federated-non-shared-root.svg`](topology/topology-federated-non-shared-root.svg)

## Prerequisites

- The laboratory images, built by the podman example: run
  [`../podman/bootstrap.sh`](../podman/bootstrap.sh) first. The cluster has no access to
  the host image store, so `kload_images` carries them in.
- `kind`, `helm`, `kubectl`, and either Docker Desktop or podman. Docker is preferred
  when a real Docker daemon is running; podman is the fallback, using kind's experimental
  provider. `helpers.sh` picks the runtime itself and is not fooled by a `docker` command
  that is really a symlink to podman.
- If `KIND_EXPERIMENTAL_PROVIDER` is exported in your shell from earlier work, unset it.
  It overrides the runtime detection.

## Bring the cluster up

Source the helpers, create the cluster, and load the images:

```sh
cd pvxs-cms/example/kubernetes
export DOCKER_REGISTRY=docker.io DOCKER_USERNAME=georgeleveln   # as used at image build
. ./helpers.sh
kind_create
kload_images
```

`kind_create` builds a one-node `kind` cluster named `spva-lab` with the default network
plugin turned off, then installs Cilium with Hubble enabled. Hubble is worth having: it
shows every flow with pod identity, which is how you see in one command that a client
went straight to a pod rather than through the Service in front of it.

Then build a laboratory:

```sh
kreset_topology simple-with-gateway
```

`kreset_topology` with no argument lists the four laboratories and builds nothing. Every
reset destroys whatever laboratory was up, claims and authorities included, and checks
the new one before handing it to you. The checks are the acceptance criteria, not a
smoke test; the last one for Part 2 is a negative, and a laboratory that passes the
others while failing it has an open boundary.

To take a laboratory away and build nothing in its place:

```sh
kreset_topology clear             # the laboratory; the cluster stays
kreset_topology clear --cluster   # the cluster too
```

The podman and Kubernetes laboratories share one podman machine but are entirely
separate instances: separate containers, separate networks, separate certificate
authorities. `reset_topology clear` over in the podman directory takes that one away;
neither clear can see the other's laboratory.

## The commands

The commands take the same words in the same order as the podman helpers, with a `k` in
front.

### `krun_in`: run something, somewhere, as someone

```
krun_in <place> as <person> [without a certificate] [--show] <command...>
```

Places: `lab`, `ml`, `internet` (also accepted as `internet`), `lab-pvacms`,
`ml-pvacms`, `testioc`, `tstioc`, `ml-ioc`, `gateway`, `ml-gateway`. People: `guest`
and `operator` at workstations, `admin` on a certificate manager, and each service as
itself. A place that exists but not in the laboratory currently up is refused with a
message saying which laboratory is up and what it does have.

`without a certificate` runs the same person presenting nothing. `--show` prints the
`kubectl` command that would run, without running it.

Two Kubernetes notes, both invisible in ordinary use:

- `kubectl exec` has no equivalent of `podman exec --user`, so a person is become with
  `su -`, which is a login shell and discards the pod's environment. `krun_in` writes
  the pod's `EPICS_PVA` settings out before the `su` and reads them back after the login
  profile has had its say, so the pod's addressing always wins.
- The login profiles name the federated laboratory's hosts. `krun_in` unsets and
  restores all four `EPICS_PVA` addressing variables so a setting this laboratory does
  not make cannot survive from the profile.

### `krestart`: three different things called a restart

```sh
krestart testioc            # the softIoc alone, inside the running pod
krestart testioc pod        # delete the pod; the Deployment replaces it
krestart testioc service    # roll the Deployment behind the Service
```

The Service keeps its address through all three, and keychains live on
PersistentVolumeClaims, so the replacement pod is the same certificate holder as the old
one. A pod restart is a restart, not a revocation.

### `kgo_tls`: everything the walkthrough does by hand, in order

Issues certificates for every place in the laboratory that is up, approves them on the
manager that issued them, restarts what now holds one, carries the trust anchor to the
outside workstation where the laboratory has one, and proves the boundary opens. The
order is not a preference: IOCs before the gateway, because a gateway with the plaintext
listener closed serves nothing at all until it holds a certificate, and the outside
workstation last, because it cannot ask for anything until the anchor has been carried
across.

### `kcarry_anchor`: the authority, carried across by hand

Copies the certificate manager's `trust_anchor.p12` to the outside workstation's users,
never over an existing identity. Carrying it by hand is the point of Part 2's opening,
so no chart mounts it anywhere.

### `kauthority_says`, `kauthority_revoke`, `kauthority_restore`

Part 3 only. The facility root has no status process variable of its own; a responder
answers for it from one line in an index file on the `ocsp-state` claim. Revoking the
root is a rewrite of that line plus a responder restart, and restoring it is the same
edit backwards. Restore is a laboratory convenience, not a recovery.

## Part 1: simple

Diagram: [`topology/topology-simple.svg`](topology/topology-simple.svg)

One department: a certificate manager that mints its own authority the first time it
starts, two IOCs each behind a ClusterIP Service, and a workstation. Build it:

```sh
kreset_topology simple
```

```
The simple laboratory is up with no certificates issued:
    one lab, two IOCs, one pvacms

```

The reset also prints `$ROOT` and `$ROOT_SKID`, the authority's issuer identifier in its
short and whole forms, and exports both into your shell.

Reading needs nothing. Writing needs a certificate, and nothing holds one yet:

```sh
krun_in lab as guest without a certificate pvxget test:aiExample
#   value double = 10 ...
krun_in lab as guest without a certificate pvxput test:stringExample hello
#   ERROR ... Put not permitted
```

Everyone asks for a certificate, the administrator approves the lot, and the IOCs pick
theirs up:

```sh
krun_in lab as guest    authnstd -u client
krun_in lab as operator authnstd -u client
krun_in testioc as testioc authnstd -u ioc
krun_in tstioc  as tstioc  authnstd -u ioc
krun_in lab-pvacms as admin pvxcert --review-pending --all approve --yes
krestart testioc
krestart tstioc
```

Now the access rules decide, and they distinguish people:

```sh
krun_in lab as operator pvxput test:spec 3     # written: SPECIAL grants operators
krun_in lab as guest    pvxput test:spec 3     # refused: guest is not an operator
krun_in lab as guest    pvxput test:open 3     # written: OPEN grants any holder
```

`test:open` is the rule worth reading twice: it names no user group at all. Its
condition is only that a certificate was presented over TLS and chains to the
laboratory's authority.

**THE DIFFERENCE.** After the manager mints its authority, the issuer identifier is
read back into ConfigMap `lab-issuer` and every Deployment is rolled to mount it, and
the reset then confirms the identifier has actually reached a workstation before
declaring the laboratory up. A rollout reporting finished means the new pod is running,
not that the file it mounts has caught up, and everything after that point asks for
certificates from an authority named by that file.

## Part 2: simple, with a gateway

Diagram: [`topology/topology-simple-with-gateway.svg`](topology/topology-simple-with-gateway.svg)

Part 1, plus a boundary. The gateway serves TLS and nothing else
(`EPICS_PVAS_SERVER_PORT: "NO"`), a Service named `facility` in front of it is the one
name the outside knows, and only the secure port is published through it. The outside
workstation starts holding nothing.

```sh
kreset_topology simple-with-gateway
```

```
    the boundary lets nothing in yet: it carries TLS alone, and the workstation
    outside has not been given the authority to verify it with
```

That last line is a negative check, and it is what NetworkPolicy enforcement looks
like: with nothing in its keychain, the workstation outside cannot verify what answers,
so it never gets far enough to be told no about any particular name. Before
certificates exist, the gateway has no TLS to serve and therefore no listener at all;
`krun_in gateway as gateway sh -c 'ss -lnt'` shows nothing on 5076 until `kgo_tls` has
run.

Provision everything:

```sh
kgo_tls
```

```
==> carrying the authority to the workstation outside
    carried to guest
    carried to operator
==> asking for a certificate from outside, across the boundary
Certificate identifier  : <issuer>:<serial>
==> reading across the boundary
    the boundary is open to a holder with a valid certificate
```

The anchor is carried by hand, `podman cp` in the podman walkthrough and `kubectl cp`
here, because that is the story: trust arrives out of band, and everything after it can
be verified. The outside workstation then requests its own identity across the boundary
as `remote`, and the walkthrough's three writes behave exactly as they do in podman:

```sh
krun_in internet as guest pvxput test:stringExample 9   # refused: DEFAULT grants no write
krun_in internet as guest pvxput test:spec 9            # refused: SPECIAL wants an operator
krun_in internet as guest pvxput test:open 9            # written
krun_in internet as guest pvxget test:open              # value double = 9
```

**Why the outside workstation is configured with `no_own_cert_status_check`.** A holder
normally establishes the status of its own certificate before using it. This
workstation cannot: the certificate manager is on the other side of a boundary it can
only cross with TLS. The searches it makes are carried over a TLS name server
(`pvas://facility:5076`), the gateway checks what is presented to it and refuses a
holder whose certificate is not valid, so the check is made where the connection is accepted. The
entitlement belongs to the search, not to any one connection: a channel found by a TLS
search keeps it even when the channel is later created over a different connection.
That last sentence is load-bearing in Kubernetes, where the gateway's advertised
address is reachable and clients leave the name server connection; in podman the
advertised address is unreachable and the distinction never shows.

**A defect worth knowing about.** The gateway's configuration must carry
`"readOnly": false`. Without it, `pvagw` attaches no access file to any channel:
every read forwards and every write is refused, whatever the rules say, which presents
as a permissions problem three steps from the cause.

## Part 3: federated, one facility root

Diagram: [`topology/topology-federated-shared-root.svg`](topology/topology-federated-shared-root.svg)

Two departments under one facility root. Each has its own certificate manager signing
with its own intermediate, its own IOCs and workstation, and its own gateway. A
department reaches its peer through the `facility` Service, where the port chooses the
department: 5075 and 5076 reach the lab, 5175 and 5176 reach the ML department. The
root itself is answered for by a responder, because a root has no status process
variable of its own.

```sh
kreset_topology federated-shared-root
```

```
    the responder answers for the facility root
    each certificate manager answers its administrator
    reading works, from each department and from outside
    a write with no certificate is refused, by the IOC and at the boundary
```

The reset exports `$LAB`, `$ML`, `$LAB_SKID`, and `$ML_SKID`.

**The authorities are minted before anything starts.** A pre-install Job runs
`gen_lab_certs` once: a facility root, an intermediate for each department, and the
responder's material. Each manager's Secret holds only its own intermediate; the root's
key is never packaged at all. The Job is guarded so that it mints once per laboratory,
not once per helm operation; an upgrade that re-minted authorities mid-life would leave
the managers signing with roots that nothing else still trusts.

Issue certificates in both departments and approve each on the manager that issued it:

```sh
krun_in lab as guest    authnstd -u client
krun_in ml  as guest    authnstd -u client
krun_in testioc as testioc authnstd -u ioc
krun_in tstioc  as tstioc  authnstd -u ioc
krun_in ml-ioc  as mlioc   authnstd -u ioc
krun_in gateway    as gateway authnstd -u ioc
krun_in ml-gateway as gateway authnstd -u ioc
krun_in lab-pvacms as admin pvxcert --review-pending --all approve --yes
krun_in ml-pvacms  as admin pvxcert --review-pending --all approve --yes
```

Cross the departments as identified peers. The chain each side is shown names the
facility root above the peer's intermediate:

```sh
krun_in lab as operator pvxinfo -v ml:aiExample | grep '^#'
# TLS x509:<serial>:EPICS Root Certificate Authority -> EPICS ML Intermediate CA/gateway@...
krun_in ml as guest pvxput test:open 31        # written, across the boundary
```

**Only the department that issued a certificate can report on its status.** Every
status route therefore crosses to the peer: an IOC asks through the facility's peer
port (`EPICS_PVAS_STATUS_NAME_SERVERS: facility:5175` on a lab IOC), and a gateway asks
the peer gateway directly, a setting read by its inner status client alone so nothing
else is given the route.

### Revoke a department's authority

The ML administrator revokes their own intermediate, and nobody else can:

```sh
krun_in ml-pvacms as admin pvxcert -R "${ML}:00000000009876543213"
```

Within seconds, every ML holder reports `AUTHORITY_REVOKED`, the word that says the
fault is above the holder: their own certificates were never touched, and asking the
same authority for another one would not help. The lab department is untouched:

```sh
krun_in ml  as guest    pvxcert -f /home/guest/.config/pva/1.5/client.p12    # AUTHORITY_REVOKED
krun_in lab as operator pvxcert -f /home/operator/.config/pva/1.5/client.p12 # VALID
```

The ML manager's own service certificate is signed by the revoked intermediate too, so
its secure port goes with it, and its administrator tooling stops answering. That is
the rule working, not a broken laboratory; it behaves identically under podman. A reset
is the way back.

### Revoke the facility root

```sh
kauthority_revoke
#   the facility root is REVOKED
```

The responder now answers `revoked` for the root, and within one responder validity
window both departments degrade, because everything either of them issued chains to it:

```sh
krun_in ml  as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12   # AUTHORITY_REVOKED
krun_in lab as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12   # AUTHORITY_REVOKED
```

`kauthority_restore` puts the answer back so the demonstration can run again. A fresh
status enquiry recovers on its own; a connection that already degraded stays degraded
until the process behind it restarts, and in a real facility recovery would mean a new
root, not an edited index.

## Part 4: federated, two independent roots

Diagram: [`topology/topology-federated-non-shared-root.svg`](topology/topology-federated-non-shared-root.svg)

Two departments under two roots that share nothing. There is no facility above them: no
load balancer, no responder, no common ancestor. Each gateway is addressed by its own
name, both serve 5075 and 5076, and trust crosses only because every keychain holds
both roots as anchors: one identity, many anchors.

```sh
kreset_topology federated-non-shared-root
```

The minting Job differs to match: `gen_lab_certs` mints the lab root and the Controls
intermediate and then discards the lab root's key; the ML root is minted by `pvacms`
itself, exactly as a first start would, and that department signs with its root
directly; both roots, without keys, are packaged as Secret `trust-anchors` and mounted
into every IOC, gateway, and workstation at `/certs/trust_anchors.p12`.

**Anchors first, identities second.** A user establishes trust before asking for
anything, naming both authorities by their whole identifiers:

```sh
krun_in ml  as guest    authnstd --trust-anchor --issuer "${LAB_SKID} ${ML_SKID}"
krun_in lab as operator authnstd --trust-anchor --issuer "${LAB_SKID} ${ML_SKID}"
```

The whole 40-digit identifier is required for first-use trust, and the tool refuses the
short form with an explanation when the authority is not already held. After the
anchors are in place the short form is enough to choose between them:

```sh
krun_in ml  as guest    authnstd -u client --issuer "${ML}"
krun_in lab as operator authnstd -u client --issuer "${LAB}"
```

Approve on each manager, restart the holders, and trust crosses roots that share
nothing. Each side accepts a chain ending in a root its own department never issued,
because the anchor list says to:

```sh
krun_in ml as guest pvxinfo -v test:aiExample | grep '^#'
# TLS x509:...:EPICS Lab Root Certificate Authority -> EPICS Controls Intermediate CA/gateway@...
krun_in ml as guest pvxput test:open 41        # written
krun_in ml as guest pvxput test:spec 9         # refused: operators only
```

**The access files are part of the topology.** The gateways and IOCs mount access files
naming both roots (`AUTHORITY(LAB_CA, ...)`, `AUTHORITY(ML_CA, ...)`) over the ones
baked into the images, which name Part 3's shared root. A rule naming an authority that
does not exist matches no holder, and every write is refused with nothing looking
wrong.

## When something goes wrong

- **A cross-boundary read times out right after provisioning.** A gateway makes its
  upstream connections when it starts and does not retry the ones it could not make.
  Restart the gateways after the IOCs are serving: `kubectl -n spva-lab rollout restart
  deploy/pvxs-lab-gateway`, or run `kreset_topology`, which does this for you.
- **Everything reads but nothing writes, through a gateway.** Check `"readOnly": false`
  is present in the gateway's configuration, and check the writer actually holds an
  identity: a keychain holding only an anchor reads fine and fails every write, because
  a gateway forwards reads regardless and the holder is anonymous.
- **`no certificate manager answered CERT:CREATE:...`.** The issuer identifier in the
  requesting pod does not match the authority that is actually serving. In Part 1 style
  laboratories the identifier is distributed after the authority exists; make sure the
  reset completed, and re-source `helpers.sh` if it is stale in your shell.
- **The laboratory appears to work but the boundary checks fail.** The cluster has no
  policy-enforcing network plugin, so every NetworkPolicy is silently ignored. Build
  the cluster with `kind_create`, which installs Cilium.
- **A reset hangs.** Do not delete PersistentVolumeClaims while pods still mount them;
  the deletion waits forever. `kreset_topology` takes the workloads down first and
  bounds every wait, so prefer it over hand-rolled cleanup.
- **Watching the traffic.** Hubble shows flows with pod identity:
  `kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --pod
  spva-lab/internet-client`. One line per flow, named at both ends; it answers "who
  actually connected to whom" in seconds.

## The files

| Path | What it is |
|---|---|
| `helpers.sh` | The commands: `kreset_topology`, `krun_in`, `krestart`, `kgo_tls`, `kcarry_anchor`, `kauthority_*`, `kind_create`, `kload_images` |
| `kind-cluster.yaml` | The cluster: one node, default network plugin off |
| `helm/simple` | Part 1 chart |
| `helm/simple-with-gateway` | Part 2 chart |
| `helm/federated-shared-root` | Part 3 chart, including the minting Job and the responder |
| `helm/federated-non-shared-root` | Part 4 chart, including the two-root minting Job |
| `helm/*/files/` | Start scripts and access files, taken verbatim from the podman topology so the two stay in step |
| `topology/` | The four diagrams and the scripts that draw them |
| `docker/` | The image definitions, shared with and built by the podman example |
