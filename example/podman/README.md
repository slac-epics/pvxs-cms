# Secure PVAccess demonstration laboratory, on podman

A two-department Secure PVAccess laboratory that runs on rootless podman with
`podman-compose`. No Kubernetes, no Helm, no cluster.

It stands up two independent certificate managers under one facility root, a gateway on
each department's boundary, controllers on both sides, and a client outside both that can
only reach anything through a gateway.

## What it demonstrates

- **Two departments, each running its own certificate manager**, each signing with its own
  intermediate certificate authority.
- **One facility root that every node trusts.** A certificate issued by either department
  is trusted laboratory-wide, so federated trust decisions can be written in access
  security files. Authorisation stays per department: an administrator of one is not an
  administrator of the other, because each certificate manager's write rule names its own
  authority.
- **A gateway on each boundary**, forwarding its own department's certificate process
  variables keyed by issuer id, so two certificate managers on one network are never
  ambiguous.
- **Real network separation.** Three podman networks; a container reaches only those it is
  attached to. The perimeter client physically cannot address a certificate manager.

## Requirements

- podman and podman-compose
- The four source trees checked out as siblings: `pvxs-cms`, `pvxs`, `epics-base`, `p4p`

## Getting started

```sh
cd pvxs-cms/example/podman
./bootstrap.sh              # builds the images, mints the authorities
podman-compose up -d
podman-compose ps
```

`bootstrap.sh` writes `issuer_ids.env`, holding the two departments' issuer ids. Compose
reads it, and the gateways substitute their own id into their process variable lists.

### Issue the certificates

Nothing holds a certificate yet. Each service asks for one, and each department's
administrator approves its own.

```sh
# a controller asks
podman-compose exec pvxs-lab-testioc authnstd -u server

# the lab administrator approves everything waiting
podman-compose exec pvxs-lab-pvacms pvxcert --review-pending --all approve --yes

# the machine learning side, on its own certificate manager
podman-compose exec pvxs-lab-ml-ioc authnstd -u server
podman-compose exec pvxs-lab-ml pvxcert --review-pending --all approve --yes

# gateways last: they need the controllers valid before they can connect upstream
podman-compose exec pvxs-lab-gateway    authnstd -u ioc
podman-compose exec pvxs-lab-ml-gateway authnstd -u ioc -n ml-gateway
podman-compose exec pvxs-lab-pvacms pvxcert --review-pending --all approve --yes
podman-compose exec pvxs-lab-ml     pvxcert --review-pending --all approve --yes

podman-compose restart pvxs-lab-testioc pvxs-lab-ml-ioc pvxs-lab-gateway pvxs-lab-ml-gateway
```

`--review-pending` lists what is waiting with the subject and the request identifier and
asks about each in turn; `--all approve --yes` takes them all without asking. Drop
`--all --yes` to step through them.

### Check it works

```sh
# inside a department, directly
podman-compose exec lab-client pvxget test:aiExample

# from outside both, through a gateway
podman-compose exec perimeter-client pvxget test:aiExample
podman-compose exec perimeter-client pvxget ml:aiExample

# what each department has issued
podman-compose exec pvxs-lab-pvacms pvxcert -l
podman-compose exec pvxs-lab-ml     pvxcert -l
```

## The layout

| Service | Network(s) | What it is |
|---|---|---|
| `pvxs-lab-pvacms` | lab | the lab department's certificate manager |
| `pvxs-lab-testioc`, `pvxs-lab-tstioc` | lab | lab controllers, serving `test:` and `tst:` |
| `pvxs-lab-gateway` | lab + perimeter | the lab boundary |
| `pvxs-lab-ml` | ml | the second department's certificate manager |
| `pvxs-lab-ml-ioc` | ml | its controller, serving `ml:` |
| `pvxs-lab-ml-gateway` | ml + perimeter | its boundary |
| `lab-client` | lab | a shell inside the lab department |
| `perimeter-client` | perimeter | a shell outside both |

Service names are the DNS names, and they match the names used in the shell profiles and
the gateway configuration inside the images, so nothing needs rewriting per environment.

## Configuration you will want to read

- `config/pvacms-lab.acf`, `config/pvacms-ml.acf` - each certificate manager's access
  security file. The administrator write rule names the user access group, that
  department's own authority, the protocol and the method. All four clauses matter: drop
  the authority and a name match alone makes someone an administrator of both departments.
- `config/gateway-lab.pvlist`, `config/gateway-ml.pvlist` - what each gateway forwards.
  Certificate process variables are named by issuer id, substituted at start.
- `config/gateway-lab.conf`, `config/gateway-ml.conf` - the gateway's own client and
  server configuration, including its keychain.

These are the same files the Kubernetes laboratory uses; they are extracted from that
chart so the two cannot drift apart.

## Notes

- **The perimeter client reaches the gateways and nothing else.** That is the point: it
  exercises the gateway path. If a process variable does not resolve from there, the fault
  is in the gateway chain - its configuration, its process variable list, its access
  security file, or its own certificate - not in the client.
- **A gateway makes its upstream connection as itself.** A certificate manager reached
  through one sees the gateway, not the user behind it. Anything gated on being an
  administrator therefore has to be done from inside that department.
- **Each department only knows its own certificates.** A certificate manager asked about
  another department's certificate never held it. The issuer half of an `<issuer>:<serial>`
  identifier says which department to ask.

## Starting over

```sh
podman-compose down -v      # removes the volumes, including every issued certificate
./bootstrap.sh              # fresh authorities
```

To rebuild the images without discarding the certificates:

```sh
./bootstrap.sh --keep-certs
```
