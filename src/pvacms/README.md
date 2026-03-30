# PVACMS — PVAccess Certificate Management Service

PVACMS is a Certificate Authority for EPICS PVAccess.  It handles certificate
provisioning, online certificate status (OCSP-like over PVA), revocation,
approval workflows, and renewal.  With `--cluster-mode`, PVACMS forms a
self-organizing cluster that replicates certificate operations across all
members.  Without it, PVACMS runs as a standalone node.

## Building

PVACMS is conditionally compiled via the `PVXS_ENABLE_PVACMS` macro in
`src/Makefile` (default: `YES` for native builds, `NO` for cross-compilation).

**Dependencies**: EPICS Base, pvxs, SQLite3, OpenSSL.

```sh
make            # from repo root
make -C src     # executable only
```

The executable is installed to `bin/<arch>/pvacms`.

## Quick Start

```sh
pvacms
```

On first run PVACMS creates all required artifacts with default paths: CA
keychain, service keychain, admin keychain, SQLite database, and access control
file.

For development or testing, skip the approval workflow:

```sh
pvacms --certs-dont-require-approval
```

Print version and exit:

```sh
pvacms -V
```

## Runtime Artifacts

All default paths follow the XDG Base Directory Specification.
`XDG_CONFIG_HOME` defaults to `~/.config`; `XDG_DATA_HOME` defaults to
`~/.local/share`.

| Artifact | Default Path | CLI Flag | Env Var |
|----------|-------------|----------|---------|
| Certificate DB | `${XDG_DATA_HOME}/pva/1.5/certs.db` | `-d, --cert-db` | `EPICS_PVACMS_DB` |
| CA Keychain | `${XDG_CONFIG_HOME}/pva/1.5/cert_auth.p12` | `-c, --cert-auth-keychain` | `EPICS_CERT_AUTH_TLS_KEYCHAIN` |
| Service Keychain | `${XDG_CONFIG_HOME}/pva/1.5/pvacms.p12` | `-p, --pvacms-keychain` | `EPICS_PVACMS_TLS_KEYCHAIN` |
| Admin Keychain | `${XDG_CONFIG_HOME}/pva/1.5/admin.p12` | `-a, --admin-keychain` | `EPICS_ADMIN_TLS_KEYCHAIN` |
| Access Control File | `${XDG_CONFIG_HOME}/pva/1.5/pvacms.acf` | `--acf` | `EPICS_PVACMS_ACF` |

Password files for each keychain can be specified via the corresponding
`*_PWD_FILE` environment variable (e.g. `EPICS_CERT_AUTH_TLS_KEYCHAIN_PWD_FILE`).

## PV Interface

The default PV prefix is `CERT`, configurable with `--cert-pv-prefix`.

### Certificate Operations

| PV Name | Type | Description |
|---------|------|-------------|
| `CERT:CREATE[:<issuer_id>]` | RPC | Submit a Certificate Creation Request (CCR) |
| `CERT:STATUS:<issuer_id>:<serial>` | Monitor / Put | Per-certificate status (wildcard listener) |
| `CERT:ROOT[:<issuer_id>]` | Get | CA root certificate |
| `CERT:ISSUER[:<issuer_id>]` | Get | Issuer (intermediate) certificate |

### Cluster (internal)

| PV Name | Type | Description |
|---------|------|-------------|
| `CERT:CLUSTER:CTRL:<issuer_id>` | RPC / Monitor | Cluster membership and join |
| `CERT:CLUSTER:SYNC:<issuer_id>:<node_id>` | Monitor | Per-node certificate database sync |

## Certificate Lifecycle

| State | Description |
|-------|-------------|
| `PENDING_APPROVAL` | Awaiting admin approval (standard auth only) |
| `PENDING` | Approved; waiting for validity start date |
| `VALID` | Active certificate |
| `PENDING_RENEWAL` | Renewal deadline passed; certificate invalid until renewed |
| `EXPIRED` | Past validity end date |
| `REVOKED` | Permanently revoked (irreversible) |

## Authentication Methods

PVACMS supports pluggable authentication for CCR verification.

| Method | Auto-Approved | Configuration |
|--------|--------------|---------------|
| Standard | No | Default; identity is hostname + username |
| Kerberos | Yes | `EPICS_AUTH_KRB_REALM`, `EPICS_AUTH_KRB_VALIDATOR_SERVICE` |
| LDAP | Yes | `EPICS_AUTH_LDAP_HOST`, `EPICS_AUTH_LDAP_PORT` |

Standard-auth certificates require explicit admin approval via the status PV.
Kerberos and LDAP certificates are auto-approved because the identity is
validated by the external authentication infrastructure.

## Configuration Reference

All flags can also be set via the listed environment variable.  CLI flags take
precedence.

### Certificate Validity

Duration format: `1y 2M 3w 4d 5h 6m 7s` (components are optional).

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cert_validity` | `EPICS_PVACMS_CERT_VALIDITY` | — | Default duration for all cert types |
| `--cert_validity-client` | `EPICS_PVACMS_CERT_VALIDITY_CLIENT` | `6M` | Client certificate duration |
| `--cert_validity-server` | `EPICS_PVACMS_CERT_VALIDITY_SERVER` | `6M` | Server certificate duration |
| `--cert_validity-ioc` | `EPICS_PVACMS_CERT_VALIDITY_IOC` | `6M` | IOC certificate duration |
| `--disallow-custom-durations` | `EPICS_PVACMS_DISALLOW_CUSTOM_DURATION` | `NO` | Reject client-requested durations |

### Approval

| Flag | Env Var | Default |
|------|---------|---------|
| `--certs-dont-require-approval` | `EPICS_PVACMS_REQUIRE_APPROVAL` | `YES` (approval required) |
| `--client-dont-require-approval` | `EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL` | `YES` |
| `--server-dont-require-approval` | `EPICS_PVACMS_REQUIRE_SERVER_APPROVAL` | `YES` |
| `--ioc-dont-require-approval` | `EPICS_PVACMS_REQUIRE_IOC_APPROVAL` | `YES` |

### Status Monitoring

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--status-validity-mins` | `EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS` | `30` | Status response validity (minutes) |
| `--status-monitoring-enabled` | `EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION` | `DEFAULT` | Require status subscription (`YES` / `NO` / `DEFAULT`) |

### Cluster

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cluster-mode` | — | off | Enable cluster mode for multi-node replication |
| `--cluster-pv-prefix` | `EPICS_PVACMS_CLUSTER_PV_PREFIX` | `CERT:CLUSTER` | PV prefix for cluster channels |
| `--cluster-discovery-timeout` | `EPICS_PVACMS_CLUSTER_DISCOVERY_TIMEOUT` | `10` | Join RPC timeout in seconds |

### CA Identity

| Flag | Env Var | Default |
|------|---------|---------|
| `--cert-auth-name` | `EPICS_CERT_AUTH_NAME` | `EPICS Root Certificate Authority` |
| `--cert-auth-org` | `EPICS_CERT_AUTH_ORGANIZATION` | `certs.epics.org` |
| `--cert-auth-org-unit` | `EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT` | `EPICS Certificate Authority` |
| `--cert-auth-country` | `EPICS_CERT_AUTH_COUNTRY` | `US` |

## Clustering

With `--cluster-mode`, PVACMS forms a self-organizing cluster.  On startup each
node attempts to join an existing cluster via the CTRL PV, located using
standard PVAccess name resolution (UDP broadcast, `EPICS_PVA_ADDR_LIST`, or
`EPICS_PVA_NAME_SERVERS`).  No seed lists or manual introductions are needed —
all nodes sharing the same CA keychain belong to the same cluster.  If no
cluster is found, the node bootstraps as a sole-node cluster.  Certificate
operations performed on any node are replicated to all members via the SYNC PV
protocol.

Full mesh connectivity is preferred but not required.  Partial mesh is
supported via transitive data forwarding — nodes that cannot directly reach all
peers use connected intermediaries to relay certificate data through the
standard SYNC protocol.  Bidirectional connectivity is verified at join time;
if the responding node cannot reach the joiner, it steps aside so a different
cluster node can handle the join.

See [CLUSTER.md](CLUSTER.md) for the full clustering design.

## Access Control

PVACMS uses an EPICS Access Control File (ACF) to restrict operations.  The
default ACF defines three access security groups:

| ASG | Controls | Default Access |
|-----|----------|---------------|
| `CERT_CREATE` | Certificate creation requests | Open |
| `CERT_STATUS` | Certificate approval and revocation | Admin only |
| `CLUSTER` | Cluster join operations | PVACMS service identity only |

## Version

Current version: **1.1.0** (`configure/CONFIG_PVACMS_VERSION`).
