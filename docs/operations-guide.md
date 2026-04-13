# PVACMS Operations Guide

This guide covers deployment, configuration, monitoring, backup, and
troubleshooting for the PVAccess Certificate Management Service (PVACMS).

## Standalone Deployment

### Prerequisites

- EPICS Base (>= 3.15.1)
- pvxs library
- OpenSSL >= 3.2.1
- SQLite >= 3.48.0
- A C++11-compliant compiler

### Quick Start

Run `pvacms` with no arguments to start a standalone instance:

```sh
pvacms
```

On first run PVACMS automatically creates all required artifacts using
default paths:

| Artifact | Default Path |
|----------|-------------|
| CA keychain | `${XDG_CONFIG_HOME}/pva/1.5/cert_auth.p12` |
| Service keychain | `${XDG_CONFIG_HOME}/pva/1.5/pvacms.p12` |
| Admin keychain | `${XDG_CONFIG_HOME}/pva/1.5/admin.p12` |
| Certificate database | `${XDG_DATA_HOME}/pva/1.5/certs.db` |
| Access control file | `${XDG_CONFIG_HOME}/pva/1.5/pvacms.acf` |

`XDG_CONFIG_HOME` defaults to `~/.config` and `XDG_DATA_HOME` defaults to
`~/.local/share` when not set.

For development or testing, skip the approval workflow:

```sh
pvacms --certs-dont-require-approval
```

Print version and exit:

```sh
pvacms -V
```

### Startup Self-Tests

PVACMS runs the following checks before publishing any PVs:

1. **CA certificate chain validation** — verifies the chain is complete and no
   certificate is expired.
2. **CA private key match** — verifies the private key matches the CA
   certificate public key via signature verification.
3. **Database schema version** — verifies the schema version matches the
   expected version for the running code.
4. **Sign/verify round-trip** — performs a test signature with the CA private
   key and verifies it.

If any self-test fails, PVACMS logs the specific error and exits with a
non-zero code.

### Authentication Methods

| Method | Auto-Approved | Configuration |
|--------|--------------|---------------|
| Standard | No | Default; identity is hostname + username |
| Kerberos | Yes | `EPICS_AUTH_KRB_REALM`, `EPICS_AUTH_KRB_VALIDATOR_SERVICE` |
| LDAP | Yes | `EPICS_AUTH_LDAP_HOST`, `EPICS_AUTH_LDAP_PORT` |

Standard-auth certificates require explicit admin approval via the status PV.
Kerberos and LDAP certificates are auto-approved because identity is validated
by external authentication infrastructure.

## Cluster Deployment

Enable cluster mode with the `--cluster-mode` flag:

```sh
pvacms --cluster-mode
```

### How Clustering Works

PVACMS forms a self-organizing cluster. All nodes sharing the same CA keychain
belong to the same cluster. No seed lists or manual introductions are needed.

On startup each node attempts to join an existing cluster via PVAccess name
resolution (UDP broadcast, `EPICS_PVA_ADDR_LIST`, or
`EPICS_PVA_NAME_SERVERS`). If no cluster is found, the node bootstraps as a
sole-node cluster.

Certificate operations performed on any node are replicated to all members via
the SYNC PV protocol.

### Network Topology

Full mesh connectivity is preferred but not required. Partial mesh is supported
via transitive data forwarding — nodes that cannot directly reach all peers use
connected intermediaries to relay data through the standard SYNC protocol.
Bidirectional connectivity is verified at join time.

For environments where UDP search is unavailable (e.g., behind gateways), set
TCP name servers:

```sh
export EPICS_PVACMS_CLUSTER_NAME_SERVERS="gateway1:5075,gateway2:5075"
```

### Join / Leave / Failover

- **Join**: Start a new node with `--cluster-mode` and the same CA keychain.
  It auto-discovers the cluster and joins.
- **Leave**: Stop the node. Remaining members detect the departure.
- **Failover**: Any node can serve certificate requests. If a node fails, the
  remaining nodes continue serving. When the failed node restarts, it
  re-joins and receives any missed certificate operations via SYNC.

### Cluster Configuration

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cluster-mode` | — | off | Enable cluster mode |
| `--cluster-pv-prefix` | `EPICS_PVACMS_CLUSTER_PV_PREFIX` | `CERT:CLUSTER` | PV prefix for cluster channels |
| `--cluster-discovery-timeout` | `EPICS_PVACMS_CLUSTER_DISCOVERY_TIMEOUT` | `10` | Seconds to wait for cluster discovery |
| `--cluster-bidi-timeout` | `EPICS_PVACMS_CLUSTER_BIDI_TIMEOUT` | `5` | Bidirectional connectivity check timeout |
| `--cluster-skip-peer-identity-check` | — | off | Skip TLS peer identity verification |
| — | `EPICS_PVACMS_CLUSTER_NAME_SERVERS` | — | TCP name servers for gateway topologies |

## Configuration Reference

All CLI flags can also be set via the listed environment variable. CLI flags
take precedence over environment variables.

### Core

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `-h, --help` | — | — | Show help |
| `-v, --verbose` | — | off | Increase log verbosity |
| `-V, --version` | — | — | Print version and exit |

### File Paths

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `-c, --cert-auth-keychain` | `EPICS_CERT_AUTH_TLS_KEYCHAIN` | `${XDG_CONFIG_HOME}/pva/1.5/cert_auth.p12` | CA keychain file |
| `--cert-auth-keychain-pwd` | `EPICS_CERT_AUTH_TLS_KEYCHAIN_PWD_FILE` | — | CA keychain password file |
| `-d, --cert-db` | `EPICS_PVACMS_DB` | `${XDG_DATA_HOME}/pva/1.5/certs.db` | Certificate database file |
| `-p, --pvacms-keychain` | `EPICS_PVACMS_TLS_KEYCHAIN` | `${XDG_CONFIG_HOME}/pva/1.5/pvacms.p12` | PVACMS service keychain |
| `--pvacms-keychain-pwd` | `EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE` | — | PVACMS keychain password file |
| `-a, --admin-keychain` | `EPICS_ADMIN_TLS_KEYCHAIN` | `${XDG_CONFIG_HOME}/pva/1.5/admin.p12` | Admin keychain file |
| `--admin-keychain-pwd` | `EPICS_ADMIN_TLS_KEYCHAIN_PWD_FILE` | — | Admin keychain password file |
| `--admin-keychain-new` | — | — | Generate new admin keychain and exit |
| `--acf` | `EPICS_PVACMS_ACF` | `${XDG_CONFIG_HOME}/pva/1.5/pvacms.acf` | Access control file |
| `--preload-cert` | — | — | Keychain file(s) to preload into the DB |

### CA Identity

Used when creating a root certificate on first run.

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cert-auth-name` | `EPICS_CERT_AUTH_NAME` | `EPICS Root Certificate Authority` | CA certificate CN |
| `--cert-auth-org` | `EPICS_CERT_AUTH_ORGANIZATION` | `certs.epics.org` | CA certificate O |
| `--cert-auth-org-unit` | `EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT` | `EPICS Certificate Authority` | CA certificate OU |
| `--cert-auth-country` | `EPICS_CERT_AUTH_COUNTRY` | `US` | CA certificate C |

### PVACMS Service Identity

Used when creating the PVACMS service certificate on first run.

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--pvacms-name` | — | `PVACMS Service` | PVACMS certificate CN |
| `--pvacms-org` | — | `certs.epics.org` | PVACMS certificate O |
| `--pvacms-org-unit` | — | `EPICS PVA Certificate Management Service` | PVACMS certificate OU |
| `--pvacms-country` | — | `US` | PVACMS certificate C |

### Certificate Validity

Duration format: `1y 2M 3w 4d 5h 6m 7s` (components are optional).

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cert_validity` | `EPICS_PVACMS_CERT_VALIDITY` | — | Default duration for all cert types |
| `--cert_validity-client` | `EPICS_PVACMS_CERT_VALIDITY_CLIENT` | `6M` | Client certificate duration |
| `--cert_validity-server` | `EPICS_PVACMS_CERT_VALIDITY_SERVER` | `6M` | Server certificate duration |
| `--cert_validity-ioc` | `EPICS_PVACMS_CERT_VALIDITY_IOC` | `6M` | IOC certificate duration |
| `--disallow-custom-durations` | `EPICS_PVACMS_DISALLOW_CUSTOM_DURATION` | off | Reject client-requested durations |
| `--disallow-custom-durations-client` | `EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION` | off | Reject custom client durations |
| `--disallow-custom-durations-server` | `EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION` | off | Reject custom server durations |
| `--disallow-custom-durations-ioc` | `EPICS_PVACMS_DISALLOW_IOC_CUSTOM_DURATION` | off | Reject custom IOC durations |

### Approval

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--certs-dont-require-approval` | `EPICS_PVACMS_REQUIRE_APPROVAL` | off (approval required) | Generate all certs in VALID state |
| `--client-dont-require-approval` | `EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL` | off | Generate client certs in VALID state |
| `--server-dont-require-approval` | `EPICS_PVACMS_REQUIRE_SERVER_APPROVAL` | off | Generate server certs in VALID state |
| `--ioc-dont-require-approval` | `EPICS_PVACMS_REQUIRE_IOC_APPROVAL` | off | Generate IOC certs in VALID state |

### Status Monitoring

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--status-validity-mins` | `EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS` | `30` | Status response validity (minutes) |
| `--status-monitoring-enabled` | `EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION` | `DEFAULT` | Require status subscription (`YES`/`NO`/`DEFAULT`) |

### PV Prefixes

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--cert-pv-prefix` | — | `CERT` | Prefix for all PVs published by PVACMS |
| `--health-pv-prefix` | `EPICS_PVACMS_HEALTH_PV_PREFIX` | `CERT:HEALTH` | Health check PV prefix |
| `--metrics-pv-prefix` | `EPICS_PVACMS_METRICS_PV_PREFIX` | `CERT:METRICS` | Operational metrics PV prefix |
| `--cluster-pv-prefix` | `EPICS_PVACMS_CLUSTER_PV_PREFIX` | `CERT:CLUSTER` | Cluster PV prefix |

### Database and Reliability

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--integrity-check-interval` | `EPICS_PVACMS_INTEGRITY_CHECK_INTERVAL` | `86400` | Seconds between SQLite integrity checks and WAL checkpoints. 0 to disable |
| `--audit-retention-days` | `EPICS_PVACMS_AUDIT_RETENTION_DAYS` | `365` | Days to retain audit log records. 0 to disable pruning |
| `--rate-limit` | `EPICS_PVACMS_RATE_LIMIT` | `10` | CCR rate limit in requests/second. 0 to disable |
| `--rate-limit-burst` | `EPICS_PVACMS_RATE_LIMIT_BURST` | `50` | CCR burst capacity |
| `--max-concurrent-ccr` | `EPICS_PVACMS_MAX_CONCURRENT_CCR` | `100` | Maximum in-flight certificate creation requests |
| `--monitor-interval-min` | `EPICS_PVACMS_MONITOR_INTERVAL_MIN` | `5` | Minimum status monitor interval (seconds) |
| `--monitor-interval-max` | `EPICS_PVACMS_MONITOR_INTERVAL_MAX` | `60` | Maximum status monitor interval (seconds) |

### Backup

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--backup` | — | — | One-shot backup to specified path, then exit |
| `--backup-interval` | `EPICS_PVACMS_BACKUP_INTERVAL` | `0` | Seconds between periodic backups. 0 to disable |
| `--backup-dir` | `EPICS_PVACMS_BACKUP_DIR` | same directory as DB | Directory for periodic backup files |
| `--backup-retention` | `EPICS_PVACMS_BACKUP_RETENTION` | `7` | Maximum number of backup files to keep |

## Monitoring

PVACMS publishes two PVs for operational monitoring: a health check PV and an
operational metrics PV. Both are updated on every status monitor cycle.

### Health Check PV

Default name: `CERT:HEALTH` (configurable via `--health-pv-prefix`).

| Field | Type | Description |
|-------|------|-------------|
| `ok` | bool | Overall health. `false` if any subsystem is failing |
| `db_ok` | bool | Database passed most recent integrity check |
| `ca_valid` | bool | CA certificate chain is valid and not expired |
| `uptime_secs` | uint64 | Seconds since PVACMS started |
| `cert_count` | uint32 | Total certificates in the database |
| `cluster_members` | uint32 | Number of cluster members (1 in standalone mode) |
| `last_check` | string | Timestamp of most recent health evaluation |

Read the health PV:

```sh
pvxget CERT:HEALTH
```

Alert on `ok=false` to detect subsystem failures.

### Operational Metrics PV

Default name: `CERT:METRICS` (configurable via `--metrics-pv-prefix`).

| Field | Type | Description |
|-------|------|-------------|
| `certs_created` | uint64 | Total certificates created (monotonic counter) |
| `certs_revoked` | uint64 | Total certificates revoked (monotonic counter) |
| `certs_active` | uint32 | Currently active (VALID) certificates |
| `avg_ccr_time_ms` | double | Average certificate creation request time in milliseconds |
| `db_size_bytes` | uint64 | Database file size including WAL |
| `uptime_secs` | uint64 | Seconds since PVACMS started |

Read the metrics PV:

```sh
pvxget CERT:METRICS
```

Compute rates from monotonic counters by sampling at regular intervals and
calculating the difference.

### Prometheus Integration

Use a PVAccess-to-Prometheus exporter (e.g., pvaPy or a custom scraper) to
bridge PVACMS metrics into Prometheus. Map the `CERT:METRICS` fields to
Prometheus gauge and counter types:

- `certs_created` and `certs_revoked` map to Prometheus counters.
- `certs_active`, `avg_ccr_time_ms`, `db_size_bytes`, and `uptime_secs` map
  to Prometheus gauges.

### Nagios

Create a check script that reads the health PV and evaluates the `ok` field:

```sh
#!/bin/sh
result=$(pvxget -w 5 CERT:HEALTH 2>/dev/null)
if echo "$result" | grep -q 'ok.*true'; then
    echo "PVACMS OK"
    exit 0
else
    echo "PVACMS CRITICAL - health check failed"
    exit 2
fi
```

### Kubernetes Probes

Configure liveness and readiness probes using `pvxget`:

```yaml
livenessProbe:
  exec:
    command:
      - sh
      - -c
      - "pvxget -w 5 CERT:HEALTH 2>/dev/null | grep -q 'ok.*true'"
  initialDelaySeconds: 30
  periodSeconds: 60
readinessProbe:
  exec:
    command:
      - sh
      - -c
      - "pvxget -w 5 CERT:HEALTH 2>/dev/null | grep -q 'ok.*true'"
  initialDelaySeconds: 10
  periodSeconds: 15
```

## Backup and Restore

### One-Shot Backup

Create a single backup and exit:

```sh
pvacms --backup /path/to/backup.db
```

This uses the SQLite Online Backup API and is safe to run against a live
database.

### Periodic Backup

Enable periodic backups by setting the interval and directory:

```sh
pvacms --backup-interval 3600 --backup-dir /backups --backup-retention 7
```

- Backups are created on the status monitor cycle at the configured interval.
- Backup files are named `certs_backup_YYYYMMDD_HHMMSS.db`.
- When the number of backup files exceeds the retention count, the oldest
  files are removed.

### Restore Procedure

1. **Stop PVACMS.** Shut down the process (`kill`, `systemctl stop`, or scale
   the Kubernetes deployment to zero).

2. **Replace the database.** Copy the backup file over the current database:

   ```sh
   cp /backups/certs_backup_20250101_120000.db "${XDG_DATA_HOME}/pva/1.5/certs.db"
   ```

3. **Remove WAL and SHM files** if they exist alongside the database:

   ```sh
   rm -f "${XDG_DATA_HOME}/pva/1.5/certs.db-wal"
   rm -f "${XDG_DATA_HOME}/pva/1.5/certs.db-shm"
   ```

4. **Start PVACMS.** The startup self-tests will verify the restored database
   before publishing PVs.

In cluster mode, restore one node first and allow the SYNC protocol to
replicate the restored data to other members.

## Troubleshooting

### Startup Self-Test Failure

PVACMS runs four self-tests at startup. If any test fails, the process logs
the specific error and exits.

| Test | Symptom | Resolution |
|------|---------|------------|
| CA chain validation | `CA certificate chain validation failed` | Verify the CA keychain file is not corrupted. Ensure all intermediate certificates are present. Check certificate expiration dates. |
| Key match | `CA private key does not match certificate` | The keychain file contains a mismatched key/certificate pair. Replace with a correct keychain. |
| Schema version | `Database schema version mismatch` | The database was created by a different PVACMS version. Allow automatic migration or restore from a compatible backup. |
| Sign/verify | `OpenSSL sign/verify self-test failed` | OpenSSL initialization problem. Verify OpenSSL installation and library paths. |

### Database Corruption

The periodic integrity check (controlled by `--integrity-check-interval`)
detects corruption and logs an error. To recover:

1. Stop PVACMS.
2. Restore from the most recent backup (see Restore Procedure above).
3. Remove WAL and SHM files.
4. Restart PVACMS.

If no backup is available, attempt a manual recovery using the SQLite CLI:

```sh
sqlite3 certs.db ".recover" | sqlite3 recovered.db
mv recovered.db certs.db
```

### Certificate Chain Issues

If the CA certificate has expired or the chain is incomplete:

1. Check the CA keychain with OpenSSL:

   ```sh
   openssl pkcs12 -in cert_auth.p12 -nokeys -clcerts | openssl x509 -text -noout
   ```

2. Verify the expiration date and issuer chain.
3. If expired, generate a new CA keychain and re-issue certificates.

### Cluster Split-Brain

When cluster nodes have divergent certificate data:

1. Identify the authoritative node — typically the one with the most recent
   certificate operations.
2. Stop all other nodes.
3. Copy the authoritative database to each other node.
4. Remove WAL and SHM files on each node.
5. Restart all nodes. The SYNC protocol will confirm consistency.

### Rate Limiting Rejections

Clients receiving errors with `retry_after_secs` are being rate-limited.

1. Check the current creation rate via `CERT:METRICS` (`certs_created` field).
2. If the rate is legitimately high, increase limits:

   ```sh
   pvacms --rate-limit 50 --rate-limit-burst 200 --max-concurrent-ccr 500
   ```

3. If the rate is unexpectedly high, investigate the source of the requests.

### Increasing Log Verbosity

Use the `-v` flag for verbose output:

```sh
pvacms -v
```

For fine-grained control, set the PVXS log level via environment variable:

```sh
export EPICS_PVA_LOG="pvxs.certs.*=DEBUG"
pvacms
```

Common log prefixes:

| Prefix | Area |
|--------|------|
| `pvxs.certs.cfg` | Configuration loading |
| `pvxs.certs.cms` | Core PVACMS operations |
| `pvxs.certs.cluster` | Cluster operations |

## Validity Schedules

> Available in a future release.

Validity schedules allow certificates to have time-based activation windows.
A certificate with a schedule transitions between `VALID` and
`SCHEDULED_OFFLINE` states based on the current time.

### Concepts

A schedule is an array of time windows. Each window specifies:

- **day_of_week** — Day(s) the window applies to (e.g., `Mon`, `Mon,Wed,Fri`,
  or `*` for every day).
- **start_time** — Start of the validity window in `HH:MM` UTC format.
- **end_time** — End of the validity window in `HH:MM` UTC format.

When the current UTC time falls within any window, the certificate is `VALID`.
Outside all windows, it transitions to `SCHEDULED_OFFLINE`. Cross-midnight
ranges (where `end_time` < `start_time`) are supported.

### Creating a Scheduled Certificate

Include a schedule in the Certificate Creation Request (CCR). The schedule is
stored alongside the certificate and evaluated on every status monitor cycle.

### Modifying Schedules

Use the `CERT:SCHEDULE` RPC to modify the schedule for an existing
certificate:

- Provide the certificate `serial` and a new `schedule` array.
- An empty schedule removes all constraints — the certificate returns to
  permanent `VALID` state.
- Schedule modifications are replicated across the cluster via SYNC.
- Each modification is recorded in the audit log.

### Monitoring Schedule Transitions

The `CERT:STATUS` PV for a scheduled certificate includes an optional
`schedule` array field showing the active schedule windows. Subscribe to the
status PV to observe transitions between `VALID` and `SCHEDULED_OFFLINE`.

## Subject Alternative Names (SAN)

> Available in a future release.

Subject Alternative Names allow certificates to include additional identity
information beyond the Common Name (CN), such as IP addresses, DNS names, and
hostnames.

### Supported SAN Types

| Type | Format | Example |
|------|--------|---------|
| `ip` | IPv4 or IPv6 address | `10.0.0.1`, `2001:db8::1` |
| `dns` | Fully qualified domain name | `host.example.com` |
| `hostname` | Short hostname (no dots required) | `myioc` |

### Requesting a Certificate with SANs

Specify SANs via CLI flags (repeatable):

```sh
pvxcert request --san ip=10.0.0.1 --san dns=host.example.com --san hostname=myioc
```

Or via environment variable (comma-separated):

```sh
export EPICS_PVA_AUTH_SAN="ip=10.0.0.1,dns=host.example.com,hostname=myioc"
```

For server certificates, use the `--server-san` flag or
`EPICS_PVA_AUTH_SERVER_SAN` environment variable.

CLI values take precedence over environment variables. The SAN data is included
in the signed CCR payload.

### SAN Storage and Display

- SANs are stored in the X.509 SubjectAltName extension (non-critical) with
  correct GeneralName types (`GEN_IPADD` for IPs, `GEN_DNS` for DNS names and
  hostnames).
- SANs are stored in the certificate database for query and display purposes.
- The `pvxcert` CLI displays SAN entries when listing or querying certificate
  details.
- Administrators can search for certificates by SAN value.

### SAN Validation

- `ip` values must be valid IPv4 or IPv6 addresses.
- `dns` values must conform to RFC 1035 syntax (labels separated by dots).
- `hostname` values must be alphanumeric with optional hyphens.
- Invalid SAN entries are rejected with a descriptive error message.
