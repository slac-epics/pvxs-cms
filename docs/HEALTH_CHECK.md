# Operational Health Check PV

## Executive Summary

We propose adding a `CERT:HEALTH` SharedPV that exposes the real-time
operational status of PVACMS over PVAccess.  In the original implementation,
the only way to determine whether a running PVACMS instance was healthy was to
inspect its process log or attempt a certificate operation and observe whether
it succeeded.  Neither approach is suitable for automated monitoring.

The health PV publishes a composite `ok` flag and individual sub-status fields
that monitoring systems (Phoebus, Nagios, Kubernetes liveness probes) can
subscribe to.  It is updated on every `statusMonitor()` cycle.  The cycle interval is
adaptive (see `ADAPTIVE_MONITOR.md`) — between 5 and 60 seconds depending on
workload — so the maximum staleness of the health PV is the configured
`monitor-interval-max` (default 60 s).

---

## Background and Motivation

### Operational visibility gap

PVACMS is typically operated as a long-running service.  An instance may be
running (process alive, PVs reachable) while being functionally impaired: its
CA certificate may be near expiry, its database may be corrupt, or it may have
lost cluster quorum.  None of these conditions were previously detectable
without direct log inspection or a failed certificate operation.

### Integration with facility monitoring

Accelerator facilities run Phoebus displays, EPICS alarm handlers, and
infrastructure monitoring systems that already know how to subscribe to PVA
channels.  Exposing PVACMS health as a PV makes it a first-class member of the
facility's monitoring infrastructure with no additional tooling required.

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — `CERT:HEALTH` SharedPV created at startup;
   `updateHealthPv()` called in `statusMonitor()` each cycle; fields populated
   from `StatusMonitor` accessors and live queries
2. **`src/pvacms/pvacms.h`** — `updateHealthPv()` declaration; SharedPV member
   in `StatusMonitor`
3. **`src/pvacms/configcms.h` / `configcms.cpp`** — `health_pv_prefix`
   field (default: `"CERT:HEALTH"`)
4. **`test/testhealthcheck.cpp`** — Self-contained test executable with 6 test
   cases

### What does not change

- The PVAccess wire protocol
- Any existing PV interface
- Certificate operations

---

## Detailed Design

### PV structure

The `CERT:HEALTH` PV publishes an NTScalar-like structure with the following
fields:

| Field | Type | Description |
|---|---|---|
| `ok` | `bool` | Composite health: `db_ok AND ca_valid` |
| `db_ok` | `bool` | `true` if the last `PRAGMA integrity_check` returned `"ok"` |
| `ca_valid` | `bool` | `true` if the CA certificate has not expired |
| `cert_count` | `uint64` | Total number of certificates in the database |
| `cluster_members` | `uint32` | Number of connected cluster peers (0 if not in cluster mode) |
| `uptime_secs` | `uint64` | Seconds since `StatusMonitor` was started |
| `timestamp` | `string` | ISO 8601 UTC timestamp of the last update |

The composite `ok` field is the primary signal for automated liveness checks.
The individual sub-fields allow monitoring systems to distinguish between
different failure modes without parsing log messages.

### Update timing

`updateHealthPv()` is called at the end of every `statusMonitor()` iteration,
after all certificate state transitions and maintenance operations have been
applied.  The update is therefore consistent with the current database state
at the point of posting.

`db_ok` reflects the result of the most recent `PRAGMA integrity_check` (see
`SQLITE_HARDENING.md`).  Between integrity check runs (default: every 24 hours)
it retains its last-known value.  `ca_valid` is re-evaluated on every cycle
by checking the CA certificate's `notAfter` field against the current wall
clock.

### PV name configuration

The full PV name is `<health_pv_prefix>`, defaulting to `CERT:HEALTH`.
Operators who run multiple PVACMS instances on the same network should set
distinct prefixes (e.g. `CERT:HEALTH:LAB`, `CERT:HEALTH:ML`) to avoid
name collisions.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--health-pv-prefix` | `EPICS_PVACMS_HEALTH_PV_PREFIX` | `CERT:HEALTH` | PV name for the health channel |

---

## Example Phoebus Integration

A Phoebus display can subscribe to `CERT:HEALTH` and show a traffic-light
indicator on the `ok` field:

```
pva://CERT:HEALTH.ok      → green (true) / red (false)
pva://CERT:HEALTH.ca_valid → warning when approaching expiry
pva://CERT:HEALTH.cert_count → gauge showing database size
```

A Kubernetes liveness probe can use `pvxget CERT:HEALTH` and exit non-zero
if the returned `ok` field is `false`.

---

## Migration and Rollback

The health PV is purely additive.  Existing deployments will find a new PV
available for subscription; no existing PVs or behaviour change.

**Rollback** requires removing the `CERT:HEALTH` SharedPV creation and the
`updateHealthPv()` call.  No persistent state is involved.

---

## Testing

`test/testhealthcheck.cpp` exercises (6 tests):

- PV is created and reachable at the configured name
- `ok` is `true` when both `db_ok` and `ca_valid` are true
- `ok` is `false` when `db_ok` is false (simulated integrity check failure)
- `cert_count` reflects the number of rows in the `certs` table
- `uptime_secs` is positive and monotonically increasing across two updates
- `timestamp` is a valid ISO 8601 string

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `f2b7fb9` — "feat: add CERT:HEALTH SharedPV for operational health monitoring" |
| Primary source | `src/pvacms/pvacms.cpp` — `updateHealthPv()` |
| Configuration | `src/pvacms/configcms.h` — `health_pv_prefix` |
| Tests | `test/testhealthcheck.cpp` |
| Companion features | `docs/SQLITE_HARDENING.md` (db_ok source), `docs/OPERATIONAL_METRICS.md` (CERT:METRICS), `docs/ADAPTIVE_MONITOR.md` (update timing) |
