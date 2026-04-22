# Operational Metrics PV

## Executive Summary

We propose adding a `CERT:METRICS` SharedPV that publishes counters and gauges
describing PVACMS operational activity since startup.  While the `CERT:HEALTH`
PV (see `HEALTH_CHECK.md`) provides a simple binary health signal, `CERT:METRICS`
provides the quantitative data needed to understand load trends, capacity
planning, and performance characteristics.

The metrics PV is updated on every `statusMonitor()` cycle.  The cycle
interval is adaptive (see `ADAPTIVE_MONITOR.md`) — between 5 and 60 seconds
depending on how many certificates are near a state transition.  During quiet
periods the interval is at its maximum (default 60 s), so successive `pvxget
CERT:METRICS` calls within that window will return the same values; this is
expected behaviour, not a bug.  Counters are monotonically increasing since
process start; gauges reflect the current state at the time of the last update.  The design follows the Prometheus convention of
separating counters (always increasing) from gauges (can go up or down), making
the data directly consumable by time-series monitoring systems.

---

## Background and Motivation

### Capacity planning and trend detection

A PVACMS deployment may manage hundreds or thousands of certificates.  Without
metrics, an operator cannot answer basic operational questions:

- How fast are certificates being created?
- What fraction of the CCR processing time is acceptable overhead?
- Is the database growing at an expected rate?
- How many certificates are currently active vs. revoked?

These questions are answerable from the audit log with SQL queries, but that
requires direct database access and is not suitable for real-time dashboards or
alerting rules.

### Rolling average CCR processing time

The time to process a Certificate Creation Request varies with load, key type,
and authentication plugin.  A rolling average of CCR processing time, published
as a PV, makes it immediately visible if performance degrades — for example,
after a certificate type change (RSA 4096 vs. EC) or after a cluster topology
change that introduces authentication round-trips.

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — `CERT:METRICS` SharedPV created at startup;
   `updateMetricsPv()` called in `statusMonitor()` each cycle; atomic counters
   incremented in `onCreateCertificate()` and `onRevoke()`; CCR timing
   instrumented with `std::chrono::steady_clock`
2. **`src/pvacms/pvacms.h`** — Atomic counter and rolling-average members in
   `StatusMonitor`; `updateMetricsPv()` declaration
3. **`src/pvacms/configcms.h` / `configcms.cpp`** — `metrics_pv_prefix` field
   (default: `"CERT:METRICS"`)
4. **`test/testoperationalmetrics.cpp`** — Self-contained test executable with
   6 test cases

### What does not change

- The PVAccess wire protocol
- Any existing PV interface
- Certificate operation logic (timing instrumentation is non-intrusive)

---

## Detailed Design

### PV structure

The `CERT:METRICS` PV publishes a structure with the following fields:

| Field | Type | Kind | Description |
|---|---|---|---|
| `certs_created` | `uint64` | Counter | Monotonic count of certificates successfully created since startup |
| `certs_revoked` | `uint64` | Counter | Monotonic count of certificates revoked since startup |
| `certs_active` | `uint64` | Gauge | Count of certificates currently in `VALID` status |
| `avg_ccr_time_ms` | `double` | Gauge | Rolling average CCR processing time in milliseconds |
| `db_size_bytes` | `uint64` | Gauge | Combined size of `certs.db` and `certs.db-wal` in bytes (via `stat()`) |
| `uptime_secs` | `uint64` | Counter | Seconds since `StatusMonitor` was started |

**Counters** (`certs_created`, `certs_revoked`, `uptime_secs`) are
monotonically increasing.  A monitoring system can compute rates by taking
the derivative over time: `rate = (v_now - v_prev) / (t_now - t_prev)`.

**Gauges** (`certs_active`, `avg_ccr_time_ms`, `db_size_bytes`) reflect the
current state and can decrease.

### Atomic counter instrumentation

`certs_created_` and `certs_revoked_` are `std::atomic<uint64_t>` members of
the `StatusMonitor` class.  They are incremented with `fetch_add(1,
memory_order_relaxed)` in `onCreateCertificate()` and `onRevoke()` respectively,
immediately after the successful database commit.  The `memory_order_relaxed`
ordering is sufficient because the counters are only read in the
single-threaded `statusMonitor()` loop and do not guard any other state.

### CCR timing

`onCreateCertificate()` records a `std::chrono::steady_clock::now()` timestamp
before the authentication step and another after the database commit.  The
elapsed duration is used to update a running average:

```
avg = alpha * new_sample + (1 - alpha) * avg
```

with `alpha = 0.1` (exponential moving average, approximately the last 10
samples).  The result is stored as a `double` in milliseconds.

### Database size

`db_size_bytes` is computed by calling `stat()` on both the main database
file and the WAL file (if it exists) and summing the `st_size` fields.  This
gives the true on-disk footprint including uncommitted WAL frames, which is
the relevant number for capacity planning.  If `stat()` fails (e.g. the WAL
file does not yet exist), the field reflects only the main file size.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--metrics-pv-prefix` | `EPICS_PVACMS_METRICS_PV_PREFIX` | `CERT:METRICS` | PV name for the metrics channel |

---

## Example Dashboard Integration

A Phoebus display or Grafana panel (via the EPICS datasource) can subscribe to
`CERT:METRICS` and show:

- A rate chart: `certs_created` derivative over a 1-minute window
- A scatter plot: `avg_ccr_time_ms` vs. time
- A storage gauge: `db_size_bytes` with a threshold alert
- An active certificate count: `certs_active` as a label

---

## Migration and Rollback

The metrics PV is purely additive.  No existing behaviour changes.

**Rollback** requires removing the `CERT:METRICS` SharedPV creation,
`updateMetricsPv()`, the atomic counters, and the CCR timing instrumentation.
No persistent state is involved.

---

## Testing

`test/testoperationalmetrics.cpp` exercises (6 tests):

- PV is reachable at the configured name
- `certs_created` increments by 1 after each successful certificate creation
- `certs_revoked` increments by 1 after each revocation
- `certs_active` reflects the current count of `VALID` rows in the database
- `avg_ccr_time_ms` is positive after at least one CCR
- `db_size_bytes` is positive and reflects a non-empty database file

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `6b5a291` — "feat: add CERT:METRICS SharedPV for operational metrics" |
| Primary source | `src/pvacms/pvacms.cpp` — `updateMetricsPv()`, CCR timing in `onCreateCertificate()` |
| Configuration | `src/pvacms/configcms.h` — `metrics_pv_prefix` |
| Tests | `test/testoperationalmetrics.cpp` |
| Companion features | `docs/HEALTH_CHECK.md` (CERT:HEALTH binary status), `docs/ADAPTIVE_MONITOR.md` (update timing) |
