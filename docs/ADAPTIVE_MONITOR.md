# Adaptive Status Monitor Interval

## Executive Summary

We propose replacing the fixed-interval `statusMonitor()` sleep with an
adaptive interval that scales with the number of certificates approaching a
state transition.  With a fixed interval, PVACMS either polls too frequently
(wasting CPU and SQLite I/O when nothing is about to change) or too
infrequently (delaying status updates for certificates near their activation,
expiry, or renewal deadlines).

The adaptive algorithm interpolates the sleep duration linearly between a
configurable minimum (5 s) and maximum (60 s) based on how many certificates
have a state transition within the next `2 × max_interval` seconds.  Zero
approaching transitions → sleep for `max_interval`; 100 or more → sleep for
`min_interval`.  This keeps PVACMS responsive during transition-dense periods
(e.g. a batch deployment with many certificates starting simultaneously) while
consuming minimal resources during quiet periods.

---

## Background and Motivation

### The fixed-interval problem

The original `statusMonitor()` used a hard-coded 15-second sleep between
iterations.  This was chosen as a conservative middle ground, but it has two
failure modes:

1. **Too slow near transitions**: A certificate whose validity window begins in
   16 seconds will not be activated until the monitor wakes 15+ seconds later.
   For time-sensitive deployments, a 15-second activation lag is observable.

2. **Too fast during idle periods**: A PVACMS instance managing thousands of
   certificates with no imminent transitions is performing a full-table SQL
   scan every 15 seconds for no benefit.  On large deployments this represents
   meaningful I/O overhead.

### Proportional response

The key insight is that the urgency of the monitor's work is directly
proportional to the number of certificates near a boundary.  When no
certificates are within `2 × max_interval` of a transition, there is no
benefit to waking up more frequently than `max_interval`.  When many
certificates are within that window, faster polling directly reduces the
maximum activation/expiration lag.

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — `statusMonitor()` calls
   `computeMonitorInterval()` at the end of each iteration to determine the
   next sleep duration; SQL query counts certificates near transitions
2. **`src/pvacms/configcms.h` / `configcms.cpp`** — Two new configuration
   fields: `monitor_interval_min_secs` and `monitor_interval_max_secs`
3. **`test/testadaptivemonitor.cpp`** — Self-contained test executable with 7
   test cases

### What does not change

- The `statusMonitor()` logic for processing transitions (unchanged)
- The PVAccess wire protocol
- Any other configuration options

---

## Detailed Design

### Transition proximity query

At the end of each monitor iteration, PVACMS runs:

```sql
SELECT COUNT(*) FROM certs
WHERE status IN ('PENDING', 'VALID', 'PENDING_RENEWAL')
  AND ABS(CAST((julianday(validity_start) - julianday('now')) * 86400 AS INTEGER))
      < :lookahead_secs
  OR  ABS(CAST((julianday(validity_end)   - julianday('now')) * 86400 AS INTEGER))
      < :lookahead_secs
  OR  ABS(CAST((julianday(renewal_date)   - julianday('now')) * 86400 AS INTEGER))
      < :lookahead_secs;
```

where `:lookahead_secs = 2 × max_interval`.  This counts certificates within
the look-ahead window for three boundary types:

- **`validity_start`**: `PENDING` → `VALID` transition
- **`validity_end`**: `VALID` → `EXPIRED` transition
- **`renewal_date`**: `VALID` → `PENDING_RENEWAL` transition

If the query fails (e.g. due to a transient lock), the interval falls back to
a fixed 15-second default to ensure the monitor continues functioning.

### Linear interpolation

```
if (n == 0)    interval = max_interval
if (n >= 100)  interval = min_interval
else           interval = max_interval - (max_interval - min_interval) * n / 100
```

The threshold of 100 certificates is a practical ceiling: beyond 100
approaching transitions, the minimum interval is already in effect and further
precision offers no benefit.  Both the threshold and the interpolation
coefficients are implementation details; the externally visible parameters are
`min_interval` and `max_interval`.

### Schedule boundary extension

When validity schedules are in use (see `VALIDITY_SCHEDULES.md`), the
transition proximity query is extended to also count certificates with schedule
boundaries within the look-ahead window.  This ensures that `SCHEDULED_OFFLINE`
↔ `VALID` transitions are also handled promptly.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--monitor-interval-min` | `EPICS_PVACMS_MONITOR_INTERVAL_MIN` | `5` | Minimum sleep between monitor iterations (seconds) |
| `--monitor-interval-max` | `EPICS_PVACMS_MONITOR_INTERVAL_MAX` | `60` | Maximum sleep between monitor iterations (seconds) |

**Default reasoning:** 5 seconds is short enough for sub-10-second activation
accuracy.  60 seconds is conservative for truly idle deployments; it can be
increased if operational experience shows the default overhead is acceptable.

---

## Migration and Rollback

The adaptive interval is transparent to existing deployments.  On upgrade, the
sleep duration will vary between 5 and 60 seconds depending on workload,
compared to the fixed 15 seconds previously.  Deployments that relied on
approximately 15-second update latency should set
`--monitor-interval-min 15 --monitor-interval-max 15` to preserve the old
behaviour.

**Rollback** requires reverting `statusMonitor()` to the fixed-sleep form.
No persistent state is involved.

---

## Testing

`test/testadaptivemonitor.cpp` exercises (7 tests):

- Zero approaching transitions → interval equals `max_interval`
- 100+ approaching transitions → interval equals `min_interval`
- Intermediate counts → interval interpolates correctly
- Query failure → interval falls back to 15-second default
- `min_interval` = `max_interval` → interval is constant regardless of count
- `--monitor-interval-min` and `--monitor-interval-max` flags respected
- Schedule boundary transitions included in the count when schedules are present

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `fadb93b` — "Add adaptive status monitor interval based on cert transition proximity" |
| Primary source | `src/pvacms/pvacms.cpp` — `computeMonitorInterval()`, `statusMonitor()` |
| Configuration | `src/pvacms/configcms.h` — `monitor_interval_min_secs`, `monitor_interval_max_secs` |
| Tests | `test/testadaptivemonitor.cpp` |
| Companion feature | `docs/VALIDITY_SCHEDULES.md` — schedule boundary extension |
