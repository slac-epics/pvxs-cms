# Validity Schedules

## Executive Summary

We propose adding recurring schedule windows to PVACMS that automatically
toggle certificates between `VALID` and a new `SCHEDULED_OFFLINE` status on
a time-based rule.  This allows operators to issue a certificate that is
cryptographically valid but operationally inactive during defined periods —
for example, a client certificate that should only be trusted during business
hours, or a maintenance window where a particular IOC should not be reachable.

Schedules are defined at certificate creation time via the authn tools (`authnstd`,
`authnkrb`, etc.) using a `--schedule` flag, or modified post-issuance by
administrators via the `CERT:SCHEDULE` RPC or `pvxcert --schedule`.  The status
monitor evaluates schedules automatically and publishes resulting status
transitions through the existing `CERT:STATUS` PV mechanism, to which pvxs
clients react immediately.  Cluster members propagate schedule changes via the
SYNC protocol.

Schedules require status monitoring to be active on the certificate — they
cannot be used with `--no-status` certificates, since clients must be able to
react to status updates from PVACMS to know whether a certificate is currently
valid.

---

## Background and Motivation

### Time-based access control in EPICS

EPICS access security (asLib) has no native concept of time-based rules.
Operators who need to restrict a device to certain hours currently do so by
revoking and re-issuing certificates manually — a fragile, error-prone process
that requires administrator intervention twice per schedule cycle.

A scheduled offline status provides the same effect without manual intervention
and without revoking the certificate permanently.  The certificate's
cryptographic validity is unchanged; only the PVACMS-issued OCSP-like status
oscillates between `VALID` and `SCHEDULED_OFFLINE` according to the schedule.

### Maintenance windows and planned outages

Facilities schedule planned maintenance for specific equipment at regular
intervals.  Expressing this schedule in the certificate means that the
equipment's certificate status automatically reflects its operational state,
without requiring the operations team to remember to approve or revoke it
each time.

---

## Scope of Changes

### What changes

1. **`src/common/security.h`** — `ScheduleWindow` struct definition;
   `schedule_windows` field added to `AuthnCredentials`
2. **`src/authn/configauthn.h`** — `schedule_windows` field added to
   `ConfigAuthN` so parsed CLI values reach the CCR builder
3. **`src/authn/std/authnstdmain.cpp`** — `--schedule day,HH:MM,HH:MM`
   CLI flag (repeatable); validated and stored in `config.schedule_windows`;
   error if combined with `--no-status`
4. **`src/authn/auth.cpp`** — Schedule windows serialised into
   `ccr["schedule"]` StructA alongside SANs in `createCertCreationRequest()`
5. **`src/authn/auth.h`** — `credentials->schedule_windows` copied from
   config (mirrors the existing SAN copy pattern)
6. **`src/pvacms/pvacms.cpp`** — Schema migration v2→v3 creates the
   `cert_schedules` table; `onCreateCertificate()` parses and persists
   schedule windows (rejects if `no_status=true`); `statusMonitor()` evaluates
   schedules and transitions between `VALID` and `SCHEDULED_OFFLINE`;
   `CERT:SCHEDULE` RPC handler for post-issuance modification (supports
   `read_only=true` for show-only queries); RPC reply echoes the current
   windows after any write
7. **`src/pvacms/pvacms.h`** — Schedule evaluation declarations; SQL macros
   for `cert_schedules` table
8. **`src/common/certstatus.h`** — New `SCHEDULED_OFFLINE` value in the
   certificate status enum
9. **`src/pvacms/clustersync.cpp` / `clusterdiscovery.cpp`** — Schedule rows
   included in SYNC payloads; receiving node applies them within the same SYNC
   transaction
10. **`src/pvacms/clustertypes.cpp`** — `SCHEDULED_OFFLINE` added to cluster
    type mappings
11. **`src/tools/pvxcert/pvxcert.cpp`** — `pvxcert status` displays schedule
    windows; new `--schedule` admin flag with `show`, `none`, and
    `day,HH:MM,HH:MM` sub-commands
12. **`test/testvalidityschedules.cpp`** — Self-contained test executable with
    16 test cases

### What does not change

- The TLS handshake (`SCHEDULED_OFFLINE` is treated as invalid by pvxs clients,
  identical to a revoked certificate)
- The `CERT:STATUS` PV protocol (the new status value is transmitted in the
  same status field)
- The CCR wire format for certificates that carry no schedule (fully backwards
  compatible — the `schedule` StructA is an optional array field)

---

## Detailed Design

### The `cert_schedules` table (schema v3)

```sql
CREATE TABLE IF NOT EXISTS cert_schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    serial      INTEGER NOT NULL REFERENCES certs(serial),
    day_of_week TEXT    NOT NULL,  -- '0'-'6' (Sun-Sat) or '*' for every day
    start_time  TEXT    NOT NULL,  -- 'HH:MM' UTC
    end_time    TEXT    NOT NULL   -- 'HH:MM' UTC
);
CREATE INDEX IF NOT EXISTS idx_cert_schedules_serial ON cert_schedules(serial);
```

Each row defines one schedule window for a certificate.  A certificate may
have multiple windows (e.g. Mon–Fri 08:00–17:00 plus Saturday 08:00–12:00).
All times are UTC to avoid daylight-saving ambiguity.  Cross-midnight windows
(e.g. `22:00`–`06:00`) are supported: `isWithinSchedule()` detects when
`end_time < start_time` and splits the comparison accordingly.

### `ScheduleWindow` struct

```cpp
struct ScheduleWindow {
    std::string day_of_week;  // "0"-"6" (Sun-Sat) or "*" for every day
    std::string start_time;   // "HH:MM" in UTC
    std::string end_time;     // "HH:MM" in UTC
};
```

### Authn tool interface

Schedule windows are specified at certificate request time using the
`--schedule` flag (repeatable):

```sh
authnstd --schedule '*,08:00,17:00' --schedule '6,08:00,12:00'
```

This requests a certificate that is `VALID` every day 08:00–17:00 UTC, plus
Saturday mornings 08:00–12:00 UTC.  The windows are validated at parse time
(day must be `0`–`6` or `*`; times must be `HH:MM`) and an error is returned
immediately if `--no-status` is also set, since schedules require status
monitoring to be active.

### Schedule windows in the CCR wire format

The `schedule` field is already part of `CCR_PROTOTYPE` in `security.h`:

```
schedule: StructA {
    day_of_week: String,  // "0"-"6" or "*"
    start_time:  String,  // "HH:MM" UTC
    end_time:    String   // "HH:MM" UTC
}[]
```

`onCreateCertificate()` validates each window and stores them in
`cert_schedules` within the same transaction that creates the certificate row.
Certificates submitted without a `schedule` field behave exactly as before.

### Status evaluation in `statusMonitor()`

On each monitor cycle, certificates with schedule rows are evaluated:

1. Query `cert_schedules` for all certificates in `VALID` or `SCHEDULED_OFFLINE`
2. For each certificate, call `isWithinSchedule(now_utc, windows)`
3. At least one window active → target status `VALID`
4. No window active → target status `SCHEDULED_OFFLINE`
5. If status differs from target, update `certs` table and post via
   `postCertificateStatus()`

Certificates without schedule rows are not evaluated.

### `CERT:SCHEDULE` RPC

The `CERT:SCHEDULE` RPC allows authorised users to query or modify schedule
windows for an existing certificate without reissuing it:

```
Request:
    query.serial:    uint64   (certificate serial number, required)
    query.read_only: bool     (true = show only, no DB changes)
    query.schedule:  StructA  (new windows; empty array clears all; omitted if read_only)
        day_of_week: String
        start_time:  String
        end_time:    String

Response:
    result:   String   ("ok")
    schedule: StructA  (current windows after the operation)
        day_of_week: String
        start_time:  String
        end_time:    String
```

The RPC is protected by the `CERT_STATUS` ACF access group (admin only).
Write operations are audited with action `SCHEDULE` in the audit table and
replicated to cluster peers.  `read_only=true` skips all writes, auditing,
and cluster sync — it is a pure read.

If the certificate is currently `VALID` or `SCHEDULED_OFFLINE` and the new
windows change which state it should be in, the status is updated immediately
and posted to the `CERT:STATUS` PV without waiting for the next monitor cycle.

### `pvxcert` admin interface

```sh
pvxcert -S show  <issuer>:<serial>       # display current windows
pvxcert -S none  <issuer>:<serial>       # remove all windows
pvxcert -S '*,08:00,17:00' \
        -S '6,08:00,12:00' \
        <issuer>:<serial>                # set two windows (replaces existing)
```

All three use the `CERT:SCHEDULE` RPC.  The reply always includes the current
windows, which pvxcert displays:

```
Schedule      :
============================================
  Every day  08:00 - 17:00 UTC
  Sat        08:00 - 12:00 UTC
--------------------------------------------
```

`pvxcert status <cert_id>` and `pvxcert -f <file>` already display schedule
windows as part of the live `CERT:STATUS` response.

### `SCHEDULED_OFFLINE` status

`SCHEDULED_OFFLINE` is a new value in the certificate status enum.  From the
perspective of pvxs clients it behaves identically to `REVOKED` — the
certificate is not trusted.  It differs semantically in that it is expected to
transition back to `VALID` automatically when the next schedule window opens.
Operators should use revocation, not scheduling, for security-motivated
certificate invalidation.

### Cluster replication

Schedule rows are included in the SYNC payload alongside the certificate data.
Each receiving node applies schedule rows to its local `cert_schedules` table
within the same SYNC transaction.  Schedule modifications via `CERT:SCHEDULE`
are replicated to all cluster members by the originating node.

### Adaptive monitor integration

The adaptive monitor interval calculation (see `ADAPTIVE_MONITOR.md`) is
extended to count certificates with schedule boundaries within the look-ahead
window, so that `VALID` ↔ `SCHEDULED_OFFLINE` transitions are applied promptly
rather than waiting up to `max_interval` seconds.

### Configuration

No new configuration flags are required for the core scheduling logic.
The `CERT:SCHEDULE` RPC is published under `<cert-pv-prefix>:SCHEDULE`
(default `CERT:SCHEDULE`), using the existing `--cert-pv-prefix` configuration.

---

## Client and Server Connection Behaviour During SCHEDULED_OFFLINE

When a certificate transitions to `SCHEDULED_OFFLINE`, the pvxs connection
layer enters a **SUSPENDED** state.  The TLS socket stays open, monitors are
paused, and operations are rejected with a clear error until the certificate
returns to `VALID` — at which point everything resumes transparently with no
reconnect and no new TLS handshake.

`PENDING_RENEWAL` (cert past its `renew_by` date, renewal in flight) is
treated identically.

The full design — covering all four cert monitoring paths (client own cert,
client peer cert, server own cert, server peer cert), the `SUSPENDED`
status class, operation behaviour, state transition diagrams, and the pvxs
files affected — is documented in `docs/ROBUST_STATE_MANAGEMENT.md`.

---

## Security Considerations

`SCHEDULED_OFFLINE` does not provide the same security guarantees as `REVOKED`.
A revoked certificate is permanently invalidated; a `SCHEDULED_OFFLINE`
certificate will become valid again when the next schedule window opens.
Operators should use revocation, not scheduling, for security-motivated
certificate invalidation.

Schedules require status monitoring (`no_status=false`).  Clients and servers
must subscribe to the `CERT:STATUS` PV to react to `SCHEDULED_OFFLINE`
transitions.  A certificate on a pvxs peer that does not subscribe to status
updates will remain trusted even when its status is `SCHEDULED_OFFLINE`.

Schedule windows are evaluated by PVACMS.  If PVACMS is unavailable during a
schedule boundary, the certificate status will not change until PVACMS
reconnects and the monitor runs — the same availability characteristic as all
other status transitions.

---

## Migration and Rollback

The `cert_schedules` table is created by the schema v2→v3 migration, which
runs automatically on first open of any existing database.  No existing
certificates are affected.

**Rollback** requires reverting the migration, the `CERT:SCHEDULE` RPC, the
`statusMonitor()` schedule evaluation, and the `SCHEDULED_OFFLINE` status
value.  Certificates that are currently `SCHEDULED_OFFLINE` at rollback time
will remain in that status until manually corrected; older PVACMS binaries do
not know how to transition them back to `VALID`.

---

## Testing

`test/testvalidityschedules.cpp` exercises (16 tests):

- Certificate with a currently-active schedule window starts as `VALID`
- Certificate with no active window transitions to `SCHEDULED_OFFLINE`
- Certificate transitions back to `VALID` when a window opens
- Cross-midnight window evaluated correctly (e.g. 22:00–06:00)
- Wildcard day (`*`) matches any day of the week
- Multiple windows: at least one active → `VALID`
- `CERT:SCHEDULE` RPC replaces all windows for the certificate
- `CERT:SCHEDULE` RPC with `read_only=true` returns windows without writing
- `CERT:SCHEDULE` RPC rejected for non-admin caller
- Schedule rows included in cluster SYNC payload
- Receiving node applies schedules from SYNC correctly
- `pvxcert status` output includes schedule window information
- Adaptive monitor interval shortened when schedule boundary is approaching
- No schedule rows → certificate unaffected by schedule evaluation
- Invalid schedule values rejected in `onCreateCertificate()`
- Audit record written for `CERT:SCHEDULE` write operations

---

## References

| Resource | Location |
|---|---|
| Core implementation | `665c609` — "feat: add validity schedules for time-based certificate status toggling" |
| Tool interface | `c40329e` (pvxcert, authnstd, auth.cpp/h, security.h, configauthn.h) |
| Primary source | `src/pvacms/pvacms.cpp` — schedule parsing, evaluation, `CERT:SCHEDULE` RPC |
| Status enum | `src/common/certstatus.h` — `SCHEDULED_OFFLINE` |
| Cluster sync | `src/pvacms/clustersync.cpp`, `src/pvacms/clusterdiscovery.cpp` |
| Authn tool | `src/authn/std/authnstdmain.cpp`, `src/authn/auth.cpp` |
| Admin tool | `src/tools/pvxcert/pvxcert.cpp` |
| Tests | `test/testvalidityschedules.cpp` |
| Companion features | `docs/ADAPTIVE_MONITOR.md` (schedule boundary integration), `docs/AUDIT_LOGGING.md` (SCHEDULE audit action), `docs/SQLITE_HARDENING.md` (schema v3 migration) |
