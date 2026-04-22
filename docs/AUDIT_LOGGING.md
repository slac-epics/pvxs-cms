# Audit Logging

## Executive Summary

We propose adding a persistent audit trail to PVACMS that records every
certificate lifecycle event — creation, approval, denial, revocation, and
cluster-synchronised updates — to a dedicated SQLite table.  In the original
implementation, these events were logged to the process log only.  Log entries
are transient, do not survive log rotation, and provide no structured query
interface for compliance review or incident investigation.

The audit log writes each event atomically within the existing database
transaction that performs the certificate operation, so the audit record and
the certificate change are always consistent.  Entries are retained for a
configurable period and pruned automatically in the status-monitor maintenance
cycle.  A `CERT:AUDIT` SharedPV (for live query access over PVA) is planned
as a follow-on extension.

---

## Background and Motivation

### Compliance and accountability

Large accelerator facilities typically operate under controls-systems policies
that require a record of who performed each administrative action on a
certificate — approval, denial, or revocation — and when.  The PVACMS event
log satisfies the audit trail requirement for those policies without adding an
external dependency (e.g. a dedicated SIEM or syslog aggregator).

### Cluster transparency

In cluster mode, certificate operations performed on one node are replicated
to all peers via the SYNC protocol.  Before audit logging, it was not possible
to determine which node originally performed an operation or to verify that a
SYNC message had been applied on a given peer.  Each receiving node now writes
its own local audit record for each SYNC event it applies, creating a
node-local record of cluster state changes.

### Structured queryability

Audit records are stored in a relational table, making them queryable with
standard SQL.  Operators can answer questions such as:
- Which certificates were approved in the last 30 days?
- Did node B receive the revocation of serial X?
- How many certificates were created by user alice last month?

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — Schema migration v1→v2 creates the `audit`
   table; `insertAuditRecord()` helper writes within existing transactions;
   audit calls added to `onCreateCertificate`, `onApprove`, `onDeny`,
   `onRevoke`; periodic pruning in the maintenance cycle
2. **`src/pvacms/pvacms.h`** — `insertAuditRecord()` and
   `insertSyncAuditRecord()` declarations; `audit_retention_days` config field
3. **`src/pvacms/configcms.h` / `configcms.cpp`** — `audit_retention_days`
   field (default: `365`)
4. **`src/pvacms/clusterdiscovery.cpp`** — `insertSyncAuditRecord()` called
   when a SYNC message is applied by the receiving node
5. **`test/testauditlogging.cpp`** — Self-contained test executable with 5 test
   cases

### What does not change

- The PVAccess wire protocol
- The SYNC protocol message format (audit records are written locally by the
  receiver; they are not transmitted)
- The `certs` table schema
- Behaviour of certificate operations (audit is a side effect, not a
  precondition)

---

## Detailed Design

### The `audit` table (schema v2)

```sql
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL DEFAULT (datetime('now')),
    action    TEXT    NOT NULL,
    serial    INTEGER,
    operator  TEXT,
    details   TEXT
);
```

| Column | Description |
|---|---|
| `id` | Monotonic row identifier |
| `ts` | UTC timestamp of the event (ISO 8601, SQLite `datetime('now')`) |
| `action` | One of `CREATE`, `APPROVE`, `DENY`, `REVOKE`, `SYNC` |
| `serial` | Certificate serial number (NULL for actions not tied to a single cert) |
| `operator` | Identity of the operator (from `ClientCredentials`), NULL for automated events |
| `details` | Free-text field for additional context (e.g. revocation reason, SYNC source node) |

### Atomic write within the certificate transaction

`insertAuditRecord()` executes an `INSERT INTO audit` as the last step of the
same `BEGIN … COMMIT` block that modifies the `certs` table.  If the
certificate operation fails and the transaction is rolled back, the audit record
is also rolled back — there are no phantom audit entries for failed operations.

```cpp
void insertAuditRecord(sqlite3 *db,
                       const std::string &action,
                       int64_t serial,
                       const std::string &operator_id,
                       const std::string &details);
```

The `operator` value is extracted from the `ClientCredentials` object present
in each RPC handler.  For `CERT:CREATE` the operator is the requesting entity;
for `CERT:STATUS` approve/deny/revoke RPCs it is the admin identity.

### Cluster SYNC audit

When a SYNC message is received and applied, the receiving node calls
`insertSyncAuditRecord()` with the action type, the serial number, and the
originating node's issuer ID.  This creates a local record of cluster
convergence that is independent of the originating node's log.

### Configurable retention and periodic pruning

Audit records older than `audit_retention_days` are deleted during the
status-monitor maintenance cycle:

```sql
DELETE FROM audit
WHERE ts < datetime('now', '-' || :retention_days || ' days');
```

Pruning runs in its own `BEGIN … COMMIT` block, separated from certificate
status updates.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--audit-retention-days` | `EPICS_PVACMS_AUDIT_RETENTION_DAYS` | `365` | Days to retain audit records before pruning |

### Deferred: `CERT:AUDIT` SharedPV

A `CERT:AUDIT` SharedPV that exposes recent audit records over PVA for live
query is planned as a follow-on extension.  A placeholder comment marks the
intended location in `pvacms.cpp`.  The table schema is designed to support
this without modification.

---

## Security Considerations

Audit records contain operator identity strings extracted from peer
credentials.  These are the same identity values used for access control and
are not sensitive beyond what is already visible in the certificate database.

The audit table is written by the PVACMS process itself; it is not writable
by external clients.  However, a user with direct SQLite access to `certs.db`
can modify or delete audit records.  Deployments that require tamper-evident
audit trails should use filesystem-level append-only controls (e.g. Linux
`chattr +a`) on the database file, or replicate audit events to an external
log aggregator via the `CERT:AUDIT` SharedPV once it is implemented.

---

## Migration and Rollback

The `audit` table is created by the schema v1→v2 migration, which runs
automatically on first open of any existing database.  No existing data is
modified.

**Rollback** requires removing the migration, the `insertAuditRecord()` calls,
and the `audit_retention_days` configuration.  The `audit` table left in the
database by a rolled-back deployment is harmless; it will not be written to
or read by older code.

---

## Testing

`test/testauditlogging.cpp` exercises (5 tests):

- Audit table is created by the migration
- `onCreateCertificate` writes a `CREATE` record
- `onApprove` writes an `APPROVE` record with the operator identity
- `onRevoke` writes a `REVOKE` record with the serial number
- Records older than retention days are pruned; records within retention are
  kept

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `fc7d2e4` — "Add audit logging: table, migration, insert/prune, admin & sync audit trails" |
| Primary source | `src/pvacms/pvacms.cpp` — `insertAuditRecord()`, `insertSyncAuditRecord()` |
| Cluster integration | `src/pvacms/clusterdiscovery.cpp` |
| Configuration | `src/pvacms/configcms.h` — `audit_retention_days` |
| Tests | `test/testauditlogging.cpp` |
| Companion features | `docs/SQLITE_HARDENING.md` (schema versioning), `docs/VALIDITY_SCHEDULES.md` (SCHEDULE audit action) |
