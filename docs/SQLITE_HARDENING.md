# SQLite Hardening and Schema Versioning

## Executive Summary

We propose hardening the PVACMS SQLite database against corruption, lock
contention, and schema drift.  In its initial form, `certs.db` was opened
with SQLite's default settings — rollback journal mode, no busy timeout, no
foreign-key enforcement, and no mechanism to track or migrate the schema.
Under sustained load or following an unclean shutdown, these defaults leave the
database vulnerable to journal file accumulation, `SQLITE_BUSY` errors that
surface as certificate creation failures, and undetected schema inconsistencies.

The proposal applies four targeted hardening measures immediately after
`sqlite3_open()` in `initCertsDatabase()`, adds a `schema_version` table with
a forward-migration framework, and introduces periodic integrity checking and
WAL checkpointing in the status-monitor loop.  All changes are backwards
compatible: an existing `certs.db` opened under the new settings is upgraded
transparently on first use.

---

## Background and Motivation

### WAL journal and concurrent access

SQLite's default journal mode (DELETE) serialises all writers and creates a
visible rollback journal file beside the database.  For PVACMS, the
status-monitor goroutine, certificate creation handlers, and (in cluster mode)
SYNC receivers all access the database concurrently.  The DELETE journal holds
an exclusive lock for the full duration of every write, causing unnecessary
contention.

WAL (Write-Ahead Logging) mode allows concurrent reads and one writer
simultaneously, with no shared-memory contention between readers and the writer.
WAL mode also recovers cleanly from process crashes — the WAL file is simply
replayed on the next open — making it more resilient than the rollback journal.

### `SQLITE_BUSY` and the absent busy timeout

Without a busy timeout, any attempt to acquire a lock on a busy database
returns `SQLITE_BUSY` immediately.  Because PVACMS never caught or retried
these errors explicitly, a burst of concurrent certificate creation requests
caused spurious failures visible to clients.  A 5-second busy timeout is
sufficient to absorb short spikes while keeping response times predictable.

### Foreign-key enforcement

The `certs` table was created with foreign-key references, but SQLite disables
foreign-key enforcement by default for backwards-compatibility reasons.  Without
`PRAGMA foreign_keys = ON`, referential integrity violations can be inserted
silently, leading to orphaned records or inconsistent JOIN results.

### Schema versioning

As PVACMS evolves, the database schema must evolve with it.  Without a
versioned schema the only options are destructive (drop and recreate) or
fragile (column-existence probes at runtime).  A `schema_version` table
with a migration framework makes the current schema level explicit and provides
a safe, testable path for adding tables and columns in future releases.

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — `initCertsDatabase()` applies four PRAGMAs
   immediately after `sqlite3_open()`; adds `schema_version` table creation
   and the `runSchemaMigrations()` routine; `statusMonitor()` calls
   `runIntegrityCheck()` and `runWalCheckpoint()` on a configurable interval
2. **`src/pvacms/pvacms.h`** — Public accessors on `StatusMonitor` for
   maintenance state (last-check timestamp, last-check result)
3. **`src/pvacms/configcms.h` / `configcms.cpp`** — New
   `integrity_check_interval_secs` configuration field (default: `86400`)
4. **`test/testsqlitehardening.cpp`** — Self-contained test executable
   with 6 test cases

### What does not change

- The `certs` table schema (no columns added or removed)
- The PVAccess wire protocol
- Any existing environment variables or CLI flags for certificate operations
- Behaviour when the database does not yet exist (created fresh with all
  hardening settings in effect)

---

## Detailed Design

### PRAGMAs applied at open time

```sql
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
```

These three statements are executed unconditionally every time the database is
opened.  `journal_mode = WAL` is idempotent — if the database is already in
WAL mode, the PRAGMA is a no-op.  `busy_timeout` and `foreign_keys` are
session-level settings that do not persist across connections and must be
re-applied each time.

**Why 5000 ms?**  This is long enough to absorb bursts from concurrent
certificate creation under normal load, while still surfacing genuine deadlocks
within a reasonable time.  The value is not currently configurable — it is
hard-coded as an implementation detail that may be exposed as a CLI flag in a
future release if operational experience demands it.

### Schema version table

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    version  INTEGER PRIMARY KEY,
    applied  TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO schema_version(version) VALUES (1);
```

The `schema_version` table is created (if absent) on every open, and version 1
is inserted if no row exists.  Subsequent `runSchemaMigrations()` calls check
the current maximum version and apply any pending migrations in order.  Each
migration runs inside its own `BEGIN … COMMIT` transaction; a migration failure
rolls back that migration only and leaves the database at the previous version.

### Periodic integrity check and WAL checkpoint

The integrity check and WAL checkpoint run on **independent timers**, both
controlled by `integrity_check_interval_secs`.

**Integrity check** (`shouldRunMaintenance()`) — fires on the first monitor
cycle after startup, then every `integrity_check_interval_secs` thereafter.
Runs `PRAGMA integrity_check`; a result of `"ok"` is logged at info level,
any other result at error level.  The check does not abort the server; it is
an early-warning signal for operators.

**WAL checkpoint** (`shouldRunCheckpoint()`) — the first checkpoint is
deferred by a full interval from startup (timer initialised to `now()`) to
avoid racing with OS-level lock release on the WAL and shm files from the
previous process.  Subsequent checkpoints run every `integrity_check_interval_secs`.
Uses `sqlite3_wal_checkpoint_v2(SQLITE_CHECKPOINT_PASSIVE)` which is
non-blocking: it flushes as many WAL frames as possible without waiting for
readers.  `SQLITE_BUSY` is silently ignored (normal under concurrent load);
only genuine errors are logged as warnings.

Public accessors on `StatusMonitor` expose the last integrity-check result
so that the `CERT:HEALTH` PV (see `HEALTH_CHECK.md`) can reflect database
health without duplicating the maintenance logic.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--integrity-check-interval` | `EPICS_PVACMS_INTEGRITY_CHECK_INTERVAL` | `86400` | Seconds between integrity checks and WAL checkpoints (independent timers, same interval) |

---

## Security Considerations

WAL mode creates two additional files beside `certs.db`: a write-ahead log
(`certs.db-wal`) and a shared-memory file (`certs.db-shm`).  Both files must
reside in the same directory as the database and must be readable and writable
by the PVACMS process.  Deployments that restrict file permissions on the
database directory should ensure these auxiliary files are covered by the same
access controls.

Foreign-key enforcement can cause existing `INSERT` statements to fail if
referential integrity was previously violated.  In practice, PVACMS maintains
its own referential consistency and the change is transparent; this caveat is
noted for operators who may inspect or modify the database directly.

---

## Migration and Rollback

Opening an existing `certs.db` under the new settings applies WAL mode
transparently.  The `schema_version` table is created and seeded with version 1
if absent — the only DDL change on an existing database.  No existing rows are
modified.

**Rollback** requires reverting `initCertsDatabase()` to the pre-hardening
form.  WAL mode can be reset to DELETE journal with
`PRAGMA journal_mode = DELETE` if required, though this is rarely necessary.
The `schema_version` table is harmless if left in place.

---

## Testing

`test/testsqlitehardening.cpp` verifies (6 tests, all self-contained):

- WAL mode is active after `initCertsDatabase()`
- `busy_timeout` is set to ≥ 5000 ms
- Foreign-key enforcement rejects a referencing insert with no parent row
- `schema_version` table exists and contains exactly one row after open
- Schema version row persists across database close and reopen
- `runSchemaMigrations()` applies pending migrations in version order

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `04a89dc` — "Add SQLite hardening: WAL mode, busy_timeout, foreign_keys, schema versioning" |
| Primary source | `src/pvacms/pvacms.cpp` — `initCertsDatabase()`, `runSchemaMigrations()`, `runIntegrityCheck()` |
| Configuration | `src/pvacms/configcms.h` — `integrity_check_interval_secs` |
| Tests | `test/testsqlitehardening.cpp` |
| SQLite WAL documentation | https://www.sqlite.org/wal.html |
| SQLite `integrity_check` pragma | https://www.sqlite.org/pragma.html#pragma_integrity_check |
| Companion feature | `docs/STARTUP_SELF_TESTS.md` |
