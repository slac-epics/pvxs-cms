# SQLite Database Backup

## Executive Summary

We propose adding online backup support to PVACMS so that the certificate
database can be copied to a safe location without stopping the service.
The certificate database (`certs.db`) is the single source of truth for all
issued certificates, their status, and their audit history.  Without a backup
mechanism, a disk failure or accidental deletion is unrecoverable: the CA can
re-issue certificates, but the historical record — serial numbers, audit trail,
approval history — is lost permanently.

The implementation uses the SQLite Online Backup API, which safely handles
WAL-mode databases and does not require an exclusive lock.  Two operational
modes are supported: a one-shot mode for scripted backups and a periodic mode
integrated into the status-monitor cycle with configurable retention.

---

## Background and Motivation

### The single-point-of-failure risk

PVACMS stores all certificate state in a single SQLite file.  SQLite is
reliable and crash-safe (especially in WAL mode, see `SQLITE_HARDENING.md`),
but hardware failure, accidental deletion, or filesystem corruption can still
result in data loss.  The CA private key can be restored from a separate
keychain backup, but the certificate database cannot be regenerated.

Specifically, the following are lost without a backup:
- Certificate serial numbers and issuance history (needed for revocation)
- The full audit trail
- The schedule table (validity windows for certificates)
- The cluster sync state

### Online backup necessity

A naive `cp certs.db backup.db` is unsafe for a WAL-mode database: the WAL
file and the shared-memory file must be consistent with the main database file
at the time of copy.  SQLite's Online Backup API handles this correctly by
reading through the WAL and copying a fully consistent snapshot.

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — `runDatabaseBackup()` function using the
   SQLite Online Backup API; one-shot mode triggered from `main()`;
   periodic mode triggered in `statusMonitor()` maintenance cycle; retention
   pruning of old backup files
2. **`src/pvacms/pvacms.h`** — Declarations for backup functions; backup state
   in `StatusMonitor`
3. **`src/pvacms/configcms.h` / `configcms.cpp`** — Three new configuration
   fields
4. **`test/testdatabasebackup.cpp`** — Self-contained test executable with 6
   test cases

### What does not change

- Normal certificate operations (backup runs in the monitor thread, not the
  RPC handlers)
- The database schema
- The PVAccess wire protocol

---

## Detailed Design

### SQLite Online Backup API

The backup uses the standard three-step SQLite pattern:

```cpp
sqlite3_backup *backup = sqlite3_backup_init(dest_db, "main", src_db, "main");
while (sqlite3_backup_step(backup, -1) == SQLITE_OK) {}
sqlite3_backup_finish(backup);
```

`sqlite3_backup_step(-1)` copies the entire database in a single step.
Concurrent writes to the source database during the backup are safely handled:
SQLite will restart the backup from the beginning if a page is modified during
the copy.  For a typical PVACMS database (thousands of rows, a few MB), the
backup completes in milliseconds and restarts are rare.

### One-shot mode

`pvacms --backup <path>` performs a single backup to the specified file and
exits with code 0 on success or 1 on failure.  This mode is intended for use
in cron jobs, deployment scripts, or Kubernetes `CronJob` manifests:

```sh
pvacms --backup /backups/certs_$(date +%Y%m%d_%H%M%S)
```

If the path does not already end in `.db`, the extension is appended
automatically, so the above produces
`/backups/certs_<YYYYMMDD_HHMMSS>.db`.

On success, pvacms prints the destination path to stdout:

```
Database backup written: /backups/certs_20260415_200503.db
```

When `--backup` is specified, no PVAccess server is started, no CA keychain
is loaded, and no schema migrations are run.  The source database is opened
read-only via `sqlite3_open_v2(SQLITE_OPEN_READONLY)`, so the backup process
cannot modify the live database.

### Periodic mode

When `--backup-interval <secs>` is set, the status-monitor cycle creates
a timestamped backup in `--backup-dir` (defaulting to the same directory as
the database) whenever the interval has elapsed:

```
<backup-dir>/certs_backup_<YYYYMMDD_HHMMSS>.db
```

The timestamp is UTC.  The naming convention `certs_backup_*.db` is used
for retention matching.

### Retention pruning

After each periodic backup, files matching `certs_backup_*.db` in the backup
directory are enumerated and sorted by name (which sorts by timestamp due to
the `YYYYMMDD_HHMMSS` format).  If the count exceeds `--backup-retention`,
the oldest files are deleted until the count equals the retention limit.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--backup <path>` | — | — | One-shot backup path; exits after backup |
| `--backup-interval` | `EPICS_PVACMS_BACKUP_INTERVAL` | `0` (disabled) | Seconds between periodic backups; `0` disables |
| `--backup-dir` | `EPICS_PVACMS_BACKUP_DIR` | Same as database | Directory for periodic backup files |
| `--backup-retention` | `EPICS_PVACMS_BACKUP_RETENTION` | `7` | Number of periodic backup files to retain |

---

## Security Considerations

Backup files contain the complete certificate database, including the audit
trail and all certificate metadata.  They do not contain private keys (which
are stored in the CA keychain, not the database).  However, serial numbers and
issuer identities in the backup could be used to craft revocation requests if
an attacker obtained both the backup and a valid admin credential.

Backup files should be stored with the same access controls as the live
database (`0600`, owner-only).  The `runDatabaseBackup()` function creates
backup files with `0600` permissions on POSIX systems.

The `--backup` one-shot mode opens the live database with `SQLITE_OPEN_READONLY`
to avoid any risk of modification.

---

## Migration and Rollback

The backup feature is opt-in: `--backup-interval` defaults to `0` (disabled).
Existing deployments are unaffected until the flag is set.

**Rollback** requires removing `runDatabaseBackup()` and the backup
configuration fields.  Existing backup files are plain SQLite databases and
can be retained, restored with `sqlite3_backup_init`, or deleted independently.

---

## Testing

`test/testdatabasebackup.cpp` exercises (6 tests):

- One-shot backup produces a valid SQLite database at the specified path
- Backup file contains the same rows as the source database
- Backup file is non-empty (file size > 0)
- Periodic backup creates a timestamped file in the backup directory
- Retention pruning removes the oldest file when count exceeds the limit
- Backup is consistent: rows inserted after backup starts are not in the backup
  (snapshot semantics)

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `27e93ae` — "feat: add SQLite database backup with one-shot and periodic modes" |
| Primary source | `src/pvacms/pvacms.cpp` — `runDatabaseBackup()` |
| Configuration | `src/pvacms/configcms.h` — `backup_interval_secs`, `backup_dir`, `backup_retention` |
| Tests | `test/testdatabasebackup.cpp` |
| SQLite Online Backup API | https://www.sqlite.org/backup.html |
| Companion feature | `docs/SQLITE_HARDENING.md` (WAL mode, which backup API handles correctly) |
