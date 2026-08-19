/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SQLITEHARDENING_H_
#define PVXS_SQLITEHARDENING_H_

#include <sqlite3.h>

namespace pvxs {
namespace certs {

/**
 * @brief Apply the settings the certificate database is expected to run with.
 *
 * Call once, immediately after opening a connection and before any statement
 * runs on it:
 *
 *  - busy_timeout: without it SQLite gives up the instant it meets a lock and
 *    reports "database is locked". That surfaced at start-up as the schema
 *    migration failing and the server exiting, recovering only because it was
 *    restarted. With a timeout it waits for the lock instead.
 *  - write-ahead logging: readers and one writer can work at the same time, so
 *    the contention is rarer to begin with.
 *  - foreign keys: enforced rather than parsed and ignored, which is SQLite's
 *    default for backwards compatibility.
 *
 * A setting that cannot be applied is logged and not fatal: the server still
 * works without it, just less well.
 *
 * @param db an open database connection
 */
void applySqliteHardening(sqlite3 *db);

/** Milliseconds SQLite waits for a lock before reporting "database is locked". */
constexpr int SQLITE_BUSY_TIMEOUT_MS = 5000;

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_SQLITEHARDENING_H_
