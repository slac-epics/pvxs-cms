/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "sqlitehardening.h"

#include <string>

#include <pvxs/log.h>

namespace pvxs {
namespace certs {

namespace {
DEFINE_LOGGER(sqlitehardening, "cms.db.hardening");

// Applies one setting. A failure is reported and shrugged off: the server runs
// without it, so refusing to start would be a worse outcome than running less
// well.
void applyPragma(sqlite3 *db, const std::string &pragma, const char *what) {
    if (sqlite3_exec(db, pragma.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        log_err_printf(sqlitehardening, "Failed to %s: %s\n", what, sqlite3_errmsg(db));
    }
}
}  // namespace

void applySqliteHardening(sqlite3 *const db) {
    if (!db) return;

    applyPragma(db, "PRAGMA journal_mode=WAL", "enable write-ahead logging");
    applyPragma(db, "PRAGMA busy_timeout=" + std::to_string(SQLITE_BUSY_TIMEOUT_MS), "set the busy timeout");
    applyPragma(db, "PRAGMA foreign_keys=ON", "enable foreign keys");

    log_debug_printf(sqlitehardening, "Applied database settings: write-ahead logging, %d ms busy timeout, foreign keys\n",
                     SQLITE_BUSY_TIMEOUT_MS);
}

}  // namespace certs
}  // namespace pvxs
