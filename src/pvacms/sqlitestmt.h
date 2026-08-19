/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SQLITESTMT_H_
#define PVXS_SQLITESTMT_H_

#include <sqlite3.h>

namespace pvxs {
namespace certs {

/**
 * @brief Owns a prepared statement and finalises it however the scope is left.
 *
 * A statement that has returned a row but is never finalised leaves a read
 * transaction open on its connection. Every certificate manager statement runs
 * on the one shared connection, so from then on a write can fail with
 * "database is locked" - and the busy timeout does not help, because the
 * connection is waiting on itself. Balancing this by hand means every throw,
 * every early return and every exception from a called function has to be
 * matched with a finalise, which is how the leaks got in.
 *
 * Usage - take the address to prepare into, then let scope do the rest:
 *
 *     SqliteStmt statement;
 *     if (sqlite3_prepare_v2(db, sql, -1, statement.acquire(), nullptr) != SQLITE_OK) {
 *         throw std::runtime_error(...);   // nothing to finalise: prepare failed
 *     }
 *     if (sqlite3_step(statement) == SQLITE_ROW) { ... }
 *     // finalised here, however this scope is left
 *
 * On a failed prepare SQLite leaves the pointer unspecified, so nothing is
 * finalised in that case: the guard only finalises what it was given.
 */
class SqliteStmt final {
  public:
    SqliteStmt() = default;
    ~SqliteStmt() { reset(); }

    SqliteStmt(const SqliteStmt &) = delete;
    SqliteStmt &operator=(const SqliteStmt &) = delete;

    /** Address to prepare into. Any statement already held is finalised first. */
    sqlite3_stmt **acquire() {
        reset();
        return &stmt_;
    }

    /** The statement, for passing to the sqlite3_* calls. */
    sqlite3_stmt *get() const { return stmt_; }
    operator sqlite3_stmt *() const { return stmt_; }

    /** Finalise early, where a scope holds the statement longer than needed. */
    void reset() {
        if (stmt_) {
            sqlite3_finalize(stmt_);
            stmt_ = nullptr;
        }
    }

  private:
    sqlite3_stmt *stmt_{nullptr};
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_SQLITESTMT_H_
