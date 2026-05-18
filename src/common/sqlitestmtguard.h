/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CMS_SQLITESTMTGUARD_H_
#define PVXS_CMS_SQLITESTMTGUARD_H_

#include <sqlite3.h>

namespace cms {
namespace detail {

// Finalizes the prepared statement even if the in-between row-processing
// loop throws.  An unfinalized SELECT in WAL mode holds an open read
// transaction that corrupts the next prepare on the same sqlite3 connection.
class SqliteStmtGuard {
    sqlite3_stmt *stmt_;
public:
    explicit SqliteStmtGuard(sqlite3_stmt *stmt) : stmt_(stmt) {}
    ~SqliteStmtGuard() { if (stmt_) sqlite3_finalize(stmt_); }
    SqliteStmtGuard(const SqliteStmtGuard&) = delete;
    SqliteStmtGuard &operator=(const SqliteStmtGuard&) = delete;
    sqlite3_stmt *get() const { return stmt_; }
    sqlite3_stmt *release() { auto s = stmt_; stmt_ = nullptr; return s; }
};

}  // namespace detail
}  // namespace cms

#endif  // PVXS_CMS_SQLITESTMTGUARD_H_
