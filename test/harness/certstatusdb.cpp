/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certstatusdb.h"

#include <chrono>
#include <epicsThread.h>
#include <sqlite3.h>
#include <stdexcept>

namespace cms {
namespace test {

namespace {

class SqliteHandle {
public:
    explicit SqliteHandle(const std::string &db_path) {
        sqlite3 *tmp = nullptr;
        if (sqlite3_open(db_path.c_str(), &tmp) != SQLITE_OK) throw std::runtime_error("sqlite3_open failed");
        db_ = tmp;
    }

    ~SqliteHandle() {
        if (db_) sqlite3_close(db_);
    }

    sqlite3 *get() const { return db_; }

private:
    sqlite3 *db_{nullptr};
};

class Statement {
public:
    Statement(sqlite3 *db, const char *sql) {
        sqlite3_stmt* tmp = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &tmp, nullptr) != SQLITE_OK) throw std::runtime_error("sqlite3_prepare_v2 failed");
        stmt_ = tmp;
    }

    ~Statement() {
        if (stmt_) sqlite3_finalize(stmt_);
    }

    sqlite3_stmt *get() const { return stmt_; }

private:
    sqlite3_stmt *stmt_{nullptr};
};

}  // namespace

std::uint64_t findCertSerialByCommonName(const std::string &db_path,
                                         const std::string &common_name) {
    SqliteHandle db(db_path);
    const Statement stmt(db.get(), "SELECT serial FROM certs WHERE CN = ? ORDER BY serial DESC LIMIT 1");

    sqlite3_bind_text(stmt.get(), 1, common_name.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) throw std::runtime_error("certificate serial for common name not found");

    return static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 0));
}

void setCertStatus(const std::string &db_path, std::uint64_t serial, const int status) {
    const SqliteHandle db(db_path);
    const Statement stmt(db.get(), "UPDATE certs SET status = ? WHERE serial = ?");

    sqlite3_bind_int(stmt.get(), 1, status);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(serial));
    if (sqlite3_step(stmt.get()) != SQLITE_DONE || sqlite3_changes(db.get()) != 1) throw std::runtime_error("status update failed");
}

void setCertRenewBy(const std::string &db_path, const std::uint64_t serial, const std::int64_t renew_by) {
    const SqliteHandle db(db_path);
    const Statement stmt(db.get(), "UPDATE certs SET renew_by = ?, renewal_due = 0 WHERE serial = ?");

    sqlite3_bind_int64(stmt.get(), 1, renew_by);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(serial));
    if (sqlite3_step(stmt.get()) != SQLITE_DONE || sqlite3_changes(db.get()) != 1) throw std::runtime_error("renew-by update failed");
}

CertRecord loadCertRecord(const std::string &db_path, const std::uint64_t serial) {
    const SqliteHandle db(db_path);
    const Statement stmt(db.get(), "SELECT status, renew_by, renewal_due FROM certs WHERE serial = ?");

    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(serial));
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) throw std::runtime_error("certificate row not found");

    CertRecord row;
    row.status = sqlite3_column_int(stmt.get(), 0);
    row.renew_by = sqlite3_column_int64(stmt.get(), 1);
    row.renewal_due = sqlite3_column_int(stmt.get(), 2);
    return row;
}

bool waitForCertRecord(const std::string &db_path, const std::uint64_t serial, const std::function<bool(const CertRecord &)>& predicate, const double timeout_secs) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<int>(timeout_secs * 1000.0));
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate(loadCertRecord(db_path, serial))) return true;
        epicsThreadSleep(0.1);
    }
    return predicate(loadCertRecord(db_path, serial));
}

}  // namespace test
}  // namespace cms
