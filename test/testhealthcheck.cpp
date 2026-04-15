/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdint>
#include <stdexcept>
#include <string>

#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

static const char SQL_CREATE_CERTS[] =
    "CREATE TABLE certs("
    "     serial INTEGER PRIMARY KEY,"
    "     status INTEGER"
    ")";

struct SqliteDb {
    sqlite3 *db{nullptr};

    SqliteDb() {
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_open failed: ") + sqlite3_errmsg(db));
        }
        if (sqlite3_exec(db, SQL_CREATE_CERTS, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("CREATE certs failed: ") + sqlite3_errmsg(db));
        }
    }

    ~SqliteDb() {
        if (db) sqlite3_close(db);
    }

    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

bool computeHealthOk(bool db_ok, bool ca_valid) {
    return db_ok && ca_valid;
}

uint64_t queryCertCount(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    uint64_t count = 0u;

    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM certs", -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare COUNT failed: ") + sqlite3_errmsg(db));
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    } else {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("step COUNT failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return count;
}

void insertCert(sqlite3 *db, sqlite3_int64 serial, int status) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
                           "INSERT INTO certs(serial, status) VALUES(?, ?)",
                           -1,
                           &stmt,
                           nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare INSERT failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_bind_int64(stmt, 1, serial);
    sqlite3_bind_int(stmt, 2, status);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("step INSERT failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
}

void testOkTruthTable() {
    testOk(computeHealthOk(true, true), "ok=true when db_ok=true and ca_valid=true");
    testOk(!computeHealthOk(false, true), "ok=false when db_ok=false");
    testOk(!computeHealthOk(true, false), "ok=false when ca_valid=false");
    testOk(!computeHealthOk(false, false), "ok=false when db_ok=false and ca_valid=false");
}

void testSqlQueryEmptyDbReturnsZero() {
    SqliteDb sdb;
    testOk(queryCertCount(sdb.db) == 0u, "empty certs table returns count 0");
}

void testSqlQueryCountsInsertedCerts() {
    SqliteDb sdb;
    insertCert(sdb.db, 1, 1);
    insertCert(sdb.db, 2, 1);
    testOk(queryCertCount(sdb.db) == 2u, "cert count returns 2 after two inserts");
}

}  // namespace

MAIN(testhealthcheck) {
    testPlan(6);
    testOkTruthTable();
    testSqlQueryEmptyDbReturnsZero();
    testSqlQueryCountsInsertedCerts();
    return testDone();
}
