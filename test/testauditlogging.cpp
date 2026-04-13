/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdint>
#include <ctime>
#include <stdexcept>
#include <string>

#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

static const char SQL_CREATE_AUDIT_TABLE[] =
    "CREATE TABLE IF NOT EXISTS audit("
    "     id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "     timestamp INTEGER NOT NULL,"
    "     action TEXT NOT NULL,"
    "     operator TEXT NOT NULL,"
    "     serial INTEGER,"
    "     detail TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp);";

static const char SQL_INSERT_AUDIT[] =
    "INSERT INTO audit(timestamp, action, operator, serial, detail) "
    "VALUES(:timestamp, :action, :operator, :serial, :detail)";

static const char SQL_PRUNE_AUDIT[] =
    "DELETE FROM audit WHERE timestamp < :cutoff";

static const char SQL_GET_RECENT_AUDIT[] =
    "SELECT id, timestamp, action, operator, serial, detail "
    "FROM audit ORDER BY id DESC LIMIT :limit";

static const char AUDIT_ACTION_CREATE[] = "CREATE";
static const char AUDIT_ACTION_APPROVE[] = "APPROVE";
static const char AUDIT_ACTION_REVOKE[] = "REVOKE";

struct SqliteDb {
    sqlite3 *db{nullptr};

    SqliteDb() {
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_open failed: ") + sqlite3_errmsg(db));
        }
        if (sqlite3_exec(db, SQL_CREATE_AUDIT_TABLE, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("CREATE audit failed: ") + sqlite3_errmsg(db));
        }
    }

    ~SqliteDb() {
        if (db) sqlite3_close(db);
    }

    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

void insertAuditRecord(sqlite3 *db, const std::string &action,
                       const std::string &operator_id, uint64_t serial,
                       const std::string &detail, sqlite3_int64 timestamp) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_AUDIT, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare audit insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":timestamp"), timestamp);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":action"), action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":operator"), operator_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), static_cast<sqlite3_int64>(serial));
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":detail"), detail.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("audit insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

int queryCount(sqlite3 *db, const char *sql) {
    sqlite3_stmt *stmt = nullptr;
    int result = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0);
    }
    if (stmt) sqlite3_finalize(stmt);
    return result;
}

void testAuditTableCreation() {
    SqliteDb sdb;
    const int count = queryCount(sdb.db,
                                 "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit'");
    testOk(count == 1, "audit table created");
}

void testInsertAndQueryAuditRecord() {
    SqliteDb sdb;
    insertAuditRecord(sdb.db, AUDIT_ACTION_CREATE, "std:user", 42, "state=VALID", 1000);

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(sdb.db,
                       "SELECT action, operator, serial, detail FROM audit WHERE serial=42",
                       -1, &stmt, nullptr);
    const int rc = sqlite3_step(stmt);
    testOk(rc == SQLITE_ROW
           && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))) == AUDIT_ACTION_CREATE
           && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1))) == "std:user"
           && sqlite3_column_int64(stmt, 2) == 42
           && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3))) == "state=VALID",
           "audit insert stores expected fields");
    sqlite3_finalize(stmt);
}

void testRecentAuditOrdering() {
    SqliteDb sdb;
    insertAuditRecord(sdb.db, AUDIT_ACTION_CREATE, "op1", 1, "first", 1000);
    insertAuditRecord(sdb.db, AUDIT_ACTION_APPROVE, "op2", 2, "second", 1001);
    insertAuditRecord(sdb.db, AUDIT_ACTION_REVOKE, "op3", 3, "third", 1002);

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(sdb.db, SQL_GET_RECENT_AUDIT, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":limit"), 2);

    const bool first_ok = sqlite3_step(stmt) == SQLITE_ROW
                          && sqlite3_column_int64(stmt, 4) == 3
                          && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2))) == AUDIT_ACTION_REVOKE;
    const bool second_ok = sqlite3_step(stmt) == SQLITE_ROW
                           && sqlite3_column_int64(stmt, 4) == 2
                           && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2))) == AUDIT_ACTION_APPROVE;
    testOk(first_ok && second_ok, "recent audit query returns newest rows first");
    sqlite3_finalize(stmt);
}

void testAuditPruningRemovesOldRecords() {
    SqliteDb sdb;
    insertAuditRecord(sdb.db, AUDIT_ACTION_CREATE, "op1", 10, "old", 100);
    insertAuditRecord(sdb.db, AUDIT_ACTION_APPROVE, "op2", 11, "recent", 1000);

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(sdb.db, SQL_PRUNE_AUDIT, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":cutoff"), 500);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const int count = queryCount(sdb.db, "SELECT COUNT(*) FROM audit WHERE serial=10");
    testOk(count == 0, "audit pruning removes rows older than cutoff");
}

void testAuditPruningPreservesRecentRecords() {
    SqliteDb sdb;
    insertAuditRecord(sdb.db, AUDIT_ACTION_CREATE, "op1", 20, "old", 100);
    insertAuditRecord(sdb.db, AUDIT_ACTION_APPROVE, "op2", 21, "recent", 1000);
    insertAuditRecord(sdb.db, AUDIT_ACTION_REVOKE, "op3", 22, "newest", 1001);

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(sdb.db, SQL_PRUNE_AUDIT, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":cutoff"), 500);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const int count = queryCount(sdb.db, "SELECT COUNT(*) FROM audit");

    sqlite3_prepare_v2(sdb.db, SQL_GET_RECENT_AUDIT, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":limit"), 1);
    const bool newest_ok = sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int64(stmt, 4) == 22;
    sqlite3_finalize(stmt);

    testOk(count == 2 && newest_ok, "audit pruning preserves recent rows and newest ordering");
}

}  // namespace

MAIN(testauditlogging) {
    testPlan(5);
    testAuditTableCreation();
    testInsertAndQueryAuditRecord();
    testRecentAuditOrdering();
    testAuditPruningRemovesOldRecords();
    testAuditPruningPreservesRecentRecords();
    return testDone();
}
