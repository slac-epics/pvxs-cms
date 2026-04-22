/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <stdexcept>

#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

static const int EXPECTED_SCHEMA_VERSION = 1;

static const char SQL_CREATE_SCHEMA_VERSION[] =
    "CREATE TABLE IF NOT EXISTS schema_version("
    "  version INTEGER NOT NULL,"
    "  applied_at INTEGER NOT NULL"
    ")";

static const char SQL_GET_SCHEMA_VERSION[] =
    "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1";

static const char SQL_INSERT_SCHEMA_VERSION[] =
    "INSERT INTO schema_version(version, applied_at) VALUES(?, ?)";

struct SqliteDb {
    sqlite3 *db{nullptr};
    SqliteDb() = default;
    ~SqliteDb() { if (db) sqlite3_close(db); }
    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

void openAndHarden(SqliteDb &sdb, const std::string &path) {
    if (sqlite3_open(path.c_str(), &sdb.db) != SQLITE_OK) {
        throw std::runtime_error(std::string("sqlite3_open failed: ") + sqlite3_errmsg(sdb.db));
    }
    sqlite3_exec(sdb.db, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    sqlite3_exec(sdb.db, "PRAGMA busy_timeout=5000", nullptr, nullptr, nullptr);
    sqlite3_exec(sdb.db, "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr);
}

void createSchemaVersion(sqlite3 *db) {
    if (sqlite3_exec(db, SQL_CREATE_SCHEMA_VERSION, nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("CREATE schema_version failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_GET_SCHEMA_VERSION, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("PREPARE get version failed: ") + sqlite3_errmsg(db));
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_stmt *ins = nullptr;
        if (sqlite3_prepare_v2(db, SQL_INSERT_SCHEMA_VERSION, -1, &ins, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("PREPARE insert version failed: ") + sqlite3_errmsg(db));
        }
        sqlite3_bind_int(ins, 1, EXPECTED_SCHEMA_VERSION);
        sqlite3_bind_int64(ins, 2, static_cast<sqlite3_int64>(time(nullptr)));
        if (sqlite3_step(ins) != SQLITE_DONE) {
            sqlite3_finalize(ins);
            throw std::runtime_error(std::string("INSERT version failed: ") + sqlite3_errmsg(db));
        }
        sqlite3_finalize(ins);
    } else {
        sqlite3_finalize(stmt);
    }
}

std::string queryText(sqlite3 *db, const char *sql) {
    sqlite3_stmt *stmt = nullptr;
    std::string result;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const auto *text = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            if (text) result = text;
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    return result;
}

void removeDb(const std::string &path) {
    std::remove(path.c_str());
    std::remove((path + "-wal").c_str());
    std::remove((path + "-shm").c_str());
}

void testWalMode() {
    testDiag("Test WAL journal mode after hardening PRAGMAs");
    const std::string path = "test_hardening_wal.db";
    removeDb(path);

    SqliteDb sdb;
    openAndHarden(sdb, path);

    const auto mode = queryText(sdb.db, "PRAGMA journal_mode");
    testOk(mode == "wal", "journal_mode is WAL (got: %s)", mode.c_str());

    sdb.~SqliteDb();
    new (&sdb) SqliteDb();
    removeDb(path);
}

void testBusyTimeout() {
    testDiag("Test busy_timeout after hardening PRAGMAs");
    const std::string path = "test_hardening_timeout.db";
    removeDb(path);

    SqliteDb sdb;
    openAndHarden(sdb, path);

    const auto timeout = queryText(sdb.db, "PRAGMA busy_timeout");
    testOk(timeout == "5000", "busy_timeout is 5000 (got: %s)", timeout.c_str());

    sdb.~SqliteDb();
    new (&sdb) SqliteDb();
    removeDb(path);
}

void testForeignKeys() {
    testDiag("Test foreign_keys after hardening PRAGMAs");
    const std::string path = "test_hardening_fk.db";
    removeDb(path);

    SqliteDb sdb;
    openAndHarden(sdb, path);

    const auto fk = queryText(sdb.db, "PRAGMA foreign_keys");
    testOk(fk == "1", "foreign_keys is ON (got: %s)", fk.c_str());

    sdb.~SqliteDb();
    new (&sdb) SqliteDb();
    removeDb(path);
}

void testSchemaVersion() {
    testDiag("Test schema_version table created with correct version");
    const std::string path = "test_hardening_schema.db";
    removeDb(path);

    SqliteDb sdb;
    openAndHarden(sdb, path);
    createSchemaVersion(sdb.db);

    const auto version = queryText(sdb.db,
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1");
    char expected[16];
    std::snprintf(expected, sizeof(expected), "%d", EXPECTED_SCHEMA_VERSION);
    testOk(version == expected,
           "schema_version is %d (got: %s)", EXPECTED_SCHEMA_VERSION, version.c_str());

    sdb.~SqliteDb();
    new (&sdb) SqliteDb();
    removeDb(path);
}

void testReopenPreservesWal() {
    testDiag("Test WAL mode persists across reopen");
    const std::string path = "test_hardening_reopen.db";
    removeDb(path);

    {
        SqliteDb sdb;
        openAndHarden(sdb, path);
        createSchemaVersion(sdb.db);
    }

    SqliteDb sdb;
    openAndHarden(sdb, path);

    const auto mode = queryText(sdb.db, "PRAGMA journal_mode");
    testOk(mode == "wal", "journal_mode is WAL after reopen (got: %s)", mode.c_str());

    const auto version = queryText(sdb.db,
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1");
    char expected[16];
    std::snprintf(expected, sizeof(expected), "%d", EXPECTED_SCHEMA_VERSION);
    testOk(version == expected,
           "schema_version preserved after reopen (got: %s)", version.c_str());

    sdb.~SqliteDb();
    new (&sdb) SqliteDb();
    removeDb(path);
}

}  // namespace

MAIN(testsqlitehardening) {
    testPlan(6);
    testWalMode();
    testBusyTimeout();
    testForeignKeys();
    testSchemaVersion();
    testReopenPreservesWal();
    return testDone();
}
