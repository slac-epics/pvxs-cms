/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

struct SqliteDb {
    sqlite3 *db{nullptr};

    explicit SqliteDb(const std::string &path)
    {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_open failed: ") + sqlite3_errmsg(db));
        }
    }

    ~SqliteDb()
    {
        if (db) sqlite3_close(db);
    }

    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

struct TempPath {
    std::string path;

    explicit TempPath(const char *pattern)
    {
        char tpl[128];
        std::snprintf(tpl, sizeof(tpl), "%s", pattern);
        const int fd = mkstemp(tpl);
        if (fd < 0) {
            throw std::runtime_error(std::string("mkstemp failed: ") + std::strerror(errno));
        }
        close(fd);
        path = tpl;
    }

    ~TempPath()
    {
        if (!path.empty()) {
            unlink(path.c_str());
        }
    }

    TempPath(const TempPath &) = delete;
    TempPath &operator=(const TempPath &) = delete;
};

void execOrThrow(sqlite3 *db, const char *sql)
{
    if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("sqlite3_exec failed: ") + sqlite3_errmsg(db));
    }
}

void insertCert(sqlite3 *db, sqlite3_int64 serial, const std::string &owner)
{
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
                           "INSERT INTO certs(serial, owner) VALUES(?, ?)",
                           -1,
                           &stmt,
                           nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare INSERT failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_bind_int64(stmt, 1, serial);
    sqlite3_bind_text(stmt, 2, owner.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("step INSERT failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
}

bool performBackup(sqlite3 *src_db, const std::string &dest_path)
{
    sqlite3 *dest_db = nullptr;
    if (sqlite3_open(dest_path.c_str(), &dest_db) != SQLITE_OK) {
        if (dest_db) sqlite3_close(dest_db);
        return false;
    }

    sqlite3_backup *backup = sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (!backup) {
        sqlite3_close(dest_db);
        return false;
    }

    const int step_status = sqlite3_backup_step(backup, -1);
    const int finish_status = sqlite3_backup_finish(backup);
    const int close_status = sqlite3_close(dest_db);
    return step_status == SQLITE_DONE && finish_status == SQLITE_OK && close_status == SQLITE_OK;
}

uint64_t fileSize(const std::string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        throw std::runtime_error(std::string("stat failed: ") + std::strerror(errno));
    }
    return static_cast<uint64_t>(st.st_size);
}

sqlite3_int64 queryInt64(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare query failed: ") + sqlite3_errmsg(db));
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("step query failed: ") + sqlite3_errmsg(db));
    }

    const sqlite3_int64 value = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return value;
}

std::string queryText(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare query failed: ") + sqlite3_errmsg(db));
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("step query failed: ") + sqlite3_errmsg(db));
    }

    const auto *text = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    std::string value = text ? text : "";
    sqlite3_finalize(stmt);
    return value;
}

void testDatabaseBackup()
{
    SqliteDb src_db(":memory:");
    execOrThrow(src_db.db, "CREATE TABLE certs(serial INTEGER PRIMARY KEY, owner TEXT NOT NULL)");
    insertCert(src_db.db, 1, "client1");
    insertCert(src_db.db, 2, "server1");

    TempPath backup_path("/tmp/testdatabasebackup.XXXXXX");
    testOk(performBackup(src_db.db, backup_path.path), "SQLite online backup succeeds");
    testOk(fileSize(backup_path.path) > 0u, "backup file exists and is non-empty");

    SqliteDb backup_db(backup_path.path);
    testOk(queryInt64(backup_db.db, "SELECT COUNT(*) FROM certs") == 2,
           "backup database contains expected row count");
    testOk(queryText(backup_db.db, "SELECT owner FROM certs WHERE serial = 2") == "server1",
           "backup database preserves inserted data");
    testOk(queryText(backup_db.db, "PRAGMA integrity_check") == "ok",
           "backup database passes integrity check");
}

void testInvalidBackupPath()
{
    SqliteDb src_db(":memory:");
    execOrThrow(src_db.db, "CREATE TABLE certs(serial INTEGER PRIMARY KEY, owner TEXT NOT NULL)");
    insertCert(src_db.db, 3, "ioc1");

    TempPath base_path("/tmp/testdatabasebackup_invalid.XXXXXX");
    unlink(base_path.path.c_str());
    const std::string invalid_path = base_path.path + "/missing/backup.db";
    testOk(!performBackup(src_db.db, invalid_path), "backup to invalid path fails gracefully");
}

}  // namespace

MAIN(testdatabasebackup)
{
    testPlan(6);
    testDiag("Exercise SQLite online backup API with a real backup file");
    testDatabaseBackup();
    testInvalidBackupPath();
    return testDone();
}
