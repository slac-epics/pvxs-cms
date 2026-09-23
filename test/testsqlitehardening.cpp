/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * The certificate database is opened with settings that decide how it behaves
 * under contention. The one that matters is the busy timeout: without it SQLite
 * reports "database is locked" the instant it meets a lock rather than waiting,
 * which stopped the certificate manager from starting. These check that
 * applySqliteHardening really puts the connection in that state, so the
 * behaviour cannot be lost silently.
 */

#include <cstdio>
#include <string>

#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "sqlitehardening.h"

using namespace pvxs::certs;

namespace {

// Reads back a single-value PRAGMA, which is how the connection reports the
// state it is actually in - as opposed to what we asked it to be.
std::string readPragma(sqlite3 *db, const char *pragma) {
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(db, pragma, -1, &statement, nullptr) != SQLITE_OK) return "<prepare failed>";
    std::string value{"<no row>"};
    if (sqlite3_step(statement) == SQLITE_ROW) {
        if (const auto *text = sqlite3_column_text(statement, 0)) {
            value = reinterpret_cast<const char *>(text);
        }
    }
    sqlite3_finalize(statement);
    return value;
}

struct TempDb {
    std::string path;
    sqlite3 *db{nullptr};

    explicit TempDb(std::string file) : path(std::move(file)) {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) db = nullptr;
    }
    ~TempDb() {
        if (db) sqlite3_close(db);
        std::remove(path.c_str());
        std::remove((path + "-wal").c_str());
        std::remove((path + "-shm").c_str());
    }
    TempDb(const TempDb &) = delete;
    TempDb &operator=(const TempDb &) = delete;
};

// A connection with no settings applied is the state that produced the failure:
// journal_mode is not write-ahead logging and the busy timeout is zero, so any
// lock is reported immediately. Establishing this is what makes the checks below
// meaningful rather than a restatement of SQLite's defaults.
void testDefaultsAreNotHardened() {
    testDiag("A freshly opened database is not hardened");
    TempDb fresh{"testsqlitehardening_defaults.db"};
    testOk(fresh.db != nullptr, "Opened a database to check its defaults");
    if (!fresh.db) return;

    testOk(readPragma(fresh.db, "PRAGMA journal_mode;") != "wal", "Write-ahead logging is not on by default");
    testEq(readPragma(fresh.db, "PRAGMA busy_timeout;"), std::string("0"));
}

void testHardeningIsApplied() {
    testDiag("applySqliteHardening puts the connection in the expected state");
    TempDb hardened{"testsqlitehardening_applied.db"};
    testOk(hardened.db != nullptr, "Opened a database to harden");
    if (!hardened.db) return;

    applySqliteHardening(hardened.db);

    testEq(readPragma(hardened.db, "PRAGMA journal_mode;"), std::string("wal"));
    testEq(readPragma(hardened.db, "PRAGMA busy_timeout;"), std::to_string(SQLITE_BUSY_TIMEOUT_MS));
    testEq(readPragma(hardened.db, "PRAGMA foreign_keys;"), std::string("1"));
}

// Write-ahead logging is recorded in the database file, so it survives reopening
// once the file has content; the busy timeout belongs to the connection and does
// not. That difference is why the settings are applied on every open rather than
// once at creation - applying them once would leave later connections with no
// timeout, which is the failure this guards against.
void testWhatSurvivesReopening() {
    testDiag("Which settings survive reopening the same file");
    const std::string path{"testsqlitehardening_reopen.db"};
    // Opened directly rather than through TempDb, whose destructor removes the file
    // - which would leave nothing to reopen.
    sqlite3 *first = nullptr;
    testOk(sqlite3_open(path.c_str(), &first) == SQLITE_OK, "Opened a database to harden and close");
    if (first) {
        // Content first: a database with no pages has no header to record the
        // journal mode in, so setting it on an empty file does not stick.
        sqlite3_exec(first, "CREATE TABLE t(x INTEGER);", nullptr, nullptr, nullptr);
        applySqliteHardening(first);
        sqlite3_close(first);
    }

    sqlite3 *reopened = nullptr;
    testOk(sqlite3_open(path.c_str(), &reopened) == SQLITE_OK, "Reopened the same database file");
    if (reopened) {
        testEq(readPragma(reopened, "PRAGMA journal_mode;"), std::string("wal"));
        testEq(readPragma(reopened, "PRAGMA busy_timeout;"), std::string("0"));
        sqlite3_close(reopened);
    }
    std::remove(path.c_str());
    std::remove((path + "-wal").c_str());
    std::remove((path + "-shm").c_str());
}

void testNullConnectionIsIgnored() {
    testDiag("A null connection is ignored rather than crashing");
    applySqliteHardening(nullptr);
    testPass("applySqliteHardening(nullptr) returned");
}

}  // namespace

MAIN(testsqlitehardening) {
    testPlan(12);
    testDefaultsAreNotHardened();
    testHardeningIsApplied();
    testWhatSurvivesReopening();
    testNullConnectionIsIgnored();
    return testDone();
}
