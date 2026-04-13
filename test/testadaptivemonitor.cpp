/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <stdexcept>
#include <string>

#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

static const uint32_t kMonitorIntervalMin = 5;
static const uint32_t kMonitorIntervalMax = 60;

static const int kCertStatusValid = 1;
static const int kCertStatusPending = 2;

static const char SQL_CREATE_CERTS[] =
    "CREATE TABLE certs("
    "     serial INTEGER PRIMARY KEY,"
    "     skid TEXT,"
    "     CN TEXT,"
    "     O TEXT,"
    "     OU TEXT,"
    "     C TEXT,"
    "     approved INTEGER,"
    "     not_before INTEGER,"
    "     not_after INTEGER,"
    "     renew_by INTEGER,"
    "     renewal_due INTEGER,"
    "     status INTEGER,"
    "     status_date INTEGER"
    ")";

static const char SQL_INSERT_CERT[] =
    "INSERT INTO certs(serial, skid, CN, O, OU, C, approved, not_before, not_after, renew_by, renewal_due, status, status_date) "
    "VALUES(?, '', '', '', '', '', 0, ?, ?, ?, 0, ?, 0)";

static const char SQL_COUNT_NEAR_TRANSITIONS[] =
    "SELECT COUNT(*) FROM certs WHERE "
    "(status = 2 AND not_before <= ?) OR "
    "(status = 1 AND not_after <= ?) OR "
    "(status = 1 AND renew_by > 0 AND renew_by <= ?)";

struct SqliteDb {
    sqlite3 *db{nullptr};

    explicit SqliteDb(bool create_schema=true) {
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_open failed: ") + sqlite3_errmsg(db));
        }
        if (create_schema && sqlite3_exec(db, SQL_CREATE_CERTS, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("CREATE certs failed: ") + sqlite3_errmsg(db));
        }
    }

    ~SqliteDb() {
        if (db) sqlite3_close(db);
    }

    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

uint32_t computeAdaptiveInterval(uint32_t interval_min,
                                 uint32_t interval_max,
                                 uint32_t near_transition_count) {
    const uint32_t clamped_interval_min = std::min(interval_min, interval_max);
    const uint32_t clamped_interval_max = std::max(interval_min, interval_max);

    uint32_t computed_secs;
    if (near_transition_count == 0) {
        computed_secs = clamped_interval_max;
    } else if (near_transition_count >= 100) {
        computed_secs = clamped_interval_min;
    } else {
        computed_secs = clamped_interval_max
            - (clamped_interval_max - clamped_interval_min) * near_transition_count / 100;
    }

    if (computed_secs < clamped_interval_min) computed_secs = clamped_interval_min;
    if (computed_secs > clamped_interval_max) computed_secs = clamped_interval_max;
    return computed_secs;
}

bool countNearTransitions(sqlite3 *db, time_t lookahead, uint32_t &count) {
    sqlite3_stmt *stmt = nullptr;
    count = 0;

    if (sqlite3_prepare_v2(db, SQL_COUNT_NEAR_TRANSITIONS, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(lookahead));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(lookahead));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(lookahead));

    const bool ok = sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) {
        count = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));
    }
    sqlite3_finalize(stmt);
    return ok;
}

void insertCert(sqlite3 *db,
                sqlite3_int64 serial,
                sqlite3_int64 not_before,
                sqlite3_int64 not_after,
                sqlite3_int64 renew_by,
                int status) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_CERT, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare cert insert failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_bind_int64(stmt, 1, serial);
    sqlite3_bind_int64(stmt, 2, not_before);
    sqlite3_bind_int64(stmt, 3, not_after);
    sqlite3_bind_int64(stmt, 4, renew_by);
    sqlite3_bind_int(stmt, 5, status);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("cert insert failed: ") + sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
}

void testComputationZeroUsesMax() {
    const uint32_t actual = computeAdaptiveInterval(kMonitorIntervalMin, kMonitorIntervalMax, 0);
    testOk(actual == kMonitorIntervalMax, "0 near-transition certs uses max interval (got %u)", actual);
}

void testComputationHundredUsesMin() {
    const uint32_t actual = computeAdaptiveInterval(kMonitorIntervalMin, kMonitorIntervalMax, 100);
    testOk(actual == kMonitorIntervalMin, "100 near-transition certs uses min interval (got %u)", actual);
}

void testComputationFiftyScalesLinearly() {
    const uint32_t actual = computeAdaptiveInterval(kMonitorIntervalMin, kMonitorIntervalMax, 50);
    testOk(actual == 33u, "50 near-transition certs scales interval linearly (got %u)", actual);
}

void testSqlQueryEmptyDbReturnsZero() {
    SqliteDb sdb;
    uint32_t count = 999;
    const bool ok = countNearTransitions(sdb.db, time(nullptr) + 120, count);
    testOk(ok && count == 0, "empty cert table returns zero near-transition certs");
}

void testSqlQueryCountsNearTransitions() {
    SqliteDb sdb;
    const time_t now = time(nullptr);
    const time_t lookahead = now + 120;

    for (sqlite3_int64 i = 1; i <= 20; ++i) {
        insertCert(sdb.db, i, static_cast<sqlite3_int64>(now + 60), static_cast<sqlite3_int64>(now + 3600), 0,
                   kCertStatusPending);
    }
    for (sqlite3_int64 i = 21; i <= 35; ++i) {
        insertCert(sdb.db, i, static_cast<sqlite3_int64>(now - 3600), static_cast<sqlite3_int64>(now + 60), 0,
                   kCertStatusValid);
    }
    for (sqlite3_int64 i = 36; i <= 50; ++i) {
        insertCert(sdb.db, i, static_cast<sqlite3_int64>(now - 3600), static_cast<sqlite3_int64>(now + 3600),
                   static_cast<sqlite3_int64>(now + 60), kCertStatusValid);
    }

    uint32_t count = 0;
    const bool ok = countNearTransitions(sdb.db, lookahead, count);
    testOk(ok && count == 50, "query counts pending, expiring, and renewal-near certificates");
}

void testSqlQueryIgnoresFarTransitions() {
    SqliteDb sdb;
    const time_t now = time(nullptr);
    const time_t lookahead = now + 120;

    insertCert(sdb.db, 1, static_cast<sqlite3_int64>(lookahead + 10), static_cast<sqlite3_int64>(now + 3600), 0,
               kCertStatusPending);
    insertCert(sdb.db, 2, static_cast<sqlite3_int64>(now - 3600), static_cast<sqlite3_int64>(lookahead + 10), 0,
               kCertStatusValid);
    insertCert(sdb.db, 3, static_cast<sqlite3_int64>(now - 3600), static_cast<sqlite3_int64>(now + 3600),
               static_cast<sqlite3_int64>(lookahead + 10), kCertStatusValid);

    uint32_t count = 999;
    const bool ok = countNearTransitions(sdb.db, lookahead, count);
    testOk(ok && count == 0, "query ignores certificates beyond lookahead window");
}

void testSqlQueryFailsGracefullyWithoutTable() {
    SqliteDb sdb(false);
    uint32_t count = 999;
    const bool ok = countNearTransitions(sdb.db, time(nullptr) + 120, count);
    testOk(!ok && count == 0, "query fails gracefully when certs table is missing");
}

}  // namespace

MAIN(testadaptivemonitor) {
    testPlan(7);
    testComputationZeroUsesMax();
    testComputationHundredUsesMin();
    testComputationFiftyScalesLinearly();
    testSqlQueryEmptyDbReturnsZero();
    testSqlQueryCountsNearTransitions();
    testSqlQueryIgnoresFarTransitions();
    testSqlQueryFailsGracefullyWithoutTable();
    return testDone();
}
