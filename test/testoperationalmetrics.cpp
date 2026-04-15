/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

static const int kCertStatusValid = 1;

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

struct CcrTimingTracker {
    mutable std::mutex mtx_;
    double total_ms_{0.0};
    uint64_t count_{0u};

    void record(double ms) {
        std::lock_guard<std::mutex> lk(mtx_);
        total_ms_ += ms;
        ++count_;
    }

    double averageMs() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return count_ > 0 ? total_ms_ / static_cast<double>(count_) : 0.0;
    }
};

struct TempFile {
    std::string path;

    explicit TempFile(size_t size_bytes) {
        char tpl[] = "/tmp/testoperationalmetrics.XXXXXX";
        const int fd = mkstemp(tpl);
        if (fd < 0) {
            throw std::runtime_error("mkstemp failed");
        }

        path = tpl;
        std::string contents(size_bytes, 'x');
        const ssize_t written = write(fd, contents.data(), contents.size());
        close(fd);

        if (written != static_cast<ssize_t>(contents.size())) {
            throw std::runtime_error("write failed");
        }
    }

    ~TempFile() {
        if (!path.empty()) {
            unlink(path.c_str());
        }
    }

    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;
};

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

uint64_t queryActiveCount(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    uint64_t count = 0u;

    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM certs WHERE status = 1", -1, &stmt, nullptr) != SQLITE_OK) {
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

uint64_t statFileSize(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        throw std::runtime_error(std::string("stat failed: ") + std::strerror(errno));
    }
    return static_cast<uint64_t>(st.st_size);
}

void testActiveCountQuery() {
    SqliteDb sdb;
    insertCert(sdb.db, 1, kCertStatusValid);
    insertCert(sdb.db, 2, 0);
    insertCert(sdb.db, 3, kCertStatusValid);
    insertCert(sdb.db, 4, 2);
    testOk(queryActiveCount(sdb.db) == 2u, "SELECT COUNT(*) WHERE status=1 returns active cert count");
}

void testCcrTimingTrackerAverage() {
    CcrTimingTracker tracker;
    testOk(tracker.averageMs() == 0.0, "empty CCR timing tracker average is 0.0 ms");
    tracker.record(10.0);
    tracker.record(20.0);
    tracker.record(30.0);
    testOk(tracker.averageMs() == 20.0, "CCR timing tracker computes rolling average");
}

void testAtomicCounters() {
    std::atomic<uint64_t> created{0u};
    std::atomic<uint64_t> revoked{0u};

    created.fetch_add(1u);
    created.fetch_add(1u);
    revoked.fetch_add(1u);

    testOk(created.load() == 2u, "certs_created counter increments monotonically");
    testOk(revoked.load() == 1u, "certs_revoked counter increments monotonically");
}

void testDbSizeStat() {
    TempFile db_file(37u);
    testOk(statFileSize(db_file.path) == 37u, "stat() reports expected db_size_bytes for temp file");
}

}  // namespace

MAIN(testoperationalmetrics) {
    testPlan(6);
    testActiveCountQuery();
    testCcrTimingTrackerAverage();
    testAtomicCounters();
    testDbSizeStat();
    return testDone();
}
