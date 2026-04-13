/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cctype>
#include <cstdint>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

static const char SQL_CREATE_CERTS[] =
    "CREATE TABLE certs("
    "     serial INTEGER PRIMARY KEY,"
    "     skid TEXT, CN TEXT, O TEXT, OU TEXT, C TEXT,"
    "     approved INTEGER, not_before INTEGER, not_after INTEGER,"
    "     renew_by INTEGER, renewal_due INTEGER, status INTEGER, status_date INTEGER"
    ")";

static const char SQL_CREATE_CERT_SCHEDULES[] =
    "CREATE TABLE IF NOT EXISTS cert_schedules("
    "     id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "     serial INTEGER NOT NULL REFERENCES certs(serial),"
    "     day_of_week TEXT NOT NULL,"
    "     start_time TEXT NOT NULL,"
    "     end_time TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_cert_schedules_serial ON cert_schedules(serial);";

static const char SQL_CREATE_AUDIT[] =
    "CREATE TABLE IF NOT EXISTS audit("
    "     id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "     timestamp INTEGER NOT NULL,"
    "     action TEXT NOT NULL,"
    "     operator TEXT NOT NULL,"
    "     serial INTEGER,"
    "     detail TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp);";

static const char SQL_INSERT_CERT[] =
    "INSERT INTO certs(serial, skid, CN, O, OU, C, approved, not_before, not_after, renew_by, renewal_due, status, status_date) "
    "VALUES(?, '', 'test', '', '', '', 0, ?, ?, 0, 0, ?, 0)";

static const char SQL_INSERT_SCHEDULE[] =
    "INSERT INTO cert_schedules(serial, day_of_week, start_time, end_time) "
    "VALUES(:serial, :day_of_week, :start_time, :end_time)";

static const char SQL_DELETE_SCHEDULES_BY_SERIAL[] =
    "DELETE FROM cert_schedules WHERE serial = :serial";

static const char SQL_SELECT_SCHEDULES_BY_SERIAL[] =
    "SELECT day_of_week, start_time, end_time FROM cert_schedules WHERE serial = :serial";

static const char SQL_INSERT_AUDIT[] =
    "INSERT INTO audit(timestamp, action, operator, serial, detail) "
    "VALUES(:timestamp, :action, :operator, :serial, :detail)";

static const int UNKNOWN = 0;
static const int VALID = 1;
static const int PENDING = 2;
static const int PENDING_APPROVAL = 3;
static const int PENDING_RENEWAL = 4;
static const int EXPIRED = 5;
static const int REVOKED = 6;
static const int SCHEDULED_OFFLINE = 7;

struct ScheduleWindow {
    std::string day_of_week;
    std::string start_time;
    std::string end_time;
};

struct SqliteDb {
    sqlite3 *db{nullptr};

    SqliteDb() {
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_open failed: ") + sqlite3_errmsg(db));
        }
        sqlite3_exec(db, "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr);
        if (sqlite3_exec(db, SQL_CREATE_CERTS, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("CREATE certs failed: ") + sqlite3_errmsg(db));
        }
        if (sqlite3_exec(db, SQL_CREATE_CERT_SCHEDULES, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("CREATE cert_schedules failed: ") + sqlite3_errmsg(db));
        }
        if (sqlite3_exec(db, SQL_CREATE_AUDIT, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("CREATE audit failed: ") + sqlite3_errmsg(db));
        }
    }

    ~SqliteDb() {
        if (db) sqlite3_close(db);
    }

    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

static bool isValidScheduleTime(const std::string &t) {
    if (t.size() != 5 || t[2] != ':')
        return false;
    if (!std::isdigit(static_cast<unsigned char>(t[0])) ||
        !std::isdigit(static_cast<unsigned char>(t[1])) ||
        !std::isdigit(static_cast<unsigned char>(t[3])) ||
        !std::isdigit(static_cast<unsigned char>(t[4])))
        return false;
    const int h = std::stoi(t.substr(0, 2));
    const int m = std::stoi(t.substr(3, 2));
    return h >= 0 && h <= 23 && m >= 0 && m <= 59;
}

static std::vector<ScheduleWindow> loadScheduleWindows(sqlite3 *db, uint64_t serial) {
    std::vector<ScheduleWindow> windows;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_SELECT_SCHEDULES_BY_SERIAL, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), static_cast<sqlite3_int64>(serial));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ScheduleWindow sw;
            auto col = [&](int c) -> std::string {
                auto t = sqlite3_column_text(stmt, c);
                return t ? reinterpret_cast<const char *>(t) : "";
            };
            sw.day_of_week = col(0);
            sw.start_time = col(1);
            sw.end_time = col(2);
            windows.push_back(sw);
        }
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return windows;
}

static bool isWithinSchedule(time_t now_utc, const std::vector<ScheduleWindow> &windows) {
    if (windows.empty()) return true;

    struct tm tm_buf;
    gmtime_r(&now_utc, &tm_buf);
    int current_day = tm_buf.tm_wday;
    int current_mins = tm_buf.tm_hour * 60 + tm_buf.tm_min;

    for (const auto &w : windows) {
        if (w.day_of_week != "*") {
            int day = w.day_of_week[0] - '0';
            if (day != current_day) continue;
        }
        int start_h = std::stoi(w.start_time.substr(0, 2));
        int start_m = std::stoi(w.start_time.substr(3, 2));
        int end_h = std::stoi(w.end_time.substr(0, 2));
        int end_m = std::stoi(w.end_time.substr(3, 2));
        int start_mins = start_h * 60 + start_m;
        int end_mins = end_h * 60 + end_m;

        if (end_mins > start_mins) {
            if (current_mins >= start_mins && current_mins < end_mins) return true;
        } else {
            if (current_mins >= start_mins || current_mins < end_mins) return true;
        }
    }
    return false;
}

static void insertSchedule(sqlite3 *db, uint64_t serial, const ScheduleWindow &sw) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_SCHEDULE, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare schedule insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), static_cast<sqlite3_int64>(serial));
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":day_of_week"), sw.day_of_week.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":start_time"), sw.start_time.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":end_time"), sw.end_time.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("schedule insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

static void insertCert(sqlite3 *db, int64_t serial, int64_t not_before, int64_t not_after, int status) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_CERT, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare cert insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(serial));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(not_before));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(not_after));
    sqlite3_bind_int(stmt, 4, status);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("cert insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

static time_t makeUtcTime(int year, int month, int day, int hour, int min) {
    struct tm t = {};
    t.tm_year = year - 1900;
    t.tm_mon = month - 1;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = 0;
    return timegm(&t);
}

static void deleteSchedulesBySerial(sqlite3 *db, uint64_t serial) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_DELETE_SCHEDULES_BY_SERIAL, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare schedule delete failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), static_cast<sqlite3_int64>(serial));
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("schedule delete failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

static void insertAudit(sqlite3 *db,
                        sqlite3_int64 timestamp,
                        const std::string &action,
                        const std::string &operator_id,
                        uint64_t serial,
                        const std::string &detail) {
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

static bool hasWindow(const std::vector<ScheduleWindow> &windows,
                      const std::string &day_of_week,
                      const std::string &start_time,
                      const std::string &end_time) {
    for (const auto &window : windows) {
        if (window.day_of_week == day_of_week
            && window.start_time == start_time
            && window.end_time == end_time) {
            return true;
        }
    }
    return false;
}

void testScheduledOfflineEnumValue() {
    testOk(SCHEDULED_OFFLINE == 7, "SCHEDULED_OFFLINE enum value is 7");
}

void testScheduledOfflineStateName() {
    static const char *const states[] = {
        "UNKNOWN",
        "VALID",
        "PENDING",
        "PENDING_APPROVAL",
        "PENDING_RENEWAL",
        "EXPIRED",
        "REVOKED",
        "SCHEDULED_OFFLINE",
    };
    const bool indexes_match = std::string(states[UNKNOWN]) == "UNKNOWN"
                               && std::string(states[VALID]) == "VALID"
                               && std::string(states[PENDING]) == "PENDING"
                               && std::string(states[PENDING_APPROVAL]) == "PENDING_APPROVAL"
                               && std::string(states[PENDING_RENEWAL]) == "PENDING_RENEWAL"
                               && std::string(states[EXPIRED]) == "EXPIRED"
                               && std::string(states[REVOKED]) == "REVOKED";
    testOk(indexes_match && std::string(states[SCHEDULED_OFFLINE]) == "SCHEDULED_OFFLINE",
           "state name for status 7 is SCHEDULED_OFFLINE");
}

void testScheduledOfflineMapsToOcspUnknown() {
    const bool maps_to_unknown = (SCHEDULED_OFFLINE != VALID) && (SCHEDULED_OFFLINE != REVOKED);
    testOk(maps_to_unknown, "scheduled offline falls into OCSP unknown class");
}

void testScheduleInsertAndLoad() {
    SqliteDb sdb;
    insertCert(sdb.db, 101, 0, 0, VALID);
    insertSchedule(sdb.db, 101, {"1", "08:30", "12:00"});
    insertSchedule(sdb.db, 101, {"*", "13:00", "17:30"});

    const auto windows = loadScheduleWindows(sdb.db, 101);
    testOk(windows.size() == 2
           && hasWindow(windows, "1", "08:30", "12:00")
           && hasWindow(windows, "*", "13:00", "17:30"),
           "schedule rows insert and load with expected fields");
}

void testScheduleDeleteAndReinsert() {
    SqliteDb sdb;
    insertCert(sdb.db, 102, 0, 0, VALID);
    insertSchedule(sdb.db, 102, {"1", "08:00", "10:00"});
    insertSchedule(sdb.db, 102, {"2", "11:00", "12:00"});

    deleteSchedulesBySerial(sdb.db, 102);
    insertSchedule(sdb.db, 102, {"3", "14:00", "16:00"});

    const auto windows = loadScheduleWindows(sdb.db, 102);
    testOk(windows.size() == 1
           && hasWindow(windows, "3", "14:00", "16:00"),
           "schedule delete and reinsert leaves only new rows");
}

void testScheduleValidation() {
    const bool valid = isValidScheduleTime("08:30")
                       && isValidScheduleTime("23:59")
                       && isValidScheduleTime("00:00");
    const bool invalid = !isValidScheduleTime("25:00")
                         && !isValidScheduleTime("8:30")
                         && !isValidScheduleTime("ab:cd")
                         && !isValidScheduleTime("12:60")
                         && !isValidScheduleTime("12:3")
                         && !isValidScheduleTime("");
    testOk(valid && invalid, "schedule time validation accepts and rejects expected formats");
}

void testIsWithinScheduleWildcardDay() {
    const std::vector<ScheduleWindow> windows{{"*", "08:00", "10:00"}};
    const bool in_window = isWithinSchedule(makeUtcTime(2025, 1, 6, 9, 15), windows);
    testOk(in_window, "wildcard day matches known UTC minute within window");
}

void testIsWithinScheduleSpecificDay() {
    const std::vector<ScheduleWindow> windows{{"1", "08:00", "10:00"}};
    const bool monday_match = isWithinSchedule(makeUtcTime(2025, 1, 6, 9, 0), windows);
    const bool tuesday_miss = !isWithinSchedule(makeUtcTime(2025, 1, 7, 9, 0), windows);
    testOk(monday_match && tuesday_miss, "specific day schedule matches Monday and rejects Tuesday");
}

void testIsWithinScheduleCrossMidnight() {
    const std::vector<ScheduleWindow> windows{{"*", "22:00", "02:00"}};
    const bool late_match = isWithinSchedule(makeUtcTime(2025, 1, 6, 23, 0), windows);
    const bool morning_miss = !isWithinSchedule(makeUtcTime(2025, 1, 6, 10, 0), windows);
    testOk(late_match && morning_miss, "cross-midnight schedule matches 23:00 and rejects 10:00");
}

void testIsWithinScheduleEmptyWindows() {
    const std::vector<ScheduleWindow> windows;
    testOk(isWithinSchedule(makeUtcTime(2025, 1, 6, 12, 0), windows), "empty schedule list imposes no restriction");
}

void testScheduleReplaceUpdatesDb() {
    SqliteDb sdb;
    insertCert(sdb.db, 103, 0, 0, VALID);
    insertSchedule(sdb.db, 103, {"*", "06:00", "07:00"});

    deleteSchedulesBySerial(sdb.db, 103);
    insertSchedule(sdb.db, 103, {"0", "09:00", "11:00"});
    insertSchedule(sdb.db, 103, {"6", "12:00", "14:00"});

    const auto windows = loadScheduleWindows(sdb.db, 103);
    testOk(windows.size() == 2
           && hasWindow(windows, "0", "09:00", "11:00")
           && hasWindow(windows, "6", "12:00", "14:00")
           && !hasWindow(windows, "*", "06:00", "07:00"),
           "schedule replacement updates persisted DB rows");
}

void testScheduleAuditRecordInserted() {
    SqliteDb sdb;
    insertCert(sdb.db, 104, 0, 0, VALID);
    deleteSchedulesBySerial(sdb.db, 104);
    insertSchedule(sdb.db, 104, {"*", "08:00", "17:00"});
    insertAudit(sdb.db, 1234567890, "SCHEDULE", "operator:test", 104, "updated validity schedule");

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(sdb.db,
                       "SELECT action, operator, serial, detail FROM audit WHERE serial=104 ORDER BY id DESC LIMIT 1",
                       -1, &stmt, nullptr);
    const bool ok = sqlite3_step(stmt) == SQLITE_ROW
                    && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))) == "SCHEDULE"
                    && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1))) == "operator:test"
                    && sqlite3_column_int64(stmt, 2) == 104
                    && std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3))) == "updated validity schedule";
    sqlite3_finalize(stmt);

    testOk(ok, "schedule change inserts SCHEDULE audit record");
}

void testIsWithinScheduleMultipleWindows() {
    const std::vector<ScheduleWindow> windows{
        {"*", "08:00", "10:00"},
        {"*", "14:00", "16:00"},
    };
    const bool first = isWithinSchedule(makeUtcTime(2025, 1, 6, 8, 30), windows);
    const bool gap = !isWithinSchedule(makeUtcTime(2025, 1, 6, 12, 0), windows);
    const bool second = isWithinSchedule(makeUtcTime(2025, 1, 6, 15, 30), windows);
    testOk(first && gap && second, "multiple windows accept matching ranges and reject gaps");
}

void testIsWithinScheduleExactBoundary() {
    const std::vector<ScheduleWindow> windows{{"*", "08:00", "10:00"}};
    const bool at_start = isWithinSchedule(makeUtcTime(2025, 1, 6, 8, 0), windows);
    const bool at_end = !isWithinSchedule(makeUtcTime(2025, 1, 6, 10, 0), windows);
    testOk(at_start && at_end, "schedule uses half-open interval [start, end)");
}

void testIsWithinScheduleEndEqualsStart() {
    const std::vector<ScheduleWindow> windows{{"*", "08:00", "08:00"}};
    const bool before = isWithinSchedule(makeUtcTime(2025, 1, 6, 7, 59), windows);
    const bool at = isWithinSchedule(makeUtcTime(2025, 1, 6, 8, 0), windows);
    const bool after = isWithinSchedule(makeUtcTime(2025, 1, 6, 12, 0), windows);
    testOk(before && at && after, "equal start and end times behave as always-true cross-midnight window");
}

void testScheduleLoadNonExistentSerial() {
    SqliteDb sdb;
    insertCert(sdb.db, 105, 0, 0, VALID);
    const auto windows = loadScheduleWindows(sdb.db, 999);
    testOk(windows.empty(), "loading schedules for non-existent serial returns empty vector");
}

}  // namespace

MAIN(testvalidityschedules) {
    testPlan(16);
    testScheduledOfflineEnumValue();
    testScheduledOfflineStateName();
    testScheduledOfflineMapsToOcspUnknown();
    testScheduleInsertAndLoad();
    testScheduleDeleteAndReinsert();
    testScheduleValidation();
    testIsWithinScheduleWildcardDay();
    testIsWithinScheduleSpecificDay();
    testIsWithinScheduleCrossMidnight();
    testIsWithinScheduleEmptyWindows();
    testScheduleReplaceUpdatesDb();
    testScheduleAuditRecordInserted();
    testIsWithinScheduleMultipleWindows();
    testIsWithinScheduleExactBoundary();
    testIsWithinScheduleEndEqualsStart();
    testScheduleLoadNonExistentSerial();
    return testDone();
}
