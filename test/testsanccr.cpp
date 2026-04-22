/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cctype>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <sqlite3.h>

#include <epicsUnitTest.h>
#include <testMain.h>

namespace {

struct SanEntry {
    std::string type;
    std::string value;
};

static void validateSanEntries(const std::vector<SanEntry> &entries) {
    const auto isValidDnsLabel = [](const std::string &label) {
        if (label.empty() || label.size() > 63u)
            return false;
        if (label.front() == '-' || label.back() == '-')
            return false;
        for (const auto ch : label) {
            if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '-')
                return false;
        }
        return true;
    };

    for (const auto &entry : entries) {
        if (entry.type == "ip") {
            unsigned char buf4[4];
            unsigned char buf6[16];
            if (inet_pton(AF_INET, entry.value.c_str(), buf4) != 1
                && inet_pton(AF_INET6, entry.value.c_str(), buf6) != 1) {
                throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
            }
        } else if (entry.type == "dns") {
            if (entry.value.empty() || entry.value.size() > 253u)
                throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
            size_t pos = 0u;
            while (pos < entry.value.size()) {
                const auto end = entry.value.find('.', pos);
                const auto label = entry.value.substr(pos,
                                                      end == std::string::npos ? std::string::npos : end - pos);
                if (!isValidDnsLabel(label))
                    throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
                if (end == std::string::npos)
                    break;
                pos = end + 1u;
            }
        } else if (entry.type == "hostname") {
            if (!isValidDnsLabel(entry.value) || entry.value.find('.') != std::string::npos) {
                throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
            }
        } else {
            throw std::runtime_error("Unknown SAN type: " + entry.type);
        }
    }
}

static std::string escapeJsonString(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (const auto ch : s) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out += ch;
            break;
        }
    }
    return out;
}

static std::string unescapeJsonString(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    bool esc = false;
    for (const auto ch : s) {
        if (esc) {
            switch (ch) {
            case '"':
                out += '"';
                break;
            case '\\':
                out += '\\';
                break;
            case 'n':
                out += '\n';
                break;
            case 'r':
                out += '\r';
                break;
            case 't':
                out += '\t';
                break;
            default:
                out += '\\';
                out += ch;
                break;
            }
            esc = false;
        } else if (ch == '\\') {
            esc = true;
        } else {
            out += ch;
        }
    }
    return out;
}

static std::string sanToJson(const std::vector<SanEntry> &entries) {
    if (entries.empty())
        return std::string();

    std::string json("[");
    for (size_t i = 0; i < entries.size(); i++) {
        if (i)
            json += ',';
        json += "{\"type\":\"";
        json += escapeJsonString(entries[i].type);
        json += "\",\"value\":\"";
        json += escapeJsonString(entries[i].value);
        json += "\"}";
    }
    json += ']';
    return json;
}

static std::vector<SanEntry> sanFromJson(const std::string &json) {
    std::vector<SanEntry> entries;
    if (json.empty())
        return entries;

    static const std::string kTypePattern("{\"type\":\"");
    static const std::string kValuePattern("\",\"value\":\"");
    static const std::string kEndPattern("\"}");

    size_t pos = 0u;
    while ((pos = json.find(kTypePattern, pos)) != std::string::npos) {
        pos += kTypePattern.size();
        const auto valuePos = json.find(kValuePattern, pos);
        if (valuePos == std::string::npos)
            break;
        const auto endPos = json.find(kEndPattern, valuePos + kValuePattern.size());
        if (endPos == std::string::npos)
            break;

        SanEntry entry;
        entry.type = unescapeJsonString(json.substr(pos, valuePos - pos));
        entry.value = unescapeJsonString(json.substr(valuePos + kValuePattern.size(),
                                                     endPos - (valuePos + kValuePattern.size())));
        entries.push_back(entry);
        pos = endPos + kEndPattern.size();
    }
    return entries;
}

static const char SQL_CREATE_CERTS[] =
    "CREATE TABLE certs("
    "     serial INTEGER PRIMARY KEY,"
    "     skid TEXT, CN TEXT, O TEXT, OU TEXT, C TEXT,"
    "     san TEXT,"
    "     approved INTEGER, not_before INTEGER, not_after INTEGER,"
    "     renew_by INTEGER, renewal_due INTEGER, status INTEGER, status_date INTEGER"
    ")";

static const char SQL_INSERT_CERT_WITH_SAN[] =
    "INSERT INTO certs(serial, skid, CN, O, OU, C, san, approved, not_before, not_after, renew_by, renewal_due, status, status_date) "
    "VALUES(:serial, '', :CN, '', '', '', :san, 0, 0, 0, 0, 0, 1, 0)";

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
    }

    ~SqliteDb() {
        if (db)
            sqlite3_close(db);
    }

    SqliteDb(const SqliteDb &) = delete;
    SqliteDb &operator=(const SqliteDb &) = delete;
};

static void insertCertWithSan(sqlite3 *db, int64_t serial, const std::string &cn, const std::string &sanJson) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_CERT_WITH_SAN, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), serial);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":CN"), cn.c_str(), -1, SQLITE_TRANSIENT);
    if (sanJson.empty()) {
        sqlite3_bind_null(stmt, sqlite3_bind_parameter_index(stmt, ":san"));
    } else {
        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":san"), sanJson.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string("insert failed: ") + sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

static std::string loadSanFromDb(sqlite3 *db, int64_t serial) {
    sqlite3_stmt *stmt = nullptr;
    std::string result;
    if (sqlite3_prepare_v2(db, "SELECT san FROM certs WHERE serial = :serial", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), serial);
        if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            result = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        }
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return result;
}

static bool threw(void (*fn)()) {
    try {
        fn();
        return false;
    } catch (const std::runtime_error &) {
        return true;
    }
}

static SanEntry parseSanAssignment(const std::string &text) {
    const auto eq = text.find('=');
    if (eq == std::string::npos || eq == 0u || eq + 1u >= text.size()) {
        throw std::runtime_error("Invalid SAN assignment: " + text);
    }
    SanEntry entry;
    entry.type = text.substr(0u, eq);
    entry.value = text.substr(eq + 1u);
    return entry;
}

static std::vector<SanEntry> parseSanList(const std::string &text) {
    std::vector<SanEntry> entries;
    size_t pos = 0u;
    while (pos < text.size()) {
        const auto comma = text.find(',', pos);
        const auto token = text.substr(pos,
                                       comma == std::string::npos ? std::string::npos : comma - pos);
        entries.push_back(parseSanAssignment(token));
        if (comma == std::string::npos)
            break;
        pos = comma + 1u;
    }
    return entries;
}

static std::string buildSanPayload(const std::vector<SanEntry> &entries) {
    std::string payload;
    for (const auto &entry : entries) {
        payload += entry.type;
        payload += '=';
        payload += entry.value;
        payload += ';';
    }
    return payload;
}

void testSchemaMigrationSanColumn() {
    testDiag("12.26 - Schema migration: san column");

    SqliteDb db;
    insertCertWithSan(db.db, 1001, "test-cn", "[{\"type\":\"ip\",\"value\":\"10.0.0.1\"}]");
    const auto san = loadSanFromDb(db.db, 1001);
    testOk(!san.empty(), "san column exists and holds data");

    insertCertWithSan(db.db, 1002, "test-cn2", "");
    const auto san2 = loadSanFromDb(db.db, 1002);
    testOk(san2.empty(), "san column accepts NULL");
}

void testJsonRoundTrip() {
    testDiag("12.32 - JSON serialization/deserialization round-trip");

    std::vector<SanEntry> entries;
    entries.push_back({"ip", "10.0.0.1"});
    entries.push_back({"dns", "host.example.com"});
    entries.push_back({"hostname", "myioc"});

    const auto json = sanToJson(entries);
    testOk(!json.empty(), "sanToJson produces non-empty string");

    const auto parsed = sanFromJson(json);
    testOk(parsed.size() == 3u, "round-trip preserves count");
    testOk(parsed.size() > 0u && parsed[0].type == "ip" && parsed[0].value == "10.0.0.1",
           "round-trip preserves ip entry");
    testOk(parsed.size() > 1u && parsed[1].type == "dns" && parsed[1].value == "host.example.com",
           "round-trip preserves dns entry");
    testOk(parsed.size() > 2u && parsed[2].type == "hostname" && parsed[2].value == "myioc",
           "round-trip preserves hostname entry");

    const auto empty = sanFromJson("");
    testOk(empty.empty(), "sanFromJson empty input returns empty vector");

    const std::vector<SanEntry> none;
    testOk(sanToJson(none).empty(), "sanToJson empty input returns empty string");
}

void testValidationRejectsInvalidEntries() {
    testDiag("12.28 - Validation: invalid SAN entries rejected");

    const auto badIp = []() {
        const std::vector<SanEntry> entries{{"ip", "not-an-ip"}};
        validateSanEntries(entries);
    };
    testOk(threw(badIp), "bad IP rejected");

    const auto badDns = []() {
        const std::vector<SanEntry> entries{{"dns", "-invalid.example.com"}};
        validateSanEntries(entries);
    };
    testOk(threw(badDns), "malformed DNS rejected");

    const auto badType = []() {
        const std::vector<SanEntry> entries{{"email", "user@example.com"}};
        validateSanEntries(entries);
    };
    testOk(threw(badType), "unknown SAN type rejected");

    const auto hostDot = []() {
        const std::vector<SanEntry> entries{{"hostname", "host.example.com"}};
        validateSanEntries(entries);
    };
    testOk(threw(hostDot), "hostname with dots rejected");
}

void testValidationAcceptsValidEntries() {
    testDiag("12.27 - Validation: valid SAN entries accepted");

    const std::vector<SanEntry> valid{{"ip", "10.0.0.1"},
                                      {"ip", "::1"},
                                      {"dns", "host.example.com"},
                                      {"hostname", "myioc"}};

    bool ok = true;
    try {
        validateSanEntries(valid);
    } catch (...) {
        ok = false;
    }
    testOk(ok, "valid SAN entries accepted");
}

void testNoSanCreatesNullColumn() {
    testDiag("12.29 - No SAN creates NULL san column");

    SqliteDb db;
    insertCertWithSan(db.db, 2001, "no-san-cn", "");
    const auto san = loadSanFromDb(db.db, 2001);
    testOk(san.empty(), "no SAN yields empty string from DB NULL");
}

void testMissingSanFieldHandledGracefully() {
    testDiag("12.30 - Missing san field handled gracefully");

    SqliteDb db;
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db.db,
                       "INSERT INTO certs(serial,skid,CN,O,OU,C,approved,not_before,not_after,renew_by,renewal_due,status,status_date) VALUES(3001,'','old-cn','','','',0,0,0,0,0,1,0)",
                       -1, &stmt, nullptr);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const auto san = loadSanFromDb(db.db, 3001);
    testOk(san.empty(), "cert inserted without san column value yields NULL");
}

void testSanBasedSearch() {
    testDiag("12.31 - SAN-based search");

    SqliteDb db;
    insertCertWithSan(db.db, 4001, "cert-a", sanToJson(std::vector<SanEntry>{{"ip", "10.0.0.1"}, {"dns", "a.example.com"}}));
    insertCertWithSan(db.db, 4002, "cert-b", sanToJson(std::vector<SanEntry>{{"ip", "192.168.1.1"}}));
    insertCertWithSan(db.db, 4003, "cert-c", "");

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db.db, "SELECT serial FROM certs WHERE san LIKE :pattern", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, "%\"10.0.0.1\"%", -1, SQLITE_STATIC);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
        count++;
    sqlite3_finalize(stmt);

    testOk(count == 1, "SAN search for 10.0.0.1 finds 1 cert");
}

void testEnvVarParsing() {
    testDiag("12.34 - SAN env var parsing");

    const auto entries = parseSanList("ip=10.0.0.1,dns=host.example.com");
    testOk(entries.size() == 2u
           && entries[0].type == "ip"
           && entries[0].value == "10.0.0.1"
           && entries[1].type == "dns"
           && entries[1].value == "host.example.com",
           "env var parsing produces correct entries");
}

void testCliFlagParsing() {
    testDiag("12.33 - CLI flag parsing");

    const auto entry = parseSanAssignment("ip=10.0.0.1");
    testOk(entry.type == "ip" && entry.value == "10.0.0.1", "CLI flag parses correctly");

    const std::vector<std::string> flags{"ip=10.0.0.1", "dns=host.example.com", "hostname=myioc"};
    std::vector<SanEntry> entries;
    for (const auto &flag : flags) {
        entries.push_back(parseSanAssignment(flag));
    }
    testOk(entries.size() == 3u
           && entries[0].type == "ip"
           && entries[1].type == "dns"
           && entries[2].type == "hostname"
           && entries[2].value == "myioc",
           "multiple CLI flags parse correctly");
}

void testSanSignaturePayload() {
    testDiag("12.35 - SAN in signature payload");

    std::vector<SanEntry> entries{{"ip", "10.0.0.1"}, {"dns", "a.example.com"}};
    const auto payload1 = buildSanPayload(entries);
    testOk(!payload1.empty()
           && payload1.find("ip=10.0.0.1;") != std::string::npos
           && payload1.find("dns=a.example.com;") != std::string::npos,
           "SAN payload string includes all type value pairs");

    entries[0].value = "10.0.0.2";
    const auto payload2 = buildSanPayload(entries);
    testOk(payload1 != payload2, "modifying SAN changes payload string");
}

} // namespace

MAIN(testsanccr) {
    testPlan(22);
    testSchemaMigrationSanColumn();
    testJsonRoundTrip();
    testValidationRejectsInvalidEntries();
    testValidationAcceptsValidEntries();
    testNoSanCreatesNullColumn();
    testMissingSanFieldHandledGracefully();
    testSanBasedSearch();
    testEnvVarParsing();
    testCliFlagParsing();
    testSanSignaturePayload();
    return testDone();
}
