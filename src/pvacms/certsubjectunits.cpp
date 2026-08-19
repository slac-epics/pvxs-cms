/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certsubjectunits.h"

#include <stdexcept>

#include "sqlitestmt.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

std::string getOrganizationalUnitsClause(const std::vector<std::string> &units) {
    auto clause = SB();
    clause << " AND (SELECT COUNT(*) FROM cert_subject_units WHERE cert_subject_units.serial = certs.serial) = "
           << units.size();
    for (size_t i = 0; i < units.size(); i++) {
        clause << " AND EXISTS (SELECT 1 FROM cert_subject_units"
               << " WHERE cert_subject_units.serial = certs.serial"
               << " AND cert_subject_units.position = " << i
               << " AND cert_subject_units.value = :OU" << i << ")";
    }
    return clause.str();
}

void bindOrganizationalUnitsClause(sqlite3_stmt *sql_statement, const std::vector<std::string> &units) {
    for (size_t i = 0; i < units.size(); i++) {
        sqlite3_bind_text(sql_statement,
                          sqlite3_bind_parameter_index(sql_statement, (SB() << ":OU" << i).str().c_str()),
                          units[i].c_str(),
                          -1,
                          SQLITE_TRANSIENT);
    }
}

void storeSubjectUnits(sqlite3 *certs_db, const int64_t db_serial, const std::vector<std::string> &units) {
    for (size_t position = 0; position < units.size(); position++) {
        SqliteStmt sql_statement;
        if (sqlite3_prepare_v2(certs_db, SQL_CREATE_SUBJECT_UNIT, -1, sql_statement.acquire(), nullptr) != SQLITE_OK) {
            throw std::runtime_error(SB() << "Failed to prepare the organizational unit insert: " << sqlite3_errmsg(certs_db));
        }
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":position"), static_cast<int>(position));
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":value"), units[position].c_str(), -1,
                          SQLITE_TRANSIENT);
        const auto sql_status = sqlite3_step(sql_statement);
        sql_statement.reset();
        if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
            throw std::runtime_error(SB() << "Failed to record organizational unit \"" << units[position]
                                          << "\": " << sqlite3_errmsg(certs_db));
        }
    }
}

std::vector<std::string> getSubjectUnits(sqlite3 *certs_db, const int64_t db_serial) {
    std::vector<std::string> units;
    SqliteStmt sql_statement;
    if (sqlite3_prepare_v2(certs_db, SQL_GET_SUBJECT_UNITS, -1, sql_statement.acquire(), nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to prepare the organizational unit read: " << sqlite3_errmsg(certs_db));
    }
    sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
    while (sqlite3_step(sql_statement) == SQLITE_ROW) {
        if (const auto value = sqlite3_column_text(sql_statement, 0)) units.emplace_back(reinterpret_cast<const char *>(value));
    }
    sql_statement.reset();
    return units;
}

}  // namespace certs
}  // namespace pvxs
