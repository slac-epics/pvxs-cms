/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERT_SUBJECT_UNITS_H
#define PVXS_CERT_SUBJECT_UNITS_H

#include <cstdint>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace pvxs {
namespace certs {

// A certificate subject may name several organizational units, read innermost first, so one row
// per unit. `position` is the depth in the ancestry, counting from the innermost unit at zero,
// and it is the whole of the meaning: order says which unit encloses which.
//
// `certs.OU` is kept and holds the innermost value, so the existing index, the existing queries
// and anything reading the table directly keep working. It is derived and never authoritative:
// every subject comparison reads this table.
//
// Created on every start, not inside the statement that makes `certs`, because that one only
// runs when `certs` is absent and so never reaches a database made by an earlier version. The
// migration travels with it in one transaction: a table that existed but had not been filled in
// would make every certificate look as though it named no unit at all. A certificate that
// already has units is left alone.
#define SQL_CREATE_SUBJECT_UNITS_TABLE                                         \
    "BEGIN TRANSACTION; "                                                      \
    "CREATE TABLE IF NOT EXISTS cert_subject_units("                           \
    "     serial INTEGER NOT NULL REFERENCES certs(serial) ON DELETE CASCADE," \
    "     position INTEGER NOT NULL,"                                          \
    "     value TEXT NOT NULL"                                                 \
    "); "                                                                      \
    "CREATE INDEX IF NOT EXISTS idx_cert_subject_units_value "                 \
    "     ON cert_subject_units(value); "                                      \
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_subject_units_serial_position " \
    "     ON cert_subject_units(serial, position); "                           \
    "INSERT INTO cert_subject_units (serial, position, value) "                \
    "SELECT serial, 0, OU FROM certs "                                         \
    "WHERE OU IS NOT NULL "                                                    \
    "  AND OU != '' "                                                          \
    "  AND NOT EXISTS (SELECT 1 FROM cert_subject_units u WHERE u.serial = certs.serial); " \
    "COMMIT;"

#define SQL_CREATE_SUBJECT_UNIT         \
    "INSERT INTO cert_subject_units ( " \
    "     serial,"                      \
    "     position,"                    \
    "     value"                        \
    ") "                                \
    "VALUES ("                          \
    "     :serial,"                     \
    "     :position,"                   \
    "     :value"                       \
    ")"

#define SQL_GET_SUBJECT_UNITS  \
    "SELECT value "            \
    "FROM cert_subject_units " \
    "WHERE serial = :serial "  \
    "ORDER BY position ASC"

/**
 * @brief Generate the SQL that compares a candidate's organizational units against a request's.
 *
 * Two subjects are the same identity only when they carry the same number of organizational
 * units and the units are equal one by one at every position. A different order is a different
 * identity, because order is containment: `OU=staff,OU=beamline` says staff sits inside beamline
 * and the reverse says the opposite. A shorter path is a different identity too, which is why
 * the count is compared and not just the values present.
 *
 * This is an identity test, not the containment test access control asks. An access rule naming
 * the beamline matches a connection presenting staff-inside-beamline; a request naming the
 * beamline alone is not a duplicate of a certificate for staff-inside-beamline.
 *
 * @param units the organizational units being asked about, innermost first
 * @return a SQL fragment beginning with AND, to append inside a WHERE clause on `certs`
 */
std::string getOrganizationalUnitsClause(const std::vector<std::string> &units);

/**
 * @brief Bind the values that getOrganizationalUnitsClause's fragment expects.
 *
 * @param sql_statement the statement the fragment was prepared into
 * @param units the organizational units being asked about, innermost first
 */
void bindOrganizationalUnitsClause(sqlite3_stmt *sql_statement, const std::vector<std::string> &units);

/**
 * @brief Write one row per organizational unit against a certificate that has just been inserted.
 *
 * Must be called inside the transaction that wrote the certificate row, so a failure part way
 * through leaves neither the certificate nor any of its units.
 *
 * @param certs_db the database
 * @param db_serial the serial of the certificate row just written
 * @param units the organizational units, innermost first
 * @throws std::runtime_error if a row cannot be written
 */
void storeSubjectUnits(sqlite3 *certs_db, int64_t db_serial, const std::vector<std::string> &units);

/**
 * @brief Read a certificate's organizational units back out of the database, innermost first.
 *
 * @param certs_db the database
 * @param db_serial the serial of the certificate
 * @return the organizational units, innermost first
 * @throws std::runtime_error if the read cannot be prepared
 */
std::vector<std::string> getSubjectUnits(sqlite3 *certs_db, int64_t db_serial);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERT_SUBJECT_UNITS_H
