/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The PVAccess Certificate Management Service.
 *
 *   pvacms.h
 *
 */
#ifndef PVXS_PVACMS_H
#define PVXS_PVACMS_H

#include <iostream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/sharedpv.h>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "certsubjectunits.h"
#include "configcms.h"
#include "openssl.h"
#include "ownedptr.h"
#include "wildcardpv.h"

#define SQL_CREATE_DB_FILE              \
    "BEGIN TRANSACTION; "               \
    "CREATE TABLE IF NOT EXISTS certs(" \
    "     serial INTEGER PRIMARY KEY,"  \
    "     skid TEXT,"                   \
    "     CN TEXT,"                     \
    "     O TEXT,"                      \
    "     OU TEXT,"                     \
    "     C TEXT,"                      \
    "     approved INTEGER,"            \
    "     not_before INTEGER,"          \
    "     not_after INTEGER,"           \
    "     renew_by INTEGER,"            \
    "     renewal_due INTEGER,"         \
    "     status INTEGER,"              \
    "     status_date INTEGER,"         \
    "     created_date INTEGER,"        \
    "     key_usage TEXT,"              \
    "     extended_key_usage TEXT"      \
    "); "                               \
    "CREATE INDEX IF NOT EXISTS idx_certs_skid " \
    "     ON certs(skid); "            \
    "CREATE INDEX IF NOT EXISTS idx_certs_status " \
    "     ON certs(status); "          \
    "CREATE INDEX IF NOT EXISTS idx_certs_identity " \
    "     ON certs(CN, O, OU, C, status, not_before); "     \
    "CREATE INDEX IF NOT EXISTS idx_certs_not_after_skid " \
    "     ON certs(not_after, skid); " \
    "CREATE INDEX IF NOT EXISTS idx_certs_validity " \
    "     ON certs(not_before, not_after) ; " \
    "COMMIT;"

// Columns present on the certificate table, so a database created before a column
// existed can be brought forward. The create statement only runs when the table is
// absent, so it never reaches an existing database.
#define SQL_CERTS_TABLE_COLUMNS       \
    "PRAGMA table_info(certs);"

#define SQL_ADD_CREATED_DATE          \
    "ALTER TABLE certs ADD COLUMN created_date INTEGER;"

#define SQL_ADD_KEY_USAGE             \
    "ALTER TABLE certs ADD COLUMN key_usage TEXT;"

#define SQL_ADD_EXTENDED_KEY_USAGE    \
    "ALTER TABLE certs ADD COLUMN extended_key_usage TEXT;"

// Rows written before the creation time existed cannot have one recovered. The start
// of validity is the closest thing the row holds and is used as an approximation.
#define SQL_BACKFILL_CREATED_DATE     \
    "UPDATE certs SET created_date = not_before WHERE created_date IS NULL;"

#define SQL_CHECK_EXISTS_DB_FILE       \
    "SELECT name "                     \
    "FROM sqlite_master "              \
    "WHERE type='table' "              \
    "  AND name='certs';"

#define SQL_CREATE_CERT               \
    "INSERT INTO certs ( "            \
    "     serial,"                    \
    "     skid,"                      \
    "     CN,"                        \
    "     O,"                         \
    "     OU,"                        \
    "     C,"                         \
    "     approved,"                  \
    "     not_before,"                \
    "     not_after,"                 \
    "     renew_by,"                  \
    "     renewal_due,"               \
    "     status,"                    \
    "     status_date,"               \
    "     created_date,"              \
    "     key_usage,"                 \
    "     extended_key_usage"         \
    ") "                              \
    "VALUES ("                        \
    "     :serial,"                   \
    "     :skid,"                     \
    "     :CN,"                       \
    "     :O,"                        \
    "     :OU,"                       \
    "     :C,"                        \
    "     :approved,"                 \
    "     :not_before,"               \
    "     :not_after,"                \
    "     :renew_by,"                 \
    "     0,"                         \
    "     :status,"                   \
    "     :status_date,"              \
    "     :created_date,"             \
    "     :key_usage,"                \
    "     :extended_key_usage"        \
    ")"

// The organizational units are not compared here. They are an ordered list of any length, so the
// test is appended by getOrganizationalUnitsClause: a count of the candidate's units followed by
// one positional equality test per requested value. `certs.OU` is deliberately left out of the
// comparison even though it would narrow the search, because it is derived from the child table
// and matching on both would make the answer depend on the two never drifting apart.
#define SQL_DUPS_SUBJECT              \
    "SELECT COUNT(*) "                \
    "FROM certs "                     \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND C = :C "

#define SQL_DUPS_SUBJECT_KEY_IDENTIFIER \
    "SELECT COUNT(*) "                  \
    "FROM certs "                       \
    "WHERE skid = :skid "

// Get the certificate due to be renewed
#define SQL_GET_RENEWED_CERT          \
    "SELECT serial"                   \
    "     , not_after "               \
    "     , renew_by "                \
    "     , status "                  \
    "FROM certs "                     \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND C = :C "                   \
    "  AND status IN (:status0, :status1, :status2, :status3) " \
    "  AND serial != :serial "        \
    "  AND renewal_due != 0 "

// Appended after the organizational unit comparison, which must sit inside the WHERE clause
#define SQL_GET_RENEWED_CERT_TAIL     \
    " LIMIT 1 "

#define SQL_TOUCH_CERT_STATUS         \
    "UPDATE certs "                   \
    "SET status_date = :status_date " \
    "WHERE serial = :serial "

#define SQL_RENEW_CERTS               \
    "UPDATE certs "                   \
    "SET status = :status "           \
    "  , status_date = :status_date " \
    "  , renew_by = :renew_by "       \
    "  , renewal_due = 0 " \
    "WHERE serial = :serial "

#define SQL_FLAG_RENEW_CERTS          \
    "UPDATE certs "                   \
    "SET status_date = :status_date " \
    "  , renewal_due = 1 " \
    "WHERE serial = :serial "

#define SQL_CERT_STATUS               \
    "SELECT status "                  \
    "     , status_date "             \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_SKID_BY_SERIAL       \
    "SELECT skid "                    \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_IS_NODE_REVOKED      \
    "SELECT 1 "                       \
    "FROM certs "                     \
    "WHERE skid LIKE :skid_prefix "   \
    "  AND status = :revoked "        \
    "LIMIT 1"

#define SQL_CERT_VALIDITY             \
    "SELECT not_before "              \
    "     , not_after "               \
    "     , renew_by "                \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_SET_STATUS           \
    "UPDATE certs "                   \
    "SET status = :status "           \
    "  , status_date = :status_date " \
    "  , renewal_due = 0 "            \
    "WHERE serial = :serial "

#define SQL_CERT_SET_STATUS_W_APPROVAL \
    "UPDATE certs "                    \
    "SET status = :status "            \
    "  , approved = :approved "        \
    "  , status_date = :status_date "  \
    "  , renewal_due = 0 "            \
    "WHERE serial = :serial "

#define SQL_CERT_TO_VALID              \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_before <= :now "        \
    "  AND not_after > :now "          \
    "  AND (renew_by = 0 OR renew_by > :now) "

#define SQL_CERT_TO_EXPIRED            \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_after <= :now "

#define SQL_CERT_TO_EXPIRED_WITH_FULL_SKID \
    "SELECT serial "                       \
    "FROM certs "                          \
    "WHERE not_after <= :now "             \
    "  AND skid = :skid "

#define SQL_CERT_TO_PENDING_RENEWAL \
    "SELECT serial "                \
    "FROM certs "                   \
    "WHERE not_before <= :now "     \
    "  AND not_after > :now "       \
    "  AND renew_by != 0 "          \
    "  AND renew_by <= :now "

#define SQL_CERT_STATUS_NEARLY_INVALID \
    "SELECT serial, status "        \
    "FROM certs "                   \
    "WHERE not_before <= :now "     \
    "  AND not_after > :now "       \
    "  AND 2 * (:now - status_date) >= :status_validity "

#define SQL_CERT_NEARING_RENEWAL   \
    "SELECT serial "               \
    "FROM certs "                  \
    "WHERE renewal_due = 0 "       \
    "  AND not_before <= :now "    \
    "  AND not_after > :now "      \
    "  AND renew_by != 0 "         \
    "  AND 2 * :now >= status_date + renew_by "

#define SQL_PRIOR_APPROVAL_STATUS \
    "SELECT approved "            \
    "FROM certs "                 \
    "WHERE CN = :CN "             \
    "  AND O = :O "               \
    "  AND C = :C "

// Appended after the organizational unit comparison, which must sit inside the WHERE clause
#define SQL_PRIOR_APPROVAL_STATUS_TAIL \
    " ORDER BY status_date DESC LIMIT 1 "

namespace pvxs {
namespace certs {

/**
 * @brief Monitors the certificate status and updates the shared wildcard status pv when any become valid or expire.
 *
 * This function monitors the certificate status by connecting to the Certificate database, and searching
 * for all certificates that have just expired and all certificates that have just become valid.  If any
 * are found then the associated shared wildcard PV is updated and the new status stored in the database.
 *
 * @param certs_db The certificates-database object.
 * @param issuer_id The issuer ID.
 * @param status_pv The shared wildcard PV to notify.
 *
 * @note This function assumes that the certificate database and the status PV have been properly configured and initialized.
 * @note The status_pv parameter must be a valid WildcardPV object.
 */
class StatusMonitor {
   public:
    ConfigCms &config_;
    sql_ptr &certs_db_;
    std::string &issuer_id_;
    server::WildcardPV &status_pv_;
    ossl_ptr<X509> &cert_auth_cert_;
    ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    pvxs::ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain_;

    StatusMonitor(ConfigCms &config, sql_ptr &certs_db, std::string &issuer_id, server::WildcardPV &status_pv, ossl_ptr<X509> &cert_auth_cert,
                  ossl_ptr<EVP_PKEY> &cert_auth_pkey, ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain)
        : config_(config),
          certs_db_(certs_db),
          issuer_id_(issuer_id),
          status_pv_(status_pv),
          cert_auth_cert_(cert_auth_cert),
          cert_auth_pkey_(cert_auth_pkey),
          cert_auth_cert_chain_(cert_auth_chain) {}
};

void checkForDuplicates(const sql_ptr &certs_db, const CertFactory &cert_factory);

CertData createCertAuthCertificate(const ConfigCms &config, sql_ptr &certs_db, const std::shared_ptr<KeyPair> &key_pair);

ossl_ptr<X509> createCertificate(sql_ptr &certs_db, CertFactory &cert_factory);

std::string createCertificatePemString(sql_ptr &certs_db, CertFactory &cert_factory);

void createServerCertificate(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, const std::shared_ptr<KeyPair> &key_pair);

void ensureServerCertificateExists(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain);

void ensureValidityCompatible(const CertFactory &cert_factory);

uint64_t generateSerial();

std::tuple<certstatus_t, time_t> getCertificateStatus(const sql_ptr &certs_db, uint64_t serial);
void getWorstCertificateStatus(const sql_ptr &certs_db, uint64_t serial, certstatus_t &worst_status_so_far, time_t &worst_status_time_so_far);
DbCert getCertificateValidity(const sql_ptr &certs_db, uint64_t serial);
std::string getCertificateSkid(const sql_ptr &certs_db, uint64_t serial);
bool isNodeCertRevoked(const sql_ptr &certs_db, const std::string &node_id);

std::string extractCountryCode(const std::string &locale_str);

std::string getCountryCode();

/**
 * @brief Build the reply to a certificate creation request.
 * @param response_fields members an authenticator wants added, under `authenticator`.
 *        Empty leaves the reply exactly as it was before authenticators could add to it.
 */
Value getCreatePrototype(const std::vector<pvxs::Member> &response_fields = {});

time_t getNotAfterTimeFromCert(const X509 *cert);

time_t getNotBeforeTimeFromCert(const X509 *cert);

void getOrCreateCertAuthCertificate(const ConfigCms &config, sql_ptr &certs_db, ossl_ptr<X509> &cert_auth_cert, ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, ossl_ptr<X509> &cert_auth_root_cert, bool &is_initialising);

std::vector<std::string> getCertPaths(const CertData &cert_data);
std::string toACFAuth(const std::string &id, const CertData &cert_data);
std::string toACFYamlAuth(const std::string &id, const CertData &cert_data);

void createDefaultAdminACF(const ConfigCms &config, const CertData &cert_data);

void createAdminClientCert(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert,
                           const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain, const std::string &admin_name = "admin");

void initCertsDatabase(sql_ptr &certs_db, const std::string &db_file);

int64_t onCreateCertificate(ConfigCms &config, sql_ptr &certs_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args,
                         const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                         const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, std::string issuer_id);

bool getPriorApprovalStatus(const sql_ptr &certs_db, const std::string &name, const std::string &country, const std::string &organization,
                            const std::vector<std::string> &organizational_units);

void onGetStatus(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
                 const std::string &pv_name, serial_number_t serial, const std::string &issuer_id, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                 const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

void onRevoke(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
              std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
              const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

void onApprove(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
               std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
               const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

void onDeny(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
            std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
            const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

int readOptions(ConfigCms &config, int argc, char *argv[], bool &verbose);

void updateCertificateStatus(const sql_ptr &certs_db, uint64_t serial, certstatus_t cert_status, int approval_status,
                             const std::vector<certstatus_t> &valid_status = {PENDING_APPROVAL, PENDING, VALID});

void updateCertificateRenewalStatus(const sql_ptr &certs_db, serial_number_t serial, certstatus_t cert_status, time_t renew_by);

void touchCertificateStatus(const sql_ptr &certs_db, serial_number_t serial);

certstatus_t storeCertificate(const sql_ptr &certs_db, CertFactory &cert_factory);

timeval statusMonitor(const StatusMonitor &status_monitor_params);

Value postCertificateStatus(server::WildcardPV &status_pv, const std::string &pv_name, uint64_t serial, const PVACertificateStatus &cert_status = {});

std::string getValidStatusesClause(const std::vector<certstatus_t> &valid_status);
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<certstatus_t> &valid_status = {});
uint64_t getParameters(const std::list<std::string> &parameters);

template <typename T>
void setValue(Value &target, const std::string &field, const T &new_value);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_PVACMS_H
